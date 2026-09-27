package assessment

import (
	"strings"
	"testing"
	"time"
)

// This is deliberately byte-for-byte. Headings, order and punctuation are
// part of the prompt observed by the model; a cosmetic rewrite can change the
// measured verdict distribution and therefore needs an intentional fixture
// update.
func TestRenderEvidenceGolden(t *testing.T) {
	at := time.Date(2026, 9, 21, 1, 2, 0, 0, time.UTC)
	affected := 7
	got := RenderEvidence(&CaseContext{
		Incident: IncidentFacts{
			Key: "INC-2026-000042", Rule: "Shell suspeito", Severity: "high",
			Host: "srv-01", AlertCount: 3, Window: "2 minutos",
		},
		Timeline: []Burst{{Start: at, End: at.Add(2 * time.Minute), Count: 3, Detail: "3 alertas em 2 minutos"}},
		Entities: Entities{
			Processes: []Counted{{Value: "/bin/bash", Count: 3}},
			Users:     []Counted{{Value: "root", Count: 1}},
		},
		Related:    []RelatedAlert{{Rule: "Execução a partir de /tmp", Count: 2}},
		Prevalence: []Prevalence{{Subject: "/bin/bash", Hosts: 14, Alerts: 93}},
		Actions: []ActionFact{{
			Action: "elastic-siem.close_alerts", Status: "succeeded",
			Affected: &affected, At: at,
		}},
		Missing: []string{"usuário do processo indisponível"},
	})
	want := "CASO INC-2026-000042\n" +
		"Regra de detecção: Shell suspeito\n" +
		"Severidade atribuída pela regra: high\n" +
		"Host: srv-01\n" +
		"Volume: 3 alerta(s) ao longo de 2 minutos\n" +
		"\nCOMO OS ALERTAS CHEGARAM\n" +
		"  2026-09-21 01:02  3 alertas em 2 minutos\n" +
		"  (uma única rajada: o comportamento se repetiu, não evoluiu)\n" +
		"\nPROCESSOS ENVOLVIDOS\n" +
		"  /bin/bash                                            ×3\n" +
		"\nUSUÁRIOS\n" +
		"  root\n" +
		"\nOUTRAS REGRAS QUE DISPARARAM NO MESMO HOST (±1h)\n" +
		"  Execução a partir de /tmp                            2\n" +
		"\nPREVALÊNCIA NOS ÚLTIMOS 30 DIAS\n" +
		"  /bin/bash: visto em 14 host(s), 93 alerta(s)\n" +
		"\nO QUE JÁ FOI FEITO NESTE CASO\n" +
		"  01:02  elastic-siem.close_alerts (succeeded) — 7 afetado(s)\n" +
		"\nNÃO FOI POSSÍVEL COLETAR\n" +
		"  - usuário do processo indisponível\n"
	if got != want {
		t.Fatalf("evidência mudou:\n--- got\n%s--- want\n%s", got, want)
	}
}

func TestRenderEvidenceCapsModelInput(t *testing.T) {
	got := RenderEvidence(&CaseContext{
		Incident: IncidentFacts{Key: "INC-1", Rule: "R", Severity: "low", AlertCount: 1},
		Missing:  []string{strings.Repeat("x", MaxEvidenceChars*2)},
	})
	if len(got) > MaxEvidenceChars+80 {
		t.Fatalf("evidência excedeu limite: %d", len(got))
	}
	if !strings.HasSuffix(got, "[evidência truncada para caber no contexto do modelo]\n") {
		t.Fatal("marcador de truncamento ausente")
	}
}

func TestDecisionEvidenceDoesNotLeakInvestigationConclusion(t *testing.T) {
	got := RenderDecisionEvidence(&CaseContext{
		Incident: IncidentFacts{Key: "INC-1", Rule: "R", Severity: "high", AlertCount: 2},
		Related:  []RelatedAlert{{Rule: "outra regra", Count: 3}},
		Actions:  []ActionFact{{Action: "close_alerts", Status: "succeeded"}},
		Missing:  []string{"SIEM indisponível"},
	})
	for _, forbidden := range []string{"outra regra", "close_alerts", "SIEM indisponível"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("passe curto recebeu contexto da investigação: %q", forbidden)
		}
	}
}
