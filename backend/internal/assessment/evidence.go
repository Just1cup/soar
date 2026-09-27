package assessment

import (
	"fmt"
	"strings"
)

// MaxEvidenceChars is an architectural limit, not a detail.
//
// The model runs on an RX 6600 with OLLAMA_NUM_CTX=8192. The evidence has to
// leave room for the system prompt and for the model's own output, and going
// over does not fail loudly — it silently truncates the beginning, which is
// where the incident's identity lives.
const MaxEvidenceChars = 6500

// RenderDecisionEvidence deliberately excludes enrichment and action history.
// The reference two-pass pipeline measured its short decision pass over the
// alert cluster alone; feeding the long investigation back into that pass
// would change the experiment we are trying to preserve.
func RenderDecisionEvidence(cc *CaseContext) string {
	var b strings.Builder
	fmt.Fprintf(&b, "CASO %s\n", cc.Incident.Key)
	fmt.Fprintf(&b, "Regra de detecção: %s\n", cc.Incident.Rule)
	fmt.Fprintf(&b, "Severidade atribuída pela regra: %s\n", cc.Incident.Severity)
	if cc.Incident.Host != "" {
		fmt.Fprintf(&b, "Host: %s\n", cc.Incident.Host)
	}
	fmt.Fprintf(&b, "Volume: %d alerta(s)\n", cc.Incident.AlertCount)
	writeCounted(&b, "PROCESSOS OBSERVADOS", cc.Entities.Processes)
	writeCounted(&b, "USUÁRIOS OBSERVADOS", cc.Entities.Users)
	writeCounted(&b, "ORIGENS OBSERVADAS", cc.Entities.SourceIPs)
	writeCounted(&b, "DESTINOS OBSERVADOS", cc.Entities.DestIPs)
	return b.String()
}

// RenderEvidence turns the case context into the text the model reads.
//
// Written as prose with headings rather than JSON on purpose: an 8B model
// reasons noticeably better over a readable brief than over a nested object,
// and the ordering here puts identity first and speculation last.
func RenderEvidence(cc *CaseContext) string {
	var b strings.Builder

	fmt.Fprintf(&b, "CASO %s\n", cc.Incident.Key)
	fmt.Fprintf(&b, "Regra de detecção: %s\n", cc.Incident.Rule)
	fmt.Fprintf(&b, "Severidade atribuída pela regra: %s\n", cc.Incident.Severity)
	if cc.Incident.Host != "" {
		fmt.Fprintf(&b, "Host: %s\n", cc.Incident.Host)
	}
	fmt.Fprintf(&b, "Volume: %d alerta(s)", cc.Incident.AlertCount)
	if cc.Incident.Window != "" {
		fmt.Fprintf(&b, " ao longo de %s", cc.Incident.Window)
	}
	b.WriteString("\n")

	if len(cc.Timeline) > 0 {
		b.WriteString("\nCOMO OS ALERTAS CHEGARAM\n")
		for _, burst := range cc.Timeline {
			fmt.Fprintf(&b, "  %s  %s\n", burst.Start.Format("2006-01-02 15:04"), burst.Detail)
		}
		if len(cc.Timeline) == 1 && cc.Timeline[0].Count > 1 {
			b.WriteString("  (uma única rajada: o comportamento se repetiu, não evoluiu)\n")
		}
	}

	writeCounted(&b, "PROCESSOS ENVOLVIDOS", cc.Entities.Processes)
	writeCounted(&b, "USUÁRIOS", cc.Entities.Users)
	writeCounted(&b, "ORIGENS", cc.Entities.SourceIPs)
	writeCounted(&b, "DESTINOS", cc.Entities.DestIPs)
	if len(cc.Entities.Hosts) > 1 {
		writeCounted(&b, "HOSTS", cc.Entities.Hosts)
	}

	if len(cc.Related) > 0 {
		// A peça de contexto mais útil: uma regra sozinha é ruído; três
		// regras juntas no mesmo host dentro de uma hora são uma história.
		b.WriteString("\nOUTRAS REGRAS QUE DISPARARAM NO MESMO HOST (±1h)\n")
		for _, r := range cc.Related {
			fmt.Fprintf(&b, "  %-52s %d\n", truncate(r.Rule, 52), r.Count)
		}
	} else if cc.Incident.Host != "" {
		b.WriteString("\nNenhuma outra regra disparou neste host na mesma janela.\n")
	}

	if len(cc.Prevalence) > 0 {
		b.WriteString("\nPREVALÊNCIA NOS ÚLTIMOS 30 DIAS\n")
		for _, p := range cc.Prevalence {
			fmt.Fprintf(&b, "  %s: visto em %d host(s), %d alerta(s)\n",
				truncate(p.Subject, 46), p.Hosts, p.Alerts)
		}
	}

	if len(cc.Actions) > 0 {
		b.WriteString("\nO QUE JÁ FOI FEITO NESTE CASO\n")
		for _, a := range cc.Actions {
			fmt.Fprintf(&b, "  %s  %s (%s)", a.At.Format("15:04"), a.Action, a.Status)
			if a.Affected != nil {
				fmt.Fprintf(&b, " — %d afetado(s)", *a.Affected)
			}
			b.WriteString("\n")
		}
	}

	if len(cc.Missing) > 0 {
		// Dizer o que falta é parte da evidência: um analista que não sabe o
		// que está faltando não distingue um sistema quieto de um coletor
		// quebrado.
		b.WriteString("\nNÃO FOI POSSÍVEL COLETAR\n")
		for _, m := range cc.Missing {
			fmt.Fprintf(&b, "  - %s\n", m)
		}
	}

	out := b.String()
	if len(out) <= MaxEvidenceChars {
		return out
	}
	// Corta pelo FIM: a identidade do caso está no começo, e perdê-la é pior
	// que perder a cauda da prevalência.
	trimmed := out[:MaxEvidenceChars]
	if idx := strings.LastIndex(trimmed, "\n"); idx > 0 {
		trimmed = trimmed[:idx]
	}
	return trimmed + "\n[evidência truncada para caber no contexto do modelo]\n"
}

func writeCounted(b *strings.Builder, heading string, items []Counted) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintf(b, "\n%s\n", heading)
	for _, i := range items {
		if i.Count > 1 {
			fmt.Fprintf(b, "  %-52s ×%d\n", truncate(i.Value, 52), i.Count)
		} else {
			fmt.Fprintf(b, "  %s\n", truncate(i.Value, 60))
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
