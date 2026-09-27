package assessment

import (
	"encoding/json"
	"regexp"
	"testing"
)

// A ordem das propriedades É a ordem do raciocínio.
//
// Com decodificação restrita, o llama.cpp constrói a gramática na ordem em que
// as propriedades chegam. Serializar o schema como mapa do Go o enviaria em
// ordem alfabética, forçando o modelo a emitir a conclusão antes da análise —
// exatamente a falha que a ordenação existe para evitar. Medido: a primeira
// versão, com `verdict` no topo, fazia o modelo escolher o veredito e depois
// justificá-lo.
func TestCaseSchemaKeepsReasoningOrder(t *testing.T) {
	raw, err := json.Marshal(caseSchema["properties"])
	if err != nil {
		t.Fatal(err)
	}
	keys := regexp.MustCompile(`"([a-z_]+)":\{`).FindAllStringSubmatch(string(raw), -1)
	var got []string
	for _, k := range keys {
		got = append(got, k[1])
	}

	want := []string{
		"title", "summary", "why_notable", "observed",
		"suspicious_indicators", "benign_indicators", "hypotheses",
		"attack_context", "attack_tactics", "attack_techniques", "diamond",
		"likely_benign_if", "more_suspicious_if", "intelligence_gaps",
		"recommended_actions", "reasoning",
		// A análise inteira vem ANTES destes quatro.
		"behaviour_occurred", "favoured_hypothesis", "confidence",
		"source_reliability", "info_credibility",
	}
	// O primeiro nível pode conter chaves aninhadas; comparamos o prefixo
	// dos nomes de topo na ordem em que aparecem.
	var topLevel []string
	seen := map[string]bool{}
	for _, k := range got {
		for _, w := range want {
			if k == w && !seen[k] {
				seen[k] = true
				topLevel = append(topLevel, k)
			}
		}
	}
	if len(topLevel) != len(want) {
		t.Fatalf("propriedades = %d, esperado %d: %v", len(topLevel), len(want), topLevel)
	}
	for i := range want {
		if topLevel[i] != want[i] {
			t.Fatalf("posição %d = %q, esperado %q\n  completo: %v", i, topLevel[i], want[i], topLevel)
		}
	}
}

// O veredito NÃO é pedido ao modelo: ele é derivado de duas perguntas que o
// modelo responde bem.
func TestVerdictIsNotAskedFor(t *testing.T) {
	raw, _ := json.Marshal(caseSchema)
	if regexp.MustCompile(`"verdict"`).Match(raw) {
		t.Fatal("o schema do caso pede veredito; deveria derivá-lo de behaviour_occurred + favoured_hypothesis")
	}
}

func TestDeriveVerdict(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name     string
		occurred *bool
		favoured string
		want     Verdict
	}{
		{"comportamento não ocorreu", &no, "suspicious", FalsePositive},
		{"evidência favorece o suspeito", &yes, "suspicious", TruePositive},
		{"evidência favorece o benigno", &yes, "benign", BenignTruePositive},
		{"genuinamente equilibrado", &yes, "balanced", Inconclusive},
		{"sem resposta", nil, "", Inconclusive},
		// A negação vence: se o comportamento não aconteceu, a regra errou,
		// independentemente de qual hipótese o modelo preferiu.
		{"não ocorreu vence o favorecimento", &no, "benign", FalsePositive},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := DeriveVerdict(c.occurred, c.favoured); got != c.want {
				t.Fatalf("DeriveVerdict = %q, want %q", got, c.want)
			}
		})
	}
}
