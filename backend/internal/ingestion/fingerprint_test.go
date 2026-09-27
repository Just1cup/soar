package ingestion

import (
	"encoding/json"
	"os"
	"testing"
)

// Os vetores vêm dos golden fixtures capturados do pipeline Python antes do
// porte. Se este teste quebrar, todo incidente importado do console antigo
// passa a parecer novo — e a deduplicação para de funcionar através da
// fronteira entre os dois sistemas.
func TestFingerprintMatchesThePythonClusterer(t *testing.T) {
	raw, err := os.ReadFile("testdata/fingerprints.json")
	if err != nil {
		t.Skipf("vetores ausentes: %v", err)
	}
	var vectors []struct {
		Want   string `json:"want"`
		Rule   string `json:"rule"`
		Host   string `json:"host"`
		Kind   string `json:"kind"`
		Entity string `json:"entity"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("nenhum vetor")
	}
	for _, v := range vectors {
		t.Run(v.Want, func(t *testing.T) {
			if got := FingerprintHex(v.Rule, v.Host, v.Kind, v.Entity); got != v.Want {
				t.Fatalf("fingerprint = %s, want %s\n  material: %s|%s|%s|%s",
					got, v.Want, v.Rule, v.Host, v.Kind, v.Entity)
			}
		})
	}
}

func TestFingerprintIsStableAndScoped(t *testing.T) {
	base := FingerprintHex("Regra", "host1", "source.ip", "10.0.0.1")
	if base != FingerprintHex("Regra", "host1", "source.ip", "10.0.0.1") {
		t.Fatal("o mesmo escopo produziu fingerprints diferentes")
	}
	// Trocar qualquer componente muda o agrupamento: fechar o ruído de uma
	// regra num host não pode fechar a mesma regra em outro.
	for _, other := range []string{
		FingerprintHex("Outra", "host1", "source.ip", "10.0.0.1"),
		FingerprintHex("Regra", "host2", "source.ip", "10.0.0.1"),
		FingerprintHex("Regra", "host1", "user.name", "10.0.0.1"),
		FingerprintHex("Regra", "host1", "source.ip", "10.0.0.2"),
	} {
		if other == base {
			t.Fatalf("escopos diferentes colidiram em %s", base)
		}
	}
	if len(base) != 16 {
		t.Fatalf("esperado 16 caracteres hex, veio %d", len(base))
	}
}
