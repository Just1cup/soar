package ingestion

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/titas/soar/backend/internal/core/id"
)

var agora = time.Date(2026, 9, 21, 3, 0, 0, 0, time.UTC)

func alerta(rule, host, exe string) *Alert {
	return &Alert{
		RuleName: rule, Host: host, Severity: "low",
		Normalized: map[string]any{
			"process": map[string]any{"executable": exe},
		},
	}
}

func regra(slug string, conds Conditions, acts []RuleAction, expira *time.Time, on bool) Rule {
	return Rule{
		ID: id.RuleID{UUID: uuid.New()}, Slug: slug, Name: slug,
		Conditions: conds, Actions: acts, ExpiresAt: expira, Enabled: on,
	}
}

func daqui(d time.Duration) *time.Time { t := agora.Add(d); return &t }

// O caso concreto que motivou a funcionalidade: dockerd e overlay2 disparam a
// mesma regra todo dia, e em 2026-09-20 isso virou 19.344 fechamentos à mão.
func TestSuppressesInfrastructureNoise(t *testing.T) {
	r := regra("ruido-docker", Conditions{All: []Condition{
		{Field: "rule_name", Op: OpEquals, Value: "DNS to Commonly Abused Web Services"},
		{Field: "normalized.process.executable", Op: OpMatchesAny,
			Values: []string{"/usr/sbin/dockerd", "/var/lib/docker/overlay2/*"}},
	}}, []RuleAction{{Type: ActionDrop, Reason: "processo de infraestrutura conhecido"}},
		daqui(30*24*time.Hour), true)

	cases := []struct {
		name string
		a    *Alert
		drop bool
	}{
		{"dockerd", alerta("DNS to Commonly Abused Web Services", "h", "/usr/sbin/dockerd"), true},
		{"overlay2", alerta("DNS to Commonly Abused Web Services", "h",
			"/var/lib/docker/overlay2/abc123/diff/usr/sbin/nginx"), true},
		// A mesma regra, processo diferente: NÃO suprime. Uma supressão por
		// regra apenas apagaria o sinal real junto com o ruído.
		{"processo real", alerta("DNS to Commonly Abused Web Services", "h", "/usr/bin/curl"), false},
		{"outra regra", alerta("Suspicious Activity", "h", "/usr/sbin/dockerd"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := Evaluate(c.a, []Rule{r}, agora)
			if out.Drop != c.drop {
				t.Fatalf("drop = %v, want %v", out.Drop, c.drop)
			}
			if c.drop && out.DroppedBy == nil {
				t.Fatal("suprimiu sem registrar qual regra; a supressão ficaria invisível")
			}
		})
	}
}

// Uma regra vencida não age, mesmo que ainda esteja marcada como habilitada:
// o relógio anda entre carregar e avaliar.
func TestExpiredRuleDoesNotAct(t *testing.T) {
	r := regra("vencida", Conditions{All: []Condition{{Field: "host", Op: OpEquals, Value: "h"}}},
		[]RuleAction{{Type: ActionDrop}}, daqui(-time.Hour), true)
	if Evaluate(alerta("R", "h", "x"), []Rule{r}, agora).Drop {
		t.Fatal("regra vencida suprimiu um alerta")
	}
}

func TestDisabledRuleDoesNotAct(t *testing.T) {
	r := regra("desligada", Conditions{All: []Condition{{Field: "host", Op: OpEquals, Value: "h"}}},
		[]RuleAction{{Type: ActionDrop}}, daqui(time.Hour), false)
	if Evaluate(alerta("R", "h", "x"), []Rule{r}, agora).Drop {
		t.Fatal("regra desligada agiu")
	}
}

// Uma regra sem condição casaria com TUDO. É quase sempre erro de escrita, e
// o custo de errar é suprimir o SOC inteiro.
func TestRuleWithoutConditionsMatchesNothing(t *testing.T) {
	r := regra("vazia", Conditions{}, []RuleAction{{Type: ActionDrop}}, daqui(time.Hour), true)
	if Evaluate(alerta("R", "h", "x"), []Rule{r}, agora).Drop {
		t.Fatal("regra sem condição suprimiu tudo")
	}
}

// Ordem explícita e execução sequencial: o primeiro drop encerra.
func TestOrderIsExplicitAndFirstDropWins(t *testing.T) {
	marca := regra("marca", Conditions{All: []Condition{{Field: "host", Op: OpEquals, Value: "h"}}},
		[]RuleAction{{Type: ActionAddTag, Value: "infra"}, {Type: ActionSetSeverity, Value: "info"}},
		daqui(time.Hour), true)
	corta := regra("corta", Conditions{All: []Condition{{Field: "host", Op: OpEquals, Value: "h"}}},
		[]RuleAction{{Type: ActionDrop, Reason: "ruído"}}, daqui(time.Hour), true)
	nunca := regra("nunca", Conditions{All: []Condition{{Field: "host", Op: OpEquals, Value: "h"}}},
		[]RuleAction{{Type: ActionAddTag, Value: "tarde-demais"}}, daqui(time.Hour), true)

	out := Evaluate(alerta("R", "h", "x"), []Rule{marca, corta, nunca}, agora)
	if !out.Drop || out.Reason != "ruído" {
		t.Fatalf("esperava drop com motivo, veio %+v", out)
	}
	if len(out.Tags) != 1 || out.Tags[0] != "infra" {
		t.Fatalf("a regra anterior ao drop deveria ter agido: %v", out.Tags)
	}
	if out.Severity != "info" {
		t.Fatalf("severidade = %q", out.Severity)
	}
	if len(out.MatchedRules) != 2 {
		t.Fatalf("regras casadas = %d, esperado 2 (a terceira vem depois do drop)", len(out.MatchedRules))
	}
}

func TestOperators(t *testing.T) {
	a := alerta("Web Server Suspicious User Agent", "srv-01", "/usr/sbin/nginx")
	cases := []struct {
		name string
		c    Condition
		want bool
	}{
		{"equals", Condition{Field: "host", Op: OpEquals, Value: "srv-01"}, true},
		{"not_equals", Condition{Field: "host", Op: OpNotEquals, Value: "outro"}, true},
		{"contains", Condition{Field: "rule_name", Op: OpContains, Value: "User Agent"}, true},
		{"starts_with", Condition{Field: "rule_name", Op: OpStartsWith, Value: "Web"}, true},
		{"ends_with", Condition{Field: "rule_name", Op: OpEndsWith, Value: "Agent"}, true},
		{"in", Condition{Field: "host", Op: OpIn, Values: []string{"a", "srv-01"}}, true},
		{"exists", Condition{Field: "normalized.process.executable", Op: OpExists}, true},
		{"campo aninhado ausente", Condition{Field: "normalized.user.name", Op: OpExists}, false},
		{"campo desconhecido não casa", Condition{Field: "inventado", Op: OpEquals, Value: "x"}, false},
		{"glob de caminho", Condition{Field: "normalized.process.executable",
			Op: OpMatchesAny, Values: []string{"/usr/sbin/*"}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.c.Match(a); got != c.want {
				t.Fatalf("Match = %v, want %v", got, c.want)
			}
		})
	}
}
