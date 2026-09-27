package ingestion

import (
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/titas/soar/backend/internal/core/id"
)

// Pre-process rules act BEFORE the incident exists.
//
// "The cheapest decision is the one that avoids creating the case"
// (docs/soar/00 §2). This is the direct answer to the 19 344 alerts closed by
// hand on 2026-09-20: dockerd, overlay2 and the container's nginx fire the
// same two rules every day, and that was a suppression rule nobody had
// written.
//
// Two safety properties are built in rather than left to discipline:
//
//   - a rule that drops or closes CANNOT exist without an expiry date. The
//     database refuses it (migration 0011). A detection silenced forever by
//     forgetfulness is the most expensive failure a SOAR can introduce.
//   - `drop` never deletes. It marks the alert with the rule that suppressed
//     it, and the alert stays queryable. An invisible suppression is
//     indistinguishable from a loss.

type Op string

const (
	OpEquals     Op = "equals"
	OpNotEquals  Op = "not_equals"
	OpContains   Op = "contains"
	OpStartsWith Op = "starts_with"
	OpEndsWith   Op = "ends_with"
	OpIn         Op = "in"
	OpMatchesAny Op = "matches_any" // glob, para caminhos como /var/lib/docker/overlay2/*
	OpExists     Op = "exists"
)

type Condition struct {
	Field  string   `yaml:"field" json:"field"`
	Op     Op       `yaml:"op" json:"op"`
	Value  string   `yaml:"value" json:"value"`
	Values []string `yaml:"values" json:"values"`
}

type Conditions struct {
	All []Condition `yaml:"all" json:"all"`
	Any []Condition `yaml:"any" json:"any"`
}

type ActionType string

const (
	ActionDrop        ActionType = "drop"
	ActionSetSeverity ActionType = "set_severity"
	ActionAddTag      ActionType = "add_tag"
	ActionSetType     ActionType = "set_incident_type"
)

type RuleAction struct {
	Type   ActionType `yaml:"type" json:"type"`
	Value  string     `yaml:"value" json:"value"`
	Reason string     `yaml:"reason" json:"reason"`
}

type Rule struct {
	ID         id.RuleID
	Slug       string       `yaml:"id" json:"slug"`
	Name       string       `yaml:"name" json:"name"`
	Trigger    string       `yaml:"trigger" json:"trigger"`
	Order      int          `yaml:"order" json:"order"`
	Conditions Conditions   `yaml:"conditions" json:"conditions"`
	Actions    []RuleAction `yaml:"actions" json:"actions"`
	ExpiresAt  *time.Time
	Enabled    bool
}

// Outcome is what the rule engine decided about one alert.
type Outcome struct {
	Drop         bool
	DroppedBy    *id.RuleID
	Reason       string
	Severity     string
	Tags         []string
	IncidentType string
	MatchedRules []id.RuleID
}

// Evaluate runs the rules in order and stops at the first drop.
//
// Order is explicit and evaluation is sequential, never parallel — the
// Sentinel decision (docs/soar/00 §4). Parallelism here would make the result
// depend on a race, and one of the outcomes is "this alert disappears".
func Evaluate(alert *Alert, rules []Rule, now time.Time) Outcome {
	var out Outcome
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		// Uma regra vencida não age. A checagem é aqui também, e não só no
		// índice da consulta, porque o relógio anda entre carregar e avaliar.
		if r.ExpiresAt != nil && !now.Before(*r.ExpiresAt) {
			continue
		}
		if !r.Conditions.Match(alert) {
			continue
		}
		out.MatchedRules = append(out.MatchedRules, r.ID)
		for _, a := range r.Actions {
			switch a.Type {
			case ActionDrop:
				out.Drop = true
				ruleID := r.ID
				out.DroppedBy = &ruleID
				out.Reason = firstNonEmpty(a.Reason, r.Name)
				return out
			case ActionSetSeverity:
				out.Severity = a.Value
			case ActionAddTag:
				out.Tags = append(out.Tags, a.Value)
			case ActionSetType:
				out.IncidentType = a.Value
			}
		}
	}
	return out
}

func (c Conditions) Match(alert *Alert) bool {
	// Sem condição nenhuma a regra casaria com tudo. Isso é quase sempre um
	// erro de escrita, e o custo de errar aqui é suprimir o SOC inteiro.
	if len(c.All) == 0 && len(c.Any) == 0 {
		return false
	}
	for _, cond := range c.All {
		if !cond.Match(alert) {
			return false
		}
	}
	if len(c.Any) == 0 {
		return true
	}
	for _, cond := range c.Any {
		if cond.Match(alert) {
			return true
		}
	}
	return false
}

func (c Condition) Match(alert *Alert) bool {
	value, present := fieldOf(alert, c.Field)
	if c.Op == OpExists {
		return present
	}
	if !present {
		return c.Op == OpNotEquals
	}
	candidates := c.Values
	if len(candidates) == 0 && c.Value != "" {
		candidates = []string{c.Value}
	}
	switch c.Op {
	case OpEquals:
		return value == c.Value
	case OpNotEquals:
		return value != c.Value
	case OpContains:
		return strings.Contains(value, c.Value)
	case OpStartsWith:
		return strings.HasPrefix(value, c.Value)
	case OpEndsWith:
		return strings.HasSuffix(value, c.Value)
	case OpIn:
		for _, v := range candidates {
			if value == v {
				return true
			}
		}
	case OpMatchesAny:
		for _, pattern := range candidates {
			if ok, err := path.Match(pattern, value); err == nil && ok {
				return true
			}
			// path.Match não atravessa "/" com "*"; para caminhos, prefixo
			// antes do curinga final é o que o operador espera de
			// "/var/lib/docker/overlay2/*".
			if base, found := strings.CutSuffix(pattern, "/*"); found &&
				strings.HasPrefix(value, base+"/") {
				return true
			}
		}
	}
	return false
}

// fieldOf resolves a dotted path against the canonical alert, then against
// the normalized payload. Only named fields: there is no free-form predicate
// language here, and nothing the rule says is ever interpolated into SQL.
func fieldOf(a *Alert, field string) (string, bool) {
	switch field {
	case "rule_name":
		return a.RuleName, a.RuleName != ""
	case "rule_id":
		return a.RuleID, a.RuleID != ""
	case "severity":
		return a.Severity, a.Severity != ""
	case "host":
		return a.Host, a.Host != ""
	case "entity":
		return a.Entity, a.Entity != ""
	case "entity_kind":
		return a.EntityKind, a.EntityKind != ""
	case "title":
		return a.Title, a.Title != ""
	}
	raw, found := strings.CutPrefix(field, "normalized.")
	if !found {
		return "", false
	}
	return lookup(a.Normalized, strings.Split(raw, "."))
}

func lookup(m map[string]any, parts []string) (string, bool) {
	var cur any = m
	for _, p := range parts {
		asMap, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		cur, ok = asMap[p]
		if !ok {
			return "", false
		}
	}
	switch v := cur.(type) {
	case string:
		return v, true
	case fmt.Stringer:
		return v.String(), true
	case nil:
		return "", false
	default:
		return fmt.Sprint(v), true
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
