// Package integration is the catalogue: what the platform knows how to do,
// against which instance, with which credential.
//
// The shape is Splunk SOAR's app / asset / action, adopted deliberately
// (docs/soar/00 §3). It separates three things that home-grown projects
// usually mix: what I can do with this product, against which instance with
// which credential, and the atomic operation itself.
package integration

import (
	"fmt"
	"time"
)

// Autonomy is the policy that decides whether a human is in the loop.
type Autonomy string

const (
	// AutoExec runs by itself. Only for reads or for changes with no
	// operational impact: enrich, tag, comment, open a task.
	AutoExec Autonomy = "auto"
	// ApprovalRequired suspends with a rendered plan and a fingerprint.
	ApprovalRequired Autonomy = "approval_required"
	// Manual only suggests; the platform does not execute.
	Manual Autonomy = "manual"
)

func (a Autonomy) Valid() bool {
	switch a {
	case AutoExec, ApprovalRequired, Manual:
		return true
	}
	return false
}

// Action is one atomic operation an integration offers.
type Action struct {
	ID       string   `yaml:"id" json:"id"`
	Name     string   `yaml:"name" json:"name"`
	Autonomy Autonomy `yaml:"autonomy" json:"autonomy"`

	// Idempotent gates automatic retry. Retrying a non-idempotent action
	// because a socket timed out is how one close becomes two.
	Idempotent bool `yaml:"idempotent" json:"idempotent"`

	// Reversible is prose, shown to the operator in the plan. An action that
	// cannot answer this does not belong behind a button.
	Reversible string `yaml:"reversible" json:"reversible"`

	// Plan requires a preview before execution. Every non-idempotent action
	// and every action that changes another system sets this.
	Plan bool `yaml:"plan" json:"plan"`

	// Permission is the RBAC permission the caller must hold.
	Permission string `yaml:"permission" json:"permission"`

	Input  map[string]FieldSpec `yaml:"input" json:"input"`
	Output map[string]FieldSpec `yaml:"output" json:"output"`

	Timeout time.Duration `yaml:"timeout" json:"timeout"`

	// Implemented false means the action exists in the catalogue and has no
	// adapter compiled into this deployment. Containment actions live here on
	// purpose (AD-08): the permission can be granted and the call still
	// answers 501, with the reason.
	Implemented bool   `yaml:"implemented" json:"implemented"`
	Unavailable string `yaml:"unavailable" json:"unavailable"`
}

type FieldSpec struct {
	Type     string `yaml:"type" json:"type"`
	Required bool   `yaml:"required" json:"required"`
	Descr    string `yaml:"descr" json:"descr"`
}

type RateLimit struct {
	PerMinute int `yaml:"per_minute" json:"per_minute"`
}

type CircuitBreaker struct {
	Threshold  int           `yaml:"threshold" json:"threshold"`
	ResetAfter time.Duration `yaml:"reset_after" json:"reset_after"`
}

// Manifest is a content pack's integration.yaml.
type Manifest struct {
	ID             string         `yaml:"id" json:"id"`
	Name           string         `yaml:"name" json:"name"`
	PackID         string         `yaml:"pack_id" json:"pack_id"`
	Auth           Auth           `yaml:"auth" json:"auth"`
	RateLimit      RateLimit      `yaml:"rate_limit" json:"rate_limit"`
	CircuitBreaker CircuitBreaker `yaml:"circuit_breaker" json:"circuit_breaker"`
	HealthCheck    string         `yaml:"health_check" json:"health_check"`
	Actions        []Action       `yaml:"actions" json:"actions"`
}

type Auth struct {
	Type string `yaml:"type" json:"type"` // api_key | basic | bearer | none
	// Credential is a POINTER, never the secret: env://VAR, k8s://…, vault://…
	Credential string `yaml:"credential" json:"credential"`
}

// Validate refuses a manifest that would be dangerous to load. A pack is
// data, not code (AD-06), so the only defence against a bad one is refusing
// it at the door — and refusing one pack must not take the others down.
func (m Manifest) Validate() error {
	if m.ID == "" {
		return fmt.Errorf("manifesto sem id")
	}
	if len(m.Actions) == 0 {
		return fmt.Errorf("integração %q não declara nenhuma ação", m.ID)
	}
	seen := map[string]bool{}
	for _, a := range m.Actions {
		switch {
		case a.ID == "":
			return fmt.Errorf("%s: ação sem id", m.ID)
		case seen[a.ID]:
			return fmt.Errorf("%s: ação %q duplicada", m.ID, a.ID)
		case !a.Autonomy.Valid():
			return fmt.Errorf("%s.%s: autonomia inválida %q", m.ID, a.ID, a.Autonomy)
		case a.Permission == "":
			return fmt.Errorf("%s.%s: ação sem permissão declarada", m.ID, a.ID)
		}
		// Uma ação que exige aprovação e não sabe gerar plano pediria ao
		// operador para confirmar um texto em branco.
		if a.Autonomy == ApprovalRequired && !a.Plan {
			return fmt.Errorf("%s.%s: exige aprovação mas não declara plan: true", m.ID, a.ID)
		}
		// E uma que muda o mundo e não sabe dizer como voltar atrás não
		// deveria estar atrás de um botão.
		if a.Autonomy == ApprovalRequired && a.Reversible == "" {
			return fmt.Errorf("%s.%s: exige aprovação e não diz como reverter", m.ID, a.ID)
		}
		seen[a.ID] = true
	}
	return nil
}

func (m Manifest) Action(id string) (Action, bool) {
	for _, a := range m.Actions {
		if a.ID == id {
			return a, true
		}
	}
	return Action{}, false
}
