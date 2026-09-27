package integration

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"
)

// Asset is a configured instance of an integration: which endpoint, which
// credential, which options. The adapter receives the resolved secret by
// injection and never reads the environment itself.
type Asset struct {
	ID         string
	Name       string
	Endpoint   string
	Credential string
	Config     map[string]any
}

// ActionCall is one invocation.
type ActionCall struct {
	Integration string
	Action      string
	Asset       Asset
	Input       map[string]any
	// IncidentKey only travels so an adapter can put a readable reference in
	// the third-party system. Nothing may branch on it.
	IncidentKey string
}

// Plan is exactly what an action would do, in terms a human can check.
//
// Ported field for field from the Python ActionEngine, because the shape was
// right: the operator sees the count before the change, how to undo it, and
// the literal request — which is often what they run by hand the first few
// times, instead of trusting the button.
type Plan struct {
	Summary    string         `json:"summary"`
	Details    []string       `json:"details"`
	Affected   *int           `json:"affected"`
	Reversible string         `json:"reversible"`
	Warnings   []string       `json:"warnings"`
	Request    map[string]any `json:"request"`
	// Ready false means something blocks applying — a missing rule id, a
	// credential that is not configured. The plan is still shown, with the
	// reason, because "why can I not do this" is the question being asked.
	Ready bool `json:"ready"`
}

// Fingerprint is what stops an operator confirming a preview that said
// "42 alerts" and executing against the 4 000 that arrived meanwhile.
//
// It covers the action, the affected count and the literal request — the
// three things whose change would make the confirmation a lie. It does not
// cover the prose, so fixing a typo in a summary does not invalidate a
// pending approval.
func (p Plan) Fingerprint(integration, action string) []byte {
	material, _ := json.Marshal(struct {
		Integration string         `json:"integration"`
		Action      string         `json:"action"`
		Affected    *int           `json:"affected"`
		Request     map[string]any `json:"request"`
	}{integration, action, p.Affected, p.Request})
	sum := sha256.Sum256(material)
	return sum[:]
}

// Result is what happened.
type Result struct {
	Output   map[string]any
	Affected *int
	Summary  string
}

// Adapter is the port every integration implements. The domain talks to this;
// it never sees an HTTP client, a vendor SDK or a URL.
type Adapter interface {
	Slug() string

	// Plan renders the change without making it. It may read the third-party
	// system — counting what would be affected is the whole point — but must
	// not write.
	Plan(ctx context.Context, call ActionCall) (*Plan, error)

	// Execute performs the action. For an action declared `plan: true`, the
	// executor only calls this after the plan has been re-computed and its
	// fingerprint matched.
	Execute(ctx context.Context, call ActionCall) (*Result, error)

	// Health is an active probe, not a config check: "the key is set" and
	// "the service answers" are different questions.
	Health(ctx context.Context, asset Asset) error
}

// Clock lets the executor be tested without sleeping.
type Clock interface{ Now() time.Time }
