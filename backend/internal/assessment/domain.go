package assessment

import (
	"time"

	"github.com/titas/soar/backend/internal/core/id"
)

// Diamond is who, with what, from where, against whom.
//
// Every vertex may be empty. An unknown adversary is the NORMAL case for
// commodity scanning, and recording it as unknown is a correct assessment —
// an assessment that invents an attribution is worse than one that declines
// to.
type Diamond struct {
	Adversary      string `json:"adversary"`
	Capability     string `json:"capability"`
	Infrastructure string `json:"infrastructure"`
	Victim         string `json:"victim"`
}

type Observation struct {
	Statement string `json:"statement"`
	Basis     Basis  `json:"basis"`
}

// Hypothesis is one of exactly two: benign and suspicious, each with what
// supports and what contradicts it. Forcing both is what stops the model
// from writing a one-sided story and calling it analysis.
type Hypothesis struct {
	Kind          string   `json:"kind"`
	Statement     string   `json:"statement"`
	Supporting    []string `json:"supporting"`
	Contradicting []string `json:"contradicting"`
}

// Assessment is immutable once written. A correction creates a new one with
// Supersedes set; nothing edits the record of what was thought at the time.
type Assessment struct {
	ID         id.AssessmentID
	TenantID   id.TenantID
	IncidentID id.IncidentID
	Supersedes *id.AssessmentID

	AuthorKind    string // model | human
	Model         string
	SchemaVersion int

	Verdict    Verdict
	Confidence Confidence
	// Admiralty grades the SOURCE and the INFORMATION separately, on purpose.
	SourceReliability string
	InfoCredibility   string

	Title   string
	Summary string
	Body    Body
	// CaseContext is built by CODE from telemetry, never by the model. It is
	// what the model was shown, kept so a later reader can tell whether the
	// assessment was reasonable given what was available.
	CaseContext map[string]any

	AttackTactics    []string
	AttackTechniques []string

	PromotedAt *time.Time
	PromotedBy *id.UserID

	GeneratedAt  time.Time
	LatencyMS    int
	PromptTokens int
}

// Body holds the reasoning. It is JSONB because the UI reads it whole;
// promoting eighteen nested fields to columns would be ceremonial
// normalisation.
type Body struct {
	WhyNotable           string        `json:"why_notable"`
	Observed             []Observation `json:"observed"`
	SuspiciousIndicators []string      `json:"suspicious_indicators"`
	BenignIndicators     []string      `json:"benign_indicators"`
	Hypotheses           []Hypothesis  `json:"hypotheses"`
	AttackContext        string        `json:"attack_context"`
	Diamond              Diamond       `json:"diamond"`
	// LikelyBenignIf and MoreSuspiciousIf are the two lists an analyst
	// actually uses: they say what to go and check next.
	LikelyBenignIf   []string `json:"likely_benign_if"`
	MoreSuspiciousIf []string `json:"more_suspicious_if"`
	// IntelligenceGaps is what would settle the question. An assessment that
	// cannot name this is usually one that did not really reason.
	IntelligenceGaps   []string `json:"intelligence_gaps"`
	RecommendedActions []string `json:"recommended_actions"`
	Reasoning          string   `json:"reasoning"`

	// Two-pass bookkeeping: the verdict comes from the short decision pass;
	// these record what the long pass leaned towards, so a DISAGREEMENT
	// between them is visible rather than hidden.
	DecisionReasoning    string  `json:"decision_reasoning"`
	InvestigationVerdict Verdict `json:"investigation_verdict"`
	FavouredHypothesis   string  `json:"favoured_hypothesis"`
	BehaviourOccurred    *bool   `json:"behaviour_occurred"`
}

// Admiralty is the two grades written conventionally, e.g. "B2".
func (a Assessment) Admiralty() string { return a.SourceReliability + a.InfoCredibility }

// Disagreed reports whether the two passes reached different verdicts. When
// they do, confidence is forced to low: the system says "I am not sure"
// instead of picking one and sounding certain.
func (a Assessment) Disagreed() bool {
	return a.Body.InvestigationVerdict != "" && a.Body.InvestigationVerdict != a.Verdict
}
