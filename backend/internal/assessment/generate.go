package assessment

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/titas/soar/backend/internal/core/clock"
	"github.com/titas/soar/backend/internal/core/id"
)

// The prompts live separately because their exact wording is part of the
// measured Python reference contract, like the evidence and ordered schemas.

// Generator produces an assessment in two passes.
//
// The two-pass design is a measurement, not a preference. Asked in one pass
// to investigate AND conclude, the 8B model answered "inconclusive" seven
// cases out of seven — it reasoned well and then refused to commit. Asked in
// a short first pass to simply decide, it scored 5/7 against human labels.
// So the decision comes from the short pass, the reasoning from the long one,
// and when they disagree the confidence drops to low and the disagreement is
// recorded rather than hidden.
type Generator struct {
	LLM     *Ollama
	Context *ContextBuilder
	Clock   clock.Clock
}

type decisionOut struct {
	Verdict           string `json:"verdict"`
	SourceReliability string `json:"source_reliability"`
	InfoCredibility   string `json:"info_credibility"`
	Title             string `json:"title"`
	Summary           string `json:"summary"`
	Reasoning         string `json:"reasoning"`
}

type caseOut struct {
	Title                string        `json:"title"`
	Summary              string        `json:"summary"`
	WhyNotable           string        `json:"why_notable"`
	Observed             []Observation `json:"observed"`
	SuspiciousIndicators []string      `json:"suspicious_indicators"`
	BenignIndicators     []string      `json:"benign_indicators"`
	Hypotheses           []Hypothesis  `json:"hypotheses"`
	AttackContext        string        `json:"attack_context"`
	AttackTactics        []string      `json:"attack_tactics"`
	AttackTechniques     []string      `json:"attack_techniques"`
	Diamond              Diamond       `json:"diamond"`
	LikelyBenignIf       []string      `json:"likely_benign_if"`
	MoreSuspiciousIf     []string      `json:"more_suspicious_if"`
	IntelligenceGaps     []string      `json:"intelligence_gaps"`
	RecommendedActions   []string      `json:"recommended_actions"`
	Reasoning            string        `json:"reasoning"`
	BehaviourOccurred    *bool         `json:"behaviour_occurred"`
	FavouredHypothesis   string        `json:"favoured_hypothesis"`
	Confidence           string        `json:"confidence"`
	SourceReliability    string        `json:"source_reliability"`
	InfoCredibility      string        `json:"info_credibility"`
}

func (g *Generator) Generate(ctx context.Context, tenant id.TenantID,
	incidentID id.IncidentID) (*Assessment, error) {

	started := g.Clock.Now()
	bundle, err := g.Context.BuildReference(ctx, tenant, incidentID)
	if err != nil {
		return nil, err
	}
	return g.generateReference(ctx, tenant, incidentID, bundle, started)
}

// GenerateReference runs the production model path over an already-built
// bundle. The offline quality gate uses it to replay frozen Python inputs
// without consulting a mutable database or SIEM.
func (g *Generator) GenerateReference(ctx context.Context, tenant id.TenantID,
	incidentID id.IncidentID, bundle *ReferenceBundle) (*Assessment, error) {
	return g.generateReference(ctx, tenant, incidentID, bundle, g.Clock.Now())
}

func (g *Generator) generateReference(ctx context.Context, tenant id.TenantID,
	incidentID id.IncidentID, bundle *ReferenceBundle, started time.Time) (*Assessment, error) {
	if bundle == nil {
		return nil, fmt.Errorf("reference bundle ausente")
	}
	decisionEvidence := RenderReferenceDecisionEvidence(bundle.Cluster, 4500)
	evidence := RenderReferenceEvidence(bundle.Cluster, bundle.Case, MaxEvidenceChars)
	evidence += "\n\nIMPORTANTE: escreva todos os textos livres em português do Brasil (pt-BR). " +
		"Mantenha caminhos, processos, IPs e IDs ATT&CK como estão."

	// PASSE 1 — a decisão. Curto, e é dele que sai o veredito.
	decisionRaw, tokens1, decisionErr := g.LLM.Complete(ctx, decisionPrompt, decisionEvidence, decisionSchema)
	var decision *decisionOut
	if decisionErr == nil {
		var parsed decisionOut
		if err := json.Unmarshal([]byte(decisionRaw), &parsed); err != nil {
			decisionErr = fmt.Errorf("decisão ilegível: %w", err)
		} else {
			decision = &parsed
		}
	}

	// PASSE 2 — a investigação. Longo, e é dele que sai o raciocínio.
	investigationRaw, tokens2, investigationErr := g.LLM.Complete(ctx, casePrompt, evidence, caseSchema)
	var investigation *caseOut
	if investigationErr == nil {
		var parsed caseOut
		if err := json.Unmarshal([]byte(investigationRaw), &parsed); err != nil {
			investigationErr = fmt.Errorf("investigação ilegível: %w", err)
		} else {
			investigation = &parsed
		}
	}
	if decision == nil && investigation == nil {
		return nil, fmt.Errorf("modelo falhou nos dois passes (decisão: %v; investigação: %v)", decisionErr, investigationErr)
	}

	var decisionValue decisionOut
	if decision != nil {
		decisionValue = *decision
	}
	var investigationValue caseOut
	if investigation != nil {
		investigationValue = *investigation
	}

	derived := Verdict("")
	if investigation != nil {
		derived = DeriveVerdict(investigationValue.BehaviourOccurred, investigationValue.FavouredHypothesis)
	}
	verdict := derived
	if decision != nil {
		verdict = normaliseVerdict(decisionValue.Verdict)
	}
	confidence := normaliseConfidence(investigationValue.Confidence)
	if decision != nil && investigation != nil && derived != verdict {
		// Os dois passes discordaram. O sistema diz "não tenho certeza" em
		// vez de escolher um e soar seguro.
		confidence = Low
	}

	ctxMap := map[string]any{}
	if raw, err := json.Marshal(bundle.Case); err == nil {
		_ = json.Unmarshal(raw, &ctxMap)
	}

	finished := g.Clock.Now()
	return &Assessment{
		ID: id.NewAssessment(), TenantID: tenant, IncidentID: incidentID,
		AuthorKind: "model", Model: g.LLM.Model, SchemaVersion: 2,
		Verdict: verdict, Confidence: confidence,
		SourceReliability: normaliseSourceReliability(firstNonEmpty(decisionValue.SourceReliability, investigationValue.SourceReliability)),
		InfoCredibility:   normaliseInfoCredibility(firstNonEmpty(decisionValue.InfoCredibility, investigationValue.InfoCredibility)),
		Title:             firstNonEmpty(investigationValue.Title, decisionValue.Title, bundle.IncidentTitle),
		Summary:           firstNonEmpty(investigationValue.Summary, decisionValue.Summary),
		AttackTactics:     investigationValue.AttackTactics,
		AttackTechniques:  investigationValue.AttackTechniques,
		CaseContext:       ctxMap,
		Body: Body{
			WhyNotable: investigationValue.WhyNotable, Observed: investigationValue.Observed,
			SuspiciousIndicators: investigationValue.SuspiciousIndicators,
			BenignIndicators:     investigationValue.BenignIndicators,
			Hypotheses:           investigationValue.Hypotheses,
			AttackContext:        investigationValue.AttackContext,
			Diamond:              investigationValue.Diamond,
			LikelyBenignIf:       investigationValue.LikelyBenignIf,
			MoreSuspiciousIf:     investigationValue.MoreSuspiciousIf,
			IntelligenceGaps:     investigationValue.IntelligenceGaps,
			RecommendedActions:   investigationValue.RecommendedActions,
			Reasoning:            investigationValue.Reasoning,
			DecisionReasoning:    decisionValue.Reasoning,
			InvestigationVerdict: derived,
			FavouredHypothesis:   investigationValue.FavouredHypothesis,
			BehaviourOccurred:    investigationValue.BehaviourOccurred,
		},
		GeneratedAt:  finished,
		LatencyMS:    int(finished.Sub(started).Milliseconds()),
		PromptTokens: tokens1 + tokens2,
	}, nil
}

func normaliseVerdict(v string) Verdict {
	switch Verdict(strings.ToLower(strings.TrimSpace(v))) {
	case TruePositive:
		return TruePositive
	case BenignTruePositive:
		return BenignTruePositive
	case FalsePositive:
		return FalsePositive
	default:
		return Inconclusive
	}
}

func normaliseConfidence(c string) Confidence {
	switch Confidence(strings.ToLower(strings.TrimSpace(c))) {
	case High:
		return High
	case Medium:
		return Medium
	default:
		return Low
	}
}

func normaliseSourceReliability(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if len(value) == 1 && value[0] >= 'A' && value[0] <= 'F' {
		return value
	}
	return "B"
}

func normaliseInfoCredibility(value string) string {
	value = strings.TrimSpace(value)
	if len(value) == 1 && value[0] >= '1' && value[0] <= '6' {
		return value
	}
	return "4"
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

var _ = time.Time{}
