package http

import (
	"time"

	"github.com/titas/soar/backend/internal/assessment"
)

type evidenceDTO struct {
	Cluster     assessment.ReferenceCluster `json:"cluster"`
	CaseContext assessment.ReferenceCase    `json:"case_context"`
}

type assessmentDTO struct {
	ID                string                `json:"id"`
	IncidentID        string                `json:"incident_id"`
	Supersedes        *string               `json:"supersedes"`
	AuthorKind        string                `json:"author_kind"`
	Model             string                `json:"model"`
	SchemaVersion     int                   `json:"schema_version"`
	Verdict           assessment.Verdict    `json:"verdict"`
	Confidence        assessment.Confidence `json:"confidence"`
	SourceReliability string                `json:"source_reliability"`
	InfoCredibility   string                `json:"info_credibility"`
	Admiralty         string                `json:"admiralty"`
	Title             string                `json:"title"`
	Summary           string                `json:"summary"`
	Body              assessment.Body       `json:"body"`
	CaseContext       map[string]any        `json:"case_context"`
	AttackTactics     []string              `json:"attack_tactics"`
	AttackTechniques  []string              `json:"attack_techniques"`
	Disagreed         bool                  `json:"disagreed"`
	PromotedAt        *time.Time            `json:"promoted_at"`
	PromotedBy        *string               `json:"promoted_by"`
	GeneratedAt       time.Time             `json:"generated_at"`
	LatencyMS         int                   `json:"latency_ms"`
	PromptTokens      int                   `json:"prompt_tokens"`
}

func toDTO(a *assessment.Assessment) assessmentDTO {
	var supersedes, promotedBy *string
	if a.Supersedes != nil {
		value := a.Supersedes.String()
		supersedes = &value
	}
	if a.PromotedBy != nil {
		value := a.PromotedBy.String()
		promotedBy = &value
	}
	tactics := a.AttackTactics
	if tactics == nil {
		tactics = []string{}
	}
	techniques := a.AttackTechniques
	if techniques == nil {
		techniques = []string{}
	}
	return assessmentDTO{
		ID: a.ID.String(), IncidentID: a.IncidentID.String(), Supersedes: supersedes,
		AuthorKind: a.AuthorKind, Model: a.Model, SchemaVersion: a.SchemaVersion,
		Verdict: a.Verdict, Confidence: a.Confidence,
		SourceReliability: a.SourceReliability, InfoCredibility: a.InfoCredibility,
		Admiralty: a.Admiralty(), Title: a.Title, Summary: a.Summary, Body: a.Body,
		CaseContext: a.CaseContext, AttackTactics: tactics, AttackTechniques: techniques,
		Disagreed: a.Disagreed(), PromotedAt: a.PromotedAt, PromotedBy: promotedBy,
		GeneratedAt: a.GeneratedAt, LatencyMS: a.LatencyMS, PromptTokens: a.PromptTokens,
	}
}
