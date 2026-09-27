package http

import (
	"time"

	"github.com/titas/soar/backend/internal/response"
)

type planDTO struct {
	Summary    string   `json:"summary"`
	Details    []string `json:"details"`
	Affected   *int     `json:"affected"`
	Reversible string   `json:"reversible"`
	Warnings   []string `json:"warnings"`
	// A requisição literal é devolvida de propósito: o operador pode executá-la
	// à mão em vez de confiar no botão, que é o que ele faz nas primeiras vezes.
	Request map[string]any `json:"request"`
	Ready   bool           `json:"ready"`
}

type previewDTO struct {
	Plan            planDTO    `json:"plan"`
	Autonomy        string     `json:"autonomy"`
	Idempotent      bool       `json:"idempotent"`
	ApprovalID      *string    `json:"approval_id"`
	ApprovalVersion *int       `json:"approval_version"`
	ExpiresAt       *time.Time `json:"expires_at"`
}

type approvalDTO struct {
	ID          string     `json:"id"`
	IncidentID  *string    `json:"incident_id"`
	Action      string     `json:"action"`
	Permission  string     `json:"permission"`
	Plan        planDTO    `json:"plan"`
	Affected    *int       `json:"affected"`
	Status      string     `json:"status"`
	RequestedBy string     `json:"requested_by"`
	RequestedAt time.Time  `json:"requested_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	DecidedAt   *time.Time `json:"decided_at"`
	Note        string     `json:"note"`
	Version     int        `json:"version"`
}

type runDTO struct {
	ID          string     `json:"id"`
	Integration string     `json:"integration"`
	Action      string     `json:"action"`
	Autonomy    string     `json:"autonomy"`
	Status      string     `json:"status"`
	Affected    *int       `json:"affected"`
	Error       string     `json:"error"`
	ActorKind   string     `json:"actor_kind"`
	ActorID     string     `json:"actor_id"`
	RequestedAt time.Time  `json:"requested_at"`
	FinishedAt  *time.Time `json:"finished_at"`
	LatencyMS   *int       `json:"latency_ms"`
}

func slice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func toPlanDTO(p response.PlanView) planDTO {
	return planDTO{
		Summary: p.Summary, Details: slice(p.Details), Affected: p.Affected,
		Reversible: p.Reversible, Warnings: slice(p.Warnings),
		Request: p.Request, Ready: p.Ready,
	}
}

func toPreviewDTO(p *response.Preview) previewDTO {
	out := previewDTO{
		Plan: toPlanDTO(response.PlanView(p.Plan)), Autonomy: string(p.Autonomy),
		Idempotent: p.Idempotent, ApprovalVersion: p.ApprovalVersion, ExpiresAt: p.ExpiresAt,
	}
	if p.ApprovalID != nil {
		s := p.ApprovalID.String()
		out.ApprovalID = &s
	}
	return out
}

func toApprovalDTO(a *response.Approval) approvalDTO {
	out := approvalDTO{
		ID: a.ID.String(), Action: a.Action, Permission: a.Permission,
		Plan: toPlanDTO(response.PlanView(a.Plan)), Affected: a.Affected,
		Status: a.Status, RequestedBy: a.RequestedBy, RequestedAt: a.RequestedAt,
		ExpiresAt: a.ExpiresAt, DecidedAt: a.DecidedAt, Note: a.Note, Version: a.Version,
	}
	if a.IncidentID != nil {
		s := a.IncidentID.String()
		out.IncidentID = &s
	}
	return out
}

func toRunDTO(r *response.Run) runDTO {
	return runDTO{
		ID: r.ID.String(), Integration: r.Integration, Action: r.Action,
		Autonomy: string(r.Autonomy), Status: r.Status, Affected: r.Affected,
		Error: r.Error, ActorKind: r.ActorKind, ActorID: r.ActorID,
		RequestedAt: r.RequestedAt, FinishedAt: r.FinishedAt, LatencyMS: r.LatencyMS,
	}
}
