// Package http exposes the action catalogue, the plan/execute pair and the
// approval queue.
package http

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/titas/soar/backend/internal/core/errs"
	"github.com/titas/soar/backend/internal/core/id"
	"github.com/titas/soar/backend/internal/httpx"
	"github.com/titas/soar/backend/internal/integration"
	"github.com/titas/soar/backend/internal/response"
)

type Handler struct {
	Executor *response.Executor
	Approver *response.Approver
	Registry *integration.Registry
	Runs     response.RunRepository
	Log      *slog.Logger
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/integrations", h.listIntegrations)
	mux.HandleFunc("GET /api/v1/approvals", h.listApprovals)
	mux.HandleFunc("POST /api/v1/approvals/{id}/decide", h.decide)
	// Cada ação é um recurso; `POST /doAction` não existe, porque é o que
	// permite RBAC e rate limit por operação.
	mux.HandleFunc("POST /api/v1/incidents/{id}/actions/{qualified}/plan", h.plan)
	mux.HandleFunc("POST /api/v1/incidents/{id}/actions/{qualified}/execute", h.execute)
	mux.HandleFunc("GET /api/v1/incidents/{id}/actions", h.listRuns)
}

func (h *Handler) listIntegrations(w http.ResponseWriter, r *http.Request) {
	type actionDTO struct {
		ID          string                           `json:"id"`
		Name        string                           `json:"name"`
		Autonomy    string                           `json:"autonomy"`
		Permission  string                           `json:"permission"`
		Idempotent  bool                             `json:"idempotent"`
		Plan        bool                             `json:"plan"`
		Reversible  string                           `json:"reversible"`
		Implemented bool                             `json:"implemented"`
		Unavailable string                           `json:"unavailable"`
		Input       map[string]integration.FieldSpec `json:"input"`
	}
	type integrationDTO struct {
		ID      string      `json:"id"`
		Name    string      `json:"name"`
		PackID  string      `json:"pack_id"`
		Actions []actionDTO `json:"actions"`
	}
	out := []integrationDTO{}
	for _, m := range h.Registry.Manifests() {
		dto := integrationDTO{ID: m.ID, Name: m.Name, PackID: m.PackID}
		for _, a := range m.Actions {
			dto.Actions = append(dto.Actions, actionDTO{
				ID: a.ID, Name: a.Name, Autonomy: string(a.Autonomy),
				Permission: a.Permission, Idempotent: a.Idempotent, Plan: a.Plan,
				Reversible: a.Reversible, Implemented: a.Implemented,
				Unavailable: a.Unavailable,
				Input:       a.Input,
			})
		}
		out = append(out, dto)
	}
	httpx.OK(w, r, http.StatusOK, out, map[string]any{"count": len(out)})
}

type planRequest struct {
	Input map[string]any `json:"input"`
}

func (h *Handler) plan(w http.ResponseWriter, r *http.Request) {
	incidentID, ok := h.incidentID(w, r)
	if !ok {
		return
	}
	var body planRequest
	if err := decode(w, r, &body); err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	preview, err := h.Executor.Preview(r.Context(), response.PreviewRequest{
		Qualified: r.PathValue("qualified"), IncidentID: &incidentID, Input: body.Input,
	})
	if err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	httpx.OK(w, r, http.StatusOK, toPreviewDTO(preview), nil)
}

type executeRequest struct {
	Input      map[string]any `json:"input"`
	ApprovalID string         `json:"approval_id"`
}

func (h *Handler) execute(w http.ResponseWriter, r *http.Request) {
	incidentID, ok := h.incidentID(w, r)
	if !ok {
		return
	}
	var body executeRequest
	if err := decode(w, r, &body); err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	// A chave vem do cabeçalho, não do corpo: é propriedade da requisição, e
	// um cliente que repete por timeout repete o corpo inteiro.
	key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
	if key == "" {
		httpx.Fail(w, r, h.Log, errs.Coded(errs.ErrValidation, "IDEMPOTENCY_KEY_REQUIRED",
			"envie o cabeçalho Idempotency-Key"))
		return
	}
	if len(key) > 200 {
		httpx.Fail(w, r, h.Log, errs.Coded(errs.ErrValidation, "IDEMPOTENCY_KEY_TOO_LONG",
			"Idempotency-Key excede 200 caracteres"))
		return
	}

	req := response.ExecuteRequest{
		Qualified: r.PathValue("qualified"), IncidentID: &incidentID,
		Input: body.Input, IdempotencyKey: key,
	}
	if body.ApprovalID != "" {
		approvalID, err := id.ParseApproval(body.ApprovalID)
		if err != nil {
			httpx.Fail(w, r, h.Log, errs.Coded(errs.ErrValidation, "INVALID_APPROVAL_ID",
				"approval_id inválido"))
			return
		}
		req.ApprovalID = &approvalID
	}

	run, err := h.Executor.Execute(r.Context(), req)
	if err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	httpx.OK(w, r, http.StatusOK, toRunDTO(run), nil)
}

func (h *Handler) listApprovals(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	pending, err := h.Approver.ListPending(r.Context(), limit)
	if err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	out := make([]approvalDTO, 0, len(pending))
	for _, a := range pending {
		out = append(out, toApprovalDTO(a))
	}
	httpx.OK(w, r, http.StatusOK, out, map[string]any{"count": len(out)})
}

type decideRequest struct {
	Approve         bool   `json:"approve"`
	Note            string `json:"note"`
	ExpectedVersion int    `json:"expected_version"`
}

func (h *Handler) decide(w http.ResponseWriter, r *http.Request) {
	approvalID, err := id.ParseApproval(r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, r, h.Log, errs.Coded(errs.ErrValidation, "INVALID_ID", "id inválido"))
		return
	}
	var body decideRequest
	if err := decode(w, r, &body); err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	version := body.ExpectedVersion
	if raw := strings.Trim(r.Header.Get("If-Match"), `"`); raw != "" {
		v, convErr := strconv.Atoi(raw)
		if convErr != nil {
			httpx.Fail(w, r, h.Log, errs.Coded(errs.ErrValidation, "INVALID_IF_MATCH",
				"If-Match deve ser a versão da aprovação"))
			return
		}
		if version != 0 && version != v {
			httpx.Fail(w, r, h.Log, errs.Coded(errs.ErrValidation, "VERSION_TOKEN_MISMATCH",
				"If-Match e expected_version divergem"))
			return
		}
		version = v
	}

	decided, err := h.Approver.Decide(r.Context(), response.DecideCommand{
		ApprovalID: approvalID, Approve: body.Approve,
		Note: strings.TrimSpace(body.Note), ExpectedVersion: version,
	})
	if err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf(`"%d"`, decided.Version))
	httpx.OK(w, r, http.StatusOK, toApprovalDTO(decided), nil)
}

func (h *Handler) listRuns(w http.ResponseWriter, r *http.Request) {
	incidentID, ok := h.incidentID(w, r)
	if !ok {
		return
	}
	actor, err := h.Executor.Perms.Require(r.Context(), "incident.read")
	if err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	runs, err := h.Runs.ListByIncident(r.Context(), actor.TenantID, incidentID, 100)
	if err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	out := make([]runDTO, 0, len(runs))
	for _, run := range runs {
		out = append(out, toRunDTO(run))
	}
	httpx.OK(w, r, http.StatusOK, out, map[string]any{"count": len(out)})
}

func (h *Handler) incidentID(w http.ResponseWriter, r *http.Request) (id.IncidentID, bool) {
	incidentID, err := id.ParseIncident(r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, r, h.Log, errs.Coded(errs.ErrValidation, "INVALID_ID", "id inválido"))
		return id.IncidentID{}, false
	}
	return incidentID, true
}

func decode(w http.ResponseWriter, r *http.Request, into any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return errs.Coded(errs.ErrValidation, "INVALID_BODY", "corpo inválido: %v", err)
	}
	return nil
}

var _ = time.Time{}
