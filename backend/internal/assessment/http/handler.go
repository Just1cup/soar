// Package http exposes the assessments attached to an incident.
package http

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/titas/soar/backend/internal/assessment"
	"github.com/titas/soar/backend/internal/core/errs"
	"github.com/titas/soar/backend/internal/core/id"
	"github.com/titas/soar/backend/internal/httpx"
)

type Handler struct {
	Service *assessment.Service
	Log     *slog.Logger
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/incidents/{id}/evidence", h.evidence)
	mux.HandleFunc("GET /api/v1/incidents/{id}/assessments", h.list)
	// A promoção é escopada ao incidente na rota, e não só pelo id da
	// avaliação: promover a avaliação de OUTRO caso por engano seria um erro
	// silencioso, e o caminho torna isso impossível de expressar.
	mux.HandleFunc("POST /api/v1/incidents/{id}/assessments/{assessmentId}/promote", h.promote)
}

func (h *Handler) evidence(w http.ResponseWriter, r *http.Request) {
	incidentID, err := id.ParseIncident(r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, r, h.Log, errs.Coded(errs.ErrValidation, "INVALID_ID", "id inválido"))
		return
	}
	bundle, err := h.Service.Evidence(r.Context(), incidentID)
	if err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	httpx.OK(w, r, http.StatusOK, evidenceDTO{
		Cluster: bundle.Cluster, CaseContext: bundle.Case,
	}, nil)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	incidentID, err := id.ParseIncident(r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, r, h.Log, errs.Coded(errs.ErrValidation, "INVALID_ID", "id inválido"))
		return
	}
	items, err := h.Service.List(r.Context(), incidentID)
	if err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	out := make([]assessmentDTO, 0, len(items))
	for _, a := range items {
		out = append(out, toDTO(a))
	}
	httpx.OK(w, r, http.StatusOK, out, map[string]any{"count": len(out)})
}

type promoteRequest struct {
	Note string `json:"note"`
}

func (h *Handler) promote(w http.ResponseWriter, r *http.Request) {
	incidentID, err := id.ParseIncident(r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, r, h.Log, errs.Coded(errs.ErrValidation, "INVALID_ID", "id de incidente inválido"))
		return
	}
	assessmentID, err := id.ParseAssessment(r.PathValue("assessmentId"))
	if err != nil {
		httpx.Fail(w, r, h.Log, errs.Coded(errs.ErrValidation, "INVALID_ID", "id de avaliação inválido"))
		return
	}
	var body promoteRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		httpx.Fail(w, r, h.Log, errs.Coded(errs.ErrValidation, "INVALID_BODY", "corpo inválido"))
		return
	}
	promoted, err := h.Service.Promote(r.Context(), incidentID, assessmentID, strings.TrimSpace(body.Note))
	if err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	httpx.OK(w, r, http.StatusOK, toDTO(promoted), nil)
}
