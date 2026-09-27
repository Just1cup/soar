package http

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/titas/soar/backend/internal/core/errs"
	"github.com/titas/soar/backend/internal/core/id"
	"github.com/titas/soar/backend/internal/httpx"
	"github.com/titas/soar/backend/internal/incident"
	"github.com/titas/soar/backend/internal/incident/usecase"
)

type closeRequest struct {
	Resolution      string `json:"resolution"`
	Reason          string `json:"reason"`
	ExpectedVersion *int   `json:"expected_version,omitempty"`
}

type assignRequest struct {
	OwnerID         string `json:"owner_id"`
	ExpectedVersion *int   `json:"expected_version,omitempty"`
}

type reasonRequest struct {
	Reason          string `json:"reason"`
	ExpectedVersion *int   `json:"expected_version,omitempty"`
}

// expectedVersion reads the concurrency token from If-Match, falling back to
// the body. Every mutation must prove which representation it reviewed; an
// unconditional write would defeat optimistic locking.
func expectedVersion(r *http.Request, bodyVersion *int) (*int, error) {
	raw := strings.Trim(r.Header.Get("If-Match"), `"`)
	if raw == "" {
		if bodyVersion == nil {
			return nil, errs.Coded(errs.ErrPreconditionFailed, "EXPECTED_VERSION_REQUIRED",
				"envie If-Match ou expected_version")
		}
		if *bodyVersion < 1 {
			return nil, errs.Coded(errs.ErrValidation, "INVALID_EXPECTED_VERSION",
				"expected_version deve ser positivo")
		}
		return bodyVersion, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 1 {
		return nil, errs.Coded(errs.ErrValidation, "INVALID_IF_MATCH",
			"If-Match deve ser a versão do incidente")
	}
	if bodyVersion != nil && *bodyVersion != v {
		return nil, errs.Coded(errs.ErrValidation, "VERSION_TOKEN_MISMATCH",
			"If-Match e expected_version divergem")
	}
	return &v, nil
}

func decode[T any](w http.ResponseWriter, r *http.Request) (T, error) {
	var body T
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024))
	dec.DisallowUnknownFields() // campo desconhecido é erro do cliente, não silêncio
	if err := dec.Decode(&body); err != nil {
		return body, errs.Coded(errs.ErrValidation, "INVALID_BODY", "corpo inválido: %v", err)
	}
	return body, nil
}

func (h *Handler) close(w http.ResponseWriter, r *http.Request) {
	incidentID, err := id.ParseIncident(r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, r, h.Log, errs.Coded(errs.ErrValidation, "INVALID_ID", "id inválido"))
		return
	}
	body, err := decode[closeRequest](w, r)
	if err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	version, err := expectedVersion(r, body.ExpectedVersion)
	if err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	inc, err := h.Close.Execute(r.Context(), usecase.CloseCommand{
		IncidentID:      incidentID,
		Resolution:      incident.Resolution(body.Resolution),
		Reason:          strings.TrimSpace(body.Reason),
		ExpectedVersion: *version,
	})
	if err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf(`"%d"`, inc.Version))
	httpx.OK(w, r, http.StatusOK, toDetail(inc), nil)
}

func (h *Handler) assign(w http.ResponseWriter, r *http.Request) {
	incidentID, err := id.ParseIncident(r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, r, h.Log, errs.Coded(errs.ErrValidation, "INVALID_ID", "id inválido"))
		return
	}
	body, err := decode[assignRequest](w, r)
	if err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	owner, err := id.ParseUser(body.OwnerID)
	if err != nil {
		httpx.Fail(w, r, h.Log, errs.Coded(errs.ErrValidation, "INVALID_OWNER_ID", "owner_id inválido"))
		return
	}
	version, err := expectedVersion(r, body.ExpectedVersion)
	if err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	inc, err := h.Assign.Execute(r.Context(), usecase.AssignCommand{
		IncidentID: incidentID, OwnerID: owner, ExpectedVersion: *version,
	})
	if err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf(`"%d"`, inc.Version))
	httpx.OK(w, r, http.StatusOK, toDetail(inc), nil)
}

func (h *Handler) reopen(w http.ResponseWriter, r *http.Request) {
	incidentID, err := id.ParseIncident(r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, r, h.Log, errs.Coded(errs.ErrValidation, "INVALID_ID", "id inválido"))
		return
	}
	body, err := decode[reasonRequest](w, r)
	if err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	version, err := expectedVersion(r, body.ExpectedVersion)
	if err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	inc, err := h.Reopen.Execute(r.Context(), usecase.ReopenCommand{
		IncidentID: incidentID, Reason: strings.TrimSpace(body.Reason), ExpectedVersion: *version,
	})
	if err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf(`"%d"`, inc.Version))
	httpx.OK(w, r, http.StatusOK, toDetail(inc), nil)
}

func (h *Handler) timeline(w http.ResponseWriter, r *http.Request) {
	incidentID, err := id.ParseIncident(r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, r, h.Log, errs.Coded(errs.ErrValidation, "INVALID_ID", "id inválido"))
		return
	}
	entries, err := h.Timeline.Execute(r.Context(), incidentID)
	if err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	out := make([]timelineDTO, 0, len(entries))
	for _, e := range entries {
		out = append(out, timelineDTO{
			ID: e.ID, OccurredAt: e.OccurredAt, EventType: e.EventType,
			ActorKind: e.ActorKind, ActorLabel: e.ActorLabel,
			Title: e.Title, Detail: e.Detail, Payload: e.Payload,
		})
	}
	httpx.OK(w, r, http.StatusOK, out, map[string]any{"count": len(out)})
}
