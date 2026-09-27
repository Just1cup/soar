package http

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/titas/soar/backend/internal/core/errs"
	"github.com/titas/soar/backend/internal/core/id"
	"github.com/titas/soar/backend/internal/core/pagination"
	"github.com/titas/soar/backend/internal/httpx"
	"github.com/titas/soar/backend/internal/incident"
	"github.com/titas/soar/backend/internal/incident/usecase"
)

// Handler does four things and no more: parse, authenticate (later), call the
// use case, map the response. No SQL, no business rule, no vendor call.
type Handler struct {
	List     *usecase.ListIncidents
	Get      *usecase.GetIncident
	Close    usecase.CloseIncident
	Assign   usecase.AssignIncident
	Reopen   usecase.ReopenIncident
	Timeline usecase.GetTimeline
	Cursor   *pagination.Signer
	Log      *slog.Logger
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/incidents", h.list)
	mux.HandleFunc("GET /api/v1/incidents/{id}", h.get)
	mux.HandleFunc("GET /api/v1/incidents/{id}/timeline", h.timeline)
	// Cada ação é um recurso. `POST /doAction` não existe, porque é o que
	// permite RBAC e rate limit por operação (docs/soar/03 §10).
	mux.HandleFunc("POST /api/v1/incidents/{id}/close", h.close)
	mux.HandleFunc("POST /api/v1/incidents/{id}/assign", h.assign)
	mux.HandleFunc("POST /api/v1/incidents/{id}/reopen", h.reopen)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var query usecase.ListQuery

	if v := q.Get("status"); v != "" {
		s := incident.Status(v)
		query.Status = &s
	}
	query.OpenOnly = q.Get("open_only") == "true"
	if v := q.Get("severity"); v != "" {
		s := incident.Severity(v)
		query.Severity = &s
	}
	if v := q.Get("owner_id"); v != "" {
		owner, err := id.ParseUser(v)
		if err != nil {
			httpx.Fail(w, r, h.Log, errs.Coded(errs.ErrValidation, "INVALID_OWNER_ID",
				"owner_id inválido"))
			return
		}
		query.OwnerID = &owner
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			httpx.Fail(w, r, h.Log, errs.Coded(errs.ErrValidation, "INVALID_LIMIT",
				"limit deve ser inteiro"))
			return
		}
		query.Limit = n
	}
	if v := q.Get("cursor"); v != "" {
		key, err := h.Cursor.Decode(v)
		if err != nil {
			httpx.Fail(w, r, h.Log, err)
			return
		}
		query.After = &key
	}

	page, err := h.List.Execute(r.Context(), query)
	if err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}

	items := make([]incidentSummaryDTO, 0, len(page.Items))
	for _, inc := range page.Items {
		items = append(items, toSummary(inc))
	}
	meta := map[string]any{"count": len(items), "next_cursor": nil}
	if page.NextCursor != nil {
		meta["next_cursor"] = h.Cursor.Encode(*page.NextCursor)
	}
	httpx.OK(w, r, http.StatusOK, items, meta)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	incidentID, err := id.ParseIncident(r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, r, h.Log, errs.Coded(errs.ErrValidation, "INVALID_ID",
			"id de incidente inválido"))
		return
	}
	inc, err := h.Get.Execute(r.Context(), incidentID)
	if err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	// The ETag is the concurrency token: a mutation must send it back in
	// If-Match, and a stale one gets 409 rather than overwriting.
	w.Header().Set("ETag", fmt.Sprintf(`"%d"`, inc.Version))
	httpx.OK(w, r, http.StatusOK, toDetail(inc), nil)
}
