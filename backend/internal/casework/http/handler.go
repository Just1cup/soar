package http

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/titas/soar/backend/internal/casework"
	"github.com/titas/soar/backend/internal/core/errs"
	"github.com/titas/soar/backend/internal/core/id"
	"github.com/titas/soar/backend/internal/httpx"
)

type Handler struct {
	Service casework.Service
	Log     *slog.Logger
}

func (h Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/incidents/{id}/tasks", h.tasks)
	mux.HandleFunc("POST /api/v1/incidents/{id}/tasks/{taskId}/complete", h.complete)
	mux.HandleFunc("GET /api/v1/incidents/{id}/tasks/{taskId}/notes", h.notes)
	mux.HandleFunc("POST /api/v1/incidents/{id}/tasks/{taskId}/notes", h.addNote)
}

func (h Handler) ids(r *http.Request) (id.IncidentID, uuid.UUID, error) {
	incidentID, err := id.ParseIncident(r.PathValue("id"))
	if err != nil {
		return id.IncidentID{}, uuid.Nil, errs.Coded(errs.ErrValidation, "INVALID_ID", "id de incidente inválido")
	}
	if r.PathValue("taskId") == "" {
		return incidentID, uuid.Nil, nil
	}
	taskID, err := uuid.Parse(r.PathValue("taskId"))
	if err != nil {
		return id.IncidentID{}, uuid.Nil, errs.Coded(errs.ErrValidation, "INVALID_TASK_ID", "id de tarefa inválido")
	}
	return incidentID, taskID, nil
}

func (h Handler) tasks(w http.ResponseWriter, r *http.Request) {
	incidentID, _, err := h.ids(r)
	if err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	tasks, err := h.Service.List(r.Context(), incidentID)
	if err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	httpx.OK(w, r, http.StatusOK, tasks, map[string]any{"count": len(tasks)})
}

func (h Handler) notes(w http.ResponseWriter, r *http.Request) {
	incidentID, taskID, err := h.ids(r)
	if err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	notes, err := h.Service.Notes(r.Context(), incidentID, taskID)
	if err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	httpx.OK(w, r, http.StatusOK, notes, map[string]any{"count": len(notes)})
}

func (h Handler) complete(w http.ResponseWriter, r *http.Request) {
	incidentID, taskID, err := h.ids(r)
	if err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	var body struct {
		ExpectedVersion int `json:"expected_version"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		httpx.Fail(w, r, h.Log, errs.Coded(errs.ErrValidation, "INVALID_BODY", "corpo inválido"))
		return
	}
	task, err := h.Service.Complete(r.Context(), incidentID, taskID, body.ExpectedVersion)
	if err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	httpx.OK(w, r, http.StatusOK, task, nil)
}

func (h Handler) addNote(w http.ResponseWriter, r *http.Request) {
	incidentID, taskID, err := h.ids(r)
	if err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	var body struct {
		Body string `json:"body"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		httpx.Fail(w, r, h.Log, errs.Coded(errs.ErrValidation, "INVALID_BODY", "corpo inválido"))
		return
	}
	note, err := h.Service.AddNote(r.Context(), incidentID, taskID, body.Body)
	if err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	httpx.OK(w, r, http.StatusCreated, note, nil)
}
