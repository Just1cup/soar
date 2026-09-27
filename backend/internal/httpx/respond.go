// Package httpx is the transport edge: envelopes, error mapping, middleware.
//
// The error mapping lives here and only here. A domain error is translated to
// a status code in one table, so renaming a message can never change an HTTP
// contract, and adding a new sentinel is a one-line change in one file.
package httpx

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/titas/soar/backend/internal/core/errs"
	"github.com/titas/soar/backend/internal/platform/telemetry"
)

type envelope struct {
	Data      any    `json:"data"`
	Meta      any    `json:"meta,omitempty"`
	RequestID string `json:"request_id"`
}

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type errorEnvelope struct {
	Error     errorBody `json:"error"`
	RequestID string    `json:"request_id"`
}

func OK(w http.ResponseWriter, r *http.Request, status int, data, meta any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(envelope{
		Data: data, Meta: meta, RequestID: telemetry.RequestID(r.Context()),
	})
}

// statusFor is the whole mapping. Order matters: the specific wrapped
// sentinels are checked before the general ones they wrap.
func statusFor(err error) int {
	switch {
	case errors.Is(err, errs.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, errs.ErrUnauthorized):
		return http.StatusUnauthorized
	case errors.Is(err, errs.ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, errs.ErrValidation):
		return http.StatusUnprocessableEntity
	case errors.Is(err, errs.ErrApprovalRequired):
		return http.StatusPreconditionFailed
	case errors.Is(err, errs.ErrPreconditionFailed):
		return http.StatusPreconditionRequired
	case errors.Is(err, errs.ErrConflict): // cobre transição inválida e versão
		return http.StatusConflict
	case errors.Is(err, errs.ErrRateLimited):
		return http.StatusTooManyRequests
	case errors.Is(err, errs.ErrUnavailable):
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// Fail answers the client and logs the detail. A 500 never leaks the cause:
// the client gets a generic message and a request_id, and the operator finds
// the rest in the log under that id.
func Fail(w http.ResponseWriter, r *http.Request, log *slog.Logger, err error) {
	status := statusFor(err)
	code := errs.CodeOf(err)
	message := err.Error()

	l := telemetry.LoggerFrom(r.Context(), log).With(
		"path", r.URL.Path, "method", r.Method, "status", status, "code", code)
	if status >= 500 {
		l.Error("request failed", "error", err)
		message = "erro interno; use o request_id para investigar"
	} else {
		l.Info("request rejected", "error", err)
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorEnvelope{
		Error:     errorBody{Code: code, Message: message},
		RequestID: telemetry.RequestID(r.Context()),
	})
}
