// Package errs is the error vocabulary of the domain.
//
// Two rules make this worth having. First, transport never inspects strings:
// handlers map errors with errors.Is, so renaming a message cannot change an
// HTTP status. Second, every error carries a stable Code that the client may
// branch on — a UI that must parse prose to tell "not found" from "forbidden"
// is a UI that breaks on the next copy edit.
package errs

import (
	"errors"
	"fmt"
)

// Sentinels. Handlers map these to status codes, once, in one place.
var (
	ErrNotFound           = errors.New("not found")
	ErrValidation         = errors.New("validation failed")
	ErrConflict           = errors.New("conflict")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrForbidden          = errors.New("forbidden")
	ErrPreconditionFailed = errors.New("precondition failed")
	ErrApprovalRequired   = errors.New("approval required")
	ErrRateLimited        = errors.New("rate limited")
	ErrUnavailable        = errors.New("dependency unavailable")
	// ErrNotImplemented é diferente de "não existe": a ação está no catálogo,
	// a permissão pode ser concedida, e ainda assim não há adapter compilado
	// neste deploy. Fingir que a capacidade não existe seria pior.
	ErrNotImplemented         = errors.New("not implemented")
	ErrInvalidStateTransition = fmt.Errorf("%w: invalid state transition", ErrConflict)
	ErrVersionConflict        = fmt.Errorf("%w: version conflict", ErrConflict)
)

// Error carries a client-facing code alongside a sentinel, so that
// errors.Is keeps working while the API stays stable.
type Error struct {
	Code string
	Msg  string
	Err  error
}

func (e *Error) Error() string {
	if e.Msg == "" {
		return e.Err.Error()
	}
	return e.Msg
}

func (e *Error) Unwrap() error { return e.Err }

// Coded wraps a sentinel with a stable code and a message safe to show.
func Coded(err error, code, format string, args ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, args...), Err: err}
}

// CodeOf returns the stable code, or a fallback derived from the sentinel.
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) && e.Code != "" {
		return e.Code
	}
	switch {
	case errors.Is(err, ErrNotFound):
		return "NOT_FOUND"
	case errors.Is(err, ErrValidation):
		return "VALIDATION_FAILED"
	case errors.Is(err, ErrVersionConflict):
		return "VERSION_CONFLICT"
	case errors.Is(err, ErrConflict):
		return "CONFLICT"
	case errors.Is(err, ErrUnauthorized):
		return "UNAUTHORIZED"
	case errors.Is(err, ErrForbidden):
		return "FORBIDDEN"
	case errors.Is(err, ErrPreconditionFailed):
		return "PRECONDITION_FAILED"
	case errors.Is(err, ErrApprovalRequired):
		return "APPROVAL_REQUIRED"
	case errors.Is(err, ErrRateLimited):
		return "RATE_LIMITED"
	case errors.Is(err, ErrUnavailable):
		return "DEPENDENCY_UNAVAILABLE"
	case errors.Is(err, ErrNotImplemented):
		return "NOT_IMPLEMENTED"
	default:
		return "INTERNAL_ERROR"
	}
}
