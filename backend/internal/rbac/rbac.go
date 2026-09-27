// Package rbac answers one question: may this actor do this?
//
// The check lives in the use case, never in the handler and never in the
// frontend. Hiding a button is user experience; it is not a control.
package rbac

import (
	"context"

	"github.com/titas/soar/backend/internal/auth"
	"github.com/titas/soar/backend/internal/core/errs"
)

// The permissions the platform actually enforces. Constants rather than
// strings at call sites, so a typo is a build error.
const (
	IncidentRead            = "incident.read"
	IncidentAssign          = "incident.assign"
	IncidentClose           = "incident.close"
	IncidentReopen          = "incident.reopen"
	IncidentChangeSeverity  = "incident.change_severity"
	CaseComment             = "case.comment"
	CaseTaskComplete        = "case.task.complete"
	CaseSkipMandatoryTask   = "case.skip_mandatory_task"
	AssessmentPromote       = "assessment.promote"
	ApprovalDecide          = "approval.decide"
	AuditRead               = "audit.read"
	ResponseCloseAlerts     = "response.close_alerts"
	ResponseCreateException = "response.create_exception"
)

type Checker struct{}

// Require returns ErrForbidden when the actor lacks the permission. The caller
// is expected to treat that as final: there is no "unless" branch.
func (Checker) Require(ctx context.Context, permission string) (auth.Actor, error) {
	actor, err := auth.FromContext(ctx)
	if err != nil {
		return auth.Actor{}, err
	}
	if !actor.Can(permission) {
		return auth.Actor{}, errs.Coded(errs.ErrForbidden, "PERMISSION_DENIED",
			"falta a permissão %s", permission)
	}
	return actor, nil
}
