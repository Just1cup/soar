// Package usecase holds the application layer: it orchestrates the domain and
// the ports, and contains no business rules of its own.
package usecase

import (
	"context"
	"fmt"

	"github.com/titas/soar/backend/internal/core/errs"
	"github.com/titas/soar/backend/internal/core/id"
	"github.com/titas/soar/backend/internal/core/pagination"
	"github.com/titas/soar/backend/internal/incident"
	"github.com/titas/soar/backend/internal/rbac"
)

type ListIncidents struct {
	Repo  incident.Repository
	Perms rbac.Checker
}

type ListQuery struct {
	Status   *incident.Status
	OpenOnly bool
	Severity *incident.Severity
	OwnerID  *id.UserID
	Limit    int
	After    *pagination.Key
}

func (uc *ListIncidents) Execute(ctx context.Context, q ListQuery) (incident.Page, error) {
	actor, err := uc.Perms.Require(ctx, rbac.IncidentRead)
	if err != nil {
		return incident.Page{}, err
	}
	if q.Status != nil && !q.Status.Valid() {
		return incident.Page{}, errs.Coded(errs.ErrValidation, "INVALID_STATUS",
			"status desconhecido: %q", *q.Status)
	}
	if q.Severity != nil && !q.Severity.Valid() {
		return incident.Page{}, errs.Coded(errs.ErrValidation, "INVALID_SEVERITY",
			"severidade desconhecida: %q", *q.Severity)
	}
	page, err := uc.Repo.List(ctx, actor.TenantID, incident.Filter{
		Status:   q.Status,
		OpenOnly: q.OpenOnly,
		Severity: q.Severity,
		OwnerID:  q.OwnerID,
		Limit:    pagination.ClampLimit(q.Limit),
		After:    q.After,
	})
	if err != nil {
		return incident.Page{}, fmt.Errorf("listar incidentes: %w", err)
	}
	return page, nil
}
