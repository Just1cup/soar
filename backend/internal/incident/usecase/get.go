package usecase

import (
	"context"
	"errors"
	"fmt"

	"github.com/titas/soar/backend/internal/core/errs"
	"github.com/titas/soar/backend/internal/core/id"
	"github.com/titas/soar/backend/internal/incident"
	"github.com/titas/soar/backend/internal/rbac"
)

type GetIncident struct {
	Repo  incident.Repository
	Perms rbac.Checker
}

func (uc *GetIncident) Execute(ctx context.Context, incidentID id.IncidentID) (*incident.Incident, error) {
	actor, err := uc.Perms.Require(ctx, rbac.IncidentRead)
	if err != nil {
		return nil, err
	}
	inc, err := uc.Repo.FindByID(ctx, actor.TenantID, incidentID)
	if err != nil {
		if errors.Is(err, errs.ErrNotFound) {
			// Re-coded so the client gets a specific, stable code without the
			// repository having to know what resource it is serving.
			return nil, errs.Coded(errs.ErrNotFound, "INCIDENT_NOT_FOUND",
				"incidente não encontrado")
		}
		return nil, fmt.Errorf("buscar incidente: %w", err)
	}
	return inc, nil
}
