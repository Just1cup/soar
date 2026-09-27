package usecase

import (
	"context"
	"errors"
	"fmt"

	"github.com/titas/soar/backend/internal/audit"
	"github.com/titas/soar/backend/internal/core/errs"
	"github.com/titas/soar/backend/internal/core/id"
	"github.com/titas/soar/backend/internal/incident"
	"github.com/titas/soar/backend/internal/rbac"
)

// GetTimeline serves the War Room: the chronological journal of one incident.
type GetTimeline struct {
	Reader audit.Reader
	Repo   incident.Repository
	Perms  rbac.Checker
}

func (uc GetTimeline) Execute(ctx context.Context, incidentID id.IncidentID) ([]audit.TimelineEntry, error) {
	actor, err := uc.Perms.Require(ctx, rbac.IncidentRead)
	if err != nil {
		return nil, err
	}
	if _, err := uc.Repo.FindByID(ctx, actor.TenantID, incidentID); err != nil {
		if errors.Is(err, errs.ErrNotFound) {
			return nil, errs.Coded(errs.ErrNotFound, "INCIDENT_NOT_FOUND", "incidente não encontrado")
		}
		return nil, fmt.Errorf("buscar incidente da timeline: %w", err)
	}
	entries, err := uc.Reader.Timeline(ctx, actor.TenantID, incidentID, 500)
	if err != nil {
		return nil, fmt.Errorf("carregar timeline: %w", err)
	}
	return entries, nil
}
