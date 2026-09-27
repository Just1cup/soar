package usecase

import (
	"context"
	"time"

	"github.com/titas/soar/backend/internal/audit"
	"github.com/titas/soar/backend/internal/auth"
	"github.com/titas/soar/backend/internal/core/id"
	"github.com/titas/soar/backend/internal/incident"
	"github.com/titas/soar/backend/internal/rbac"
)

type AssignIncident struct{ Deps }

type AssignCommand struct {
	IncidentID      id.IncidentID
	OwnerID         id.UserID
	ExpectedVersion int
}

func (uc AssignIncident) Execute(ctx context.Context, cmd AssignCommand) (*incident.Incident, error) {
	return uc.mutation(ctx, rbac.IncidentAssign, cmd.IncidentID, cmd.ExpectedVersion,
		func(i *incident.Incident, a auth.Actor, now time.Time) error {
			if a.UserID != nil {
				i.Acknowledge(*a.UserID, now)
			}
			return i.Assign(cmd.OwnerID, now)
		},
		func(i *incident.Incident, a auth.Actor) audit.Fact {
			return audit.Fact{
				Classification: audit.Both,
				Action:         "incident.assign",
				ResourceType:   "incident",
				ResourceID:     i.ID.String(),
				EventType:      "incident.assigned",
				Title:          "Incidente atribuído",
				Payload:        map[string]any{"owner_id": cmd.OwnerID.String()},
			}
		})
}

type ReopenIncident struct{ Deps }

type ReopenCommand struct {
	IncidentID      id.IncidentID
	Reason          string
	ExpectedVersion int
}

func (uc ReopenIncident) Execute(ctx context.Context, cmd ReopenCommand) (*incident.Incident, error) {
	return uc.mutation(ctx, rbac.IncidentReopen, cmd.IncidentID, cmd.ExpectedVersion,
		func(i *incident.Incident, a auth.Actor, now time.Time) error {
			return i.Reopen(cmd.Reason, a.UserID, now)
		},
		func(i *incident.Incident, a auth.Actor) audit.Fact {
			// A reabertura NÃO apaga o fechamento anterior: ela acrescenta uma
			// linha. Quem ler a trilha vê os dois, na ordem em que aconteceram.
			return audit.Fact{
				Classification: audit.Both,
				Action:         "incident.reopen",
				ResourceType:   "incident",
				ResourceID:     i.ID.String(),
				Reason:         cmd.Reason,
				EventType:      "incident.reopened",
				Title:          "Incidente reaberto",
				Detail:         cmd.Reason,
			}
		})
}
