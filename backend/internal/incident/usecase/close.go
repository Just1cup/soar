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

type CloseIncident struct{ Deps }

type CloseCommand struct {
	IncidentID      id.IncidentID
	Resolution      incident.Resolution
	Reason          string
	ExpectedVersion int
}

func (uc CloseIncident) Execute(ctx context.Context, cmd CloseCommand) (*incident.Incident, error) {
	return uc.mutation(ctx, rbac.IncidentClose, cmd.IncidentID, cmd.ExpectedVersion,
		func(i *incident.Incident, a auth.Actor, now time.Time) error {
			if a.UserID != nil {
				i.Acknowledge(*a.UserID, now) // automação não conta como atenção humana
			}
			return i.Close(cmd.Resolution, cmd.Reason, a.UserID, now)
		},
		func(i *incident.Incident, a auth.Actor) audit.Fact {
			return audit.Fact{
				Classification: audit.Both,
				Action:         "incident.close",
				ResourceType:   "incident",
				ResourceID:     i.ID.String(),
				Reason:         cmd.Reason,
				EventType:      "incident.closed",
				Title:          "Incidente fechado como " + resolutionLabel(cmd.Resolution),
				Detail:         cmd.Reason,
				Payload:        map[string]any{"resolution": string(cmd.Resolution)},
			}
		})
}

// resolutionLabel keeps the vocabulary honest in the UI. benign_true_positive
// is the category most tooling lacks and most alerts fall into: the rule fired
// correctly and the activity was authorised.
func resolutionLabel(r incident.Resolution) string {
	switch r {
	case incident.ResolutionTruePositive:
		return "verdadeiro positivo"
	case incident.ResolutionBenignTruePositive:
		return "verdadeiro positivo benigno"
	case incident.ResolutionFalsePositive:
		return "falso positivo"
	default:
		return "inconclusivo"
	}
}
