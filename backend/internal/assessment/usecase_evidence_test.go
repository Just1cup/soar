package assessment

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/titas/soar/backend/internal/auth"
	"github.com/titas/soar/backend/internal/core/id"
	"github.com/titas/soar/backend/internal/rbac"
)

func TestEvidenceBuildsFactsWithoutGenerator(t *testing.T) {
	tenant := id.TenantID{UUID: uuid.New()}
	incidentID := id.IncidentID{UUID: uuid.New()}
	at := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	service := &Service{
		Perms: rbac.Checker{},
		Context: &ContextBuilder{Store: evidenceStore{
			facts: IncidentFacts{
				Key: "INC-1", Title: "case", Rule: "rule", Severity: "high",
				Host: "web-01", AlertCount: 1, FirstSeen: at, LastSeen: at,
				Entity: "/usr/bin/caddy", EntityKind: "process.executable",
			},
			alerts: []AlertRow{{EventTime: at, RuleName: "rule", Host: "web-01", Process: "/usr/bin/caddy", DestIP: "203.0.113.20"}},
		}},
	}
	ctx := auth.WithActor(context.Background(), auth.Actor{
		TenantID: tenant, Perms: map[string]bool{rbac.IncidentRead: true},
	})

	got, err := service.Evidence(ctx, incidentID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cluster.ClusterID == "" || got.Cluster.Observables["process.executable"][0] != "/usr/bin/caddy" {
		t.Fatalf("deterministic evidence missing: %#v", got.Cluster)
	}
	if got.Cluster.Observables["destination.ip"][0] != "203.0.113.20" {
		t.Fatalf("destination IOC missing: %#v", got.Cluster.Observables)
	}
}

type evidenceStore struct {
	facts  IncidentFacts
	alerts []AlertRow
}

func (s evidenceStore) IncidentFacts(context.Context, id.TenantID, id.IncidentID) (IncidentFacts, error) {
	return s.facts, nil
}

func (s evidenceStore) AlertTimes(context.Context, id.TenantID, id.IncidentID, int) ([]AlertRow, error) {
	return s.alerts, nil
}

func (s evidenceStore) ActionHistory(context.Context, id.TenantID, id.IncidentID) ([]ActionFact, error) {
	return nil, nil
}
