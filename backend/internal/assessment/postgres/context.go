package postgres

import (
	"context"
	"fmt"

	"github.com/titas/soar/backend/internal/assessment"
	"github.com/titas/soar/backend/internal/core/id"
)

// IncidentFacts reads what the platform already knows. Nothing here goes to
// the SIEM: the incident, its counters and its window live in Postgres.
func (s *Store) IncidentFacts(ctx context.Context, tenant id.TenantID,
	incidentID id.IncidentID) (assessment.IncidentFacts, error) {

	var f assessment.IncidentFacts
	err := s.tx.DB(ctx).QueryRow(ctx, `
			SELECT i.key, i.title, COALESCE(i.source_rule,''), i.severity,
			       COALESCE(h.host,''), i.alert_count, i.first_seen, i.last_seen,
			       COALESCE(h.entity,''), COALESCE(h.entity_kind,''),
			       i.attack_tactics, i.attack_techniques
		  FROM incident.incidents i
		  LEFT JOIN LATERAL (
			      SELECT a.host, a.entity, a.entity_kind FROM incident.alerts a
		       WHERE a.incident_id = i.id
		       ORDER BY a.event_time
		       LIMIT 1
		  ) h ON true
		 WHERE i.tenant_id=$1 AND i.id=$2`,
		tenant.UUID, incidentID.UUID,
	).Scan(&f.Key, &f.Title, &f.Rule, &f.Severity, &f.Host,
		&f.AlertCount, &f.FirstSeen, &f.LastSeen, &f.Entity, &f.EntityKind,
		&f.Tactics, &f.Techniques)
	if err != nil {
		return f, fmt.Errorf("fatos do incidente: %w", err)
	}
	return f, nil
}

func (s *Store) AlertTimes(ctx context.Context, tenant id.TenantID,
	incidentID id.IncidentID, limit int) ([]assessment.AlertRow, error) {

	rows, err := s.tx.DB(ctx).Query(ctx, `
		SELECT event_time, rule_name, COALESCE(host,''),
		       COALESCE(normalized_data->'process'->>'executable',''),
		       COALESCE(normalized_data->'user'->>'name',''),
		       COALESCE(normalized_data->'source'->>'ip',''),
		       COALESCE(normalized_data->'destination'->>'ip','')
		  FROM incident.alerts
		 WHERE tenant_id=$1 AND incident_id=$2
		 ORDER BY event_time
		 LIMIT $3`, tenant.UUID, incidentID.UUID, limit)
	if err != nil {
		return nil, fmt.Errorf("alertas do incidente: %w", err)
	}
	defer rows.Close()

	var out []assessment.AlertRow
	for rows.Next() {
		var r assessment.AlertRow
		if err := rows.Scan(&r.EventTime, &r.RuleName, &r.Host,
			&r.Process, &r.User, &r.SourceIP, &r.DestIP); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ActionHistory matters to the model: "an exception was already created for
// this rule" changes what the right recommendation is.
func (s *Store) ActionHistory(ctx context.Context, tenant id.TenantID,
	incidentID id.IncidentID) ([]assessment.ActionFact, error) {

	rows, err := s.tx.DB(ctx).Query(ctx, `
		SELECT integration_slug || '.' || action, status, affected_count, actor_id, requested_at
		  FROM response.action_runs
		 WHERE tenant_id=$1 AND incident_id=$2
		 ORDER BY requested_at`, tenant.UUID, incidentID.UUID)
	if err != nil {
		return nil, fmt.Errorf("histórico de ações: %w", err)
	}
	defer rows.Close()

	var out []assessment.ActionFact
	for rows.Next() {
		var a assessment.ActionFact
		if err := rows.Scan(&a.Action, &a.Status, &a.Affected, &a.Actor, &a.At); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
