package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/titas/soar/backend/internal/core/id"
	"github.com/titas/soar/backend/internal/ingestion"
	pg "github.com/titas/soar/backend/internal/platform/postgres"
)

type AlertStore struct{ tx *pg.TxManager }

func NewAlertStore(tx *pg.TxManager) *AlertStore { return &AlertStore{tx: tx} }

// Insert returns false when this alert was already ingested.
//
// The unique constraint on (tenant, source, external_alert_id) plus
// ON CONFLICT DO NOTHING is what makes the consumer idempotent — and that is
// far cheaper and more reliable than chasing exactly-once delivery through
// six different vendors (docs/soar/08 §7.2).
func (s *AlertStore) Insert(ctx context.Context, tenant id.TenantID, source id.SourceID,
	a *ingestion.Alert, incidentID *id.IncidentID, suppressedBy *id.RuleID, reason string) (bool, error) {

	normalized, err := json.Marshal(a.Normalized)
	if err != nil {
		return false, fmt.Errorf("serializar alerta: %w", err)
	}
	sourceRef, err := json.Marshal(a.SourceRef)
	if err != nil {
		return false, err
	}
	status := "grouped"
	var suppressor *uuid.UUID
	if suppressedBy != nil {
		status = "suppressed"
		suppressor = &suppressedBy.UUID
	}
	var incident *uuid.UUID
	if incidentID != nil {
		incident = &incidentID.UUID
	}

	tag, err := s.tx.DB(ctx).Exec(ctx, `
		INSERT INTO incident.alerts
		  (tenant_id, source_id, external_alert_id, incident_id, fingerprint, title,
		   rule_id, rule_name, severity, status, suppressed_by, suppressed_reason,
		   host, entity, entity_kind, event_time, normalized_data, source_ref)
		VALUES ($1,$2,$3,$4,$5,$6,NULLIF($7,''),$8,$9,$10,$11,NULLIF($12,''),
		        NULLIF($13,''),NULLIF($14,''),NULLIF($15,''),$16,$17::jsonb,$18::jsonb)
		ON CONFLICT (tenant_id, source_id, external_alert_id) DO NOTHING`,
		tenant.UUID, source.UUID, a.ExternalID, incident, a.Fingerprint, a.Title,
		a.RuleID, a.RuleName, a.Severity, status, suppressor, reason,
		a.Host, a.Entity, a.EntityKind, a.EventTime, string(normalized), string(sourceRef))
	if err != nil {
		return false, fmt.Errorf("gravar alerta: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

type RawStore struct{ tx *pg.TxManager }

func NewRawStore(tx *pg.TxManager) *RawStore { return &RawStore{tx: tx} }

func (s *RawStore) Pending(ctx context.Context, tenant id.TenantID, limit int) ([]ingestion.PendingRaw, error) {
	rows, err := s.tx.DB(ctx).Query(ctx, `
		SELECT id, tenant_id, source_id, payload, mode, ingested_at
		  FROM platform.raw_intake
		 WHERE tenant_id = $1 AND status = 'accepted'
		 ORDER BY ingested_at
		 LIMIT $2`, tenant.UUID, limit)
	if err != nil {
		return nil, fmt.Errorf("listar bruto pendente: %w", err)
	}
	defer rows.Close()

	var out []ingestion.PendingRaw
	for rows.Next() {
		var (
			r             ingestion.PendingRaw
			rid, tid, sid uuid.UUID
			payload       []byte
		)
		if err := rows.Scan(&rid, &tid, &sid, &payload, &r.Mode, &r.Ingested); err != nil {
			return nil, err
		}
		r.ID = rid.String()
		r.TenantID = id.TenantID{UUID: tid}
		r.SourceID = id.SourceID{UUID: sid}
		_ = json.Unmarshal(payload, &r.Payload)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *RawStore) MarkMapped(ctx context.Context, rawID string) error {
	return s.setStatus(ctx, rawID, "mapped", "")
}

func (s *RawStore) MarkDuplicate(ctx context.Context, rawID string) error {
	return s.setStatus(ctx, rawID, "duplicate", "")
}

// Quarantine keeps the payload. An unrecognisable event is a mapper bug to
// fix and replay, not garbage to delete.
func (s *RawStore) Quarantine(ctx context.Context, rawID, reason string) error {
	return s.setStatus(ctx, rawID, "quarantined", reason)
}

func (s *RawStore) setStatus(ctx context.Context, rawID, status, reason string) error {
	uid, err := uuid.Parse(rawID)
	if err != nil {
		return err
	}
	_, err = s.tx.DB(ctx).Exec(ctx, `
		UPDATE platform.raw_intake
		   SET status=$2, quarantine_reason=NULLIF($3,''), processed_at=now()
		 WHERE id=$1`, uid, status, reason)
	return err
}

// Recent feeds the dry run: the alerts a rule would have seen.
func (s *AlertStore) Recent(ctx context.Context, tenant id.TenantID,
	since time.Time, limit int) ([]*ingestion.Alert, error) {

	rows, err := s.tx.DB(ctx).Query(ctx, `
		SELECT external_alert_id, title, COALESCE(rule_id,''), rule_name, severity,
		       COALESCE(host,''), COALESCE(entity,''), COALESCE(entity_kind,''),
		       event_time, normalized_data
		  FROM incident.alerts
		 WHERE tenant_id = $1 AND ingested_at >= $2
		 ORDER BY ingested_at DESC
		 LIMIT $3`, tenant.UUID, since, limit)
	if err != nil {
		return nil, fmt.Errorf("amostrar alertas: %w", err)
	}
	defer rows.Close()

	var out []*ingestion.Alert
	for rows.Next() {
		var (
			a          ingestion.Alert
			normalized []byte
		)
		if err := rows.Scan(&a.ExternalID, &a.Title, &a.RuleID, &a.RuleName, &a.Severity,
			&a.Host, &a.Entity, &a.EntityKind, &a.EventTime, &normalized); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(normalized, &a.Normalized)
		out = append(out, &a)
	}
	return out, rows.Err()
}
