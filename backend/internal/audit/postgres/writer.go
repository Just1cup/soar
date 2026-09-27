// Package postgres implements audit.Writer and audit.Reader.
package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/titas/soar/backend/internal/audit"
	"github.com/titas/soar/backend/internal/core/id"
	pg "github.com/titas/soar/backend/internal/platform/postgres"
)

type Store struct{ tx *pg.TxManager }

func New(tx *pg.TxManager) *Store { return &Store{tx: tx} }

// redactKeys never reach the database. The list is applied here and again at
// the logging edge — two independent places, because one of them will be
// forgotten some day (docs/soar/06 §6).
var redactKeys = map[string]bool{
	"password": true, "passwordhash": true, "apikey": true, "token": true,
	"accesstoken": true, "refreshtoken": true, "authorization": true,
	"cookie": true, "secret": true, "clientsecret": true,
	"credential": true, "privatekey": true,
}

func normalizedKey(k string) string {
	k = strings.ToLower(k)
	return strings.NewReplacer("_", "", "-", "", " ", "", ".", "").Replace(k)

}

func redactValue(v any) any {
	switch value := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(value))
		for k, nested := range value {
			if redactKeys[normalizedKey(k)] {
				out[k] = "[redigido]"
				continue
			}
			out[k] = redactValue(nested)
		}
		return out
	case []any:
		out := make([]any, len(value))
		for i, nested := range value {
			out[i] = redactValue(nested)
		}
		return out
	default:
		return value
	}
}

func jsonb(m map[string]any) (any, error) {
	if m == nil {
		return nil, nil
	}
	raw, err := json.Marshal(redactValue(m))
	if err != nil {
		return nil, err
	}
	// pgx encodes []byte as bytea. A string lets PostgreSQL apply the target
	// JSONB type instead of trying to parse a bytea literal beginning with \\x.
	return string(raw), nil
}

// Record writes the fact inside the caller's transaction. It is the only
// function in the codebase that inserts into the audit schema.
func (s *Store) Record(ctx context.Context, f audit.Fact) error {
	db := s.tx.DB(ctx)
	var auditID *uuid.UUID

	if f.Classification == audit.AuditOnly || f.Classification == audit.Both {
		before, err := jsonb(f.Before)
		if err != nil {
			return fmt.Errorf("serializar before: %w", err)
		}
		after, err := jsonb(f.After)
		if err != nil {
			return fmt.Errorf("serializar after: %w", err)
		}
		var incidentID *uuid.UUID
		if f.IncidentID != nil {
			incidentID = &f.IncidentID.UUID
		}
		var generated uuid.UUID
		err = db.QueryRow(ctx, `
			INSERT INTO audit.audit_events
			  (tenant_id, occurred_at, actor_kind, actor_id, action, resource_type,
			   resource_id, incident_id, result, reason, before_state, after_state,
			   request_id, trace_id, execution_id, source_ip)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,NULLIF($16,'')::inet)
			RETURNING id`,
			f.TenantID.UUID, f.OccurredAt, string(f.Actor.Kind), f.Actor.ID,
			f.Action, f.ResourceType, f.ResourceID, incidentID, string(f.Result),
			nullable(f.Reason), before, after,
			nullable(f.RequestID), nullable(f.TraceID), f.ExecutionID, f.SourceIP,
		).Scan(&generated)
		if err != nil {
			return fmt.Errorf("gravar auditoria: %w", err)
		}
		auditID = &generated
	}

	if (f.Classification == audit.TimelineOnly || f.Classification == audit.Both) && f.IncidentID != nil {
		payload, err := jsonb(f.Payload)
		if err != nil {
			return fmt.Errorf("serializar payload: %w", err)
		}
		if payload == nil {
			payload = `{}`
		}
		_, err = db.Exec(ctx, `
			INSERT INTO audit.timeline_events
			  (tenant_id, incident_id, occurred_at, event_type, actor_kind, actor_id,
			   actor_label, title, detail, payload, audit_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
			f.TenantID.UUID, f.IncidentID.UUID, f.OccurredAt, f.EventType,
			string(f.Actor.Kind), f.Actor.ID, f.Actor.Label, f.Title,
			nullable(f.Detail), payload, auditID,
		)
		if err != nil {
			return fmt.Errorf("gravar timeline: %w", err)
		}
	}
	return nil
}

func (s *Store) Timeline(ctx context.Context, tenant id.TenantID, incidentID id.IncidentID, limit int) ([]audit.TimelineEntry, error) {
	rows, err := s.tx.DB(ctx).Query(ctx, `
		SELECT id, occurred_at, event_type, actor_kind, actor_id, actor_label,
		       title, COALESCE(detail,''), payload
		  FROM audit.timeline_events
		 WHERE tenant_id = $1 AND incident_id = $2
		 ORDER BY occurred_at, id
		 LIMIT $3`, tenant.UUID, incidentID.UUID, limit)
	if err != nil {
		return nil, fmt.Errorf("consultar timeline: %w", err)
	}
	defer rows.Close()

	var out []audit.TimelineEntry
	for rows.Next() {
		var (
			e   audit.TimelineEntry
			uid uuid.UUID
			raw []byte
		)
		if err := rows.Scan(&uid, &e.OccurredAt, &e.EventType, &e.ActorKind,
			&e.ActorID, &e.ActorLabel, &e.Title, &e.Detail, &raw); err != nil {
			return nil, fmt.Errorf("ler linha: %w", err)
		}
		e.ID = uid.String()
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &e.Payload)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
