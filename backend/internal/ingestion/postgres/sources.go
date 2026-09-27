package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/titas/soar/backend/internal/core/id"
	"github.com/titas/soar/backend/internal/ingestion"
	pg "github.com/titas/soar/backend/internal/platform/postgres"
)

type SourceStore struct{ tx *pg.TxManager }

func NewSourceStore(tx *pg.TxManager) *SourceStore { return &SourceStore{tx: tx} }

func (s *SourceStore) ListEnabled(ctx context.Context, tenant id.TenantID) ([]ingestion.SourceConfig, error) {
	rows, err := s.tx.DB(ctx).Query(ctx, `
		SELECT id, tenant_id, slug, name, kind, mode, config, default_incident_type, enabled
		  FROM incident.alert_sources
		 WHERE tenant_id = $1 AND enabled
		 ORDER BY slug`, tenant.UUID)
	if err != nil {
		return nil, fmt.Errorf("listar fontes: %w", err)
	}
	defer rows.Close()

	var out []ingestion.SourceConfig
	for rows.Next() {
		c, err := scanSource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

func (s *SourceStore) BySlug(ctx context.Context, tenant id.TenantID, slug string) (*ingestion.SourceConfig, error) {
	c, err := scanSource(s.tx.DB(ctx).QueryRow(ctx, `
		SELECT id, tenant_id, slug, name, kind, mode, config, default_incident_type, enabled
		  FROM incident.alert_sources WHERE tenant_id=$1 AND slug=$2`, tenant.UUID, slug))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("buscar fonte: %w", err)
	}
	return c, nil
}

func scanSource(row pgx.Row) (*ingestion.SourceConfig, error) {
	var (
		c        ingestion.SourceConfig
		sid, tid uuid.UUID
		config   []byte
	)
	if err := row.Scan(&sid, &tid, &c.Slug, &c.Name, &c.Kind, &c.Mode,
		&config, &c.DefaultIncidentType, &c.Enabled); err != nil {
		return nil, err
	}
	c.ID = id.SourceID{UUID: sid}
	c.TenantID = id.TenantID{UUID: tid}
	if len(config) > 0 {
		_ = json.Unmarshal(config, &c.Config)
	}
	return &c, nil
}

func (s *SourceStore) Cursor(ctx context.Context, sourceID id.SourceID) (ingestion.Cursor, error) {
	var raw []byte
	err := s.tx.DB(ctx).QueryRow(ctx,
		`SELECT cursor FROM incident.source_cursors WHERE source_id=$1`, sourceID.UUID).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return ingestion.Cursor{}, nil
	}
	if err != nil {
		return ingestion.Cursor{}, fmt.Errorf("ler cursor: %w", err)
	}
	var c ingestion.Cursor
	_ = json.Unmarshal(raw, &c)
	return c, nil
}

// AdvanceCursor is only ever called after a durable accept. That ordering is
// what makes pull ingestion at-least-once instead of best effort.
func (s *SourceStore) AdvanceCursor(ctx context.Context, sourceID id.SourceID,
	cursor ingestion.Cursor, at time.Time) error {

	raw, err := json.Marshal(cursor)
	if err != nil {
		return err
	}
	_, err = s.tx.DB(ctx).Exec(ctx, `
		INSERT INTO incident.source_cursors (source_id, tenant_id, cursor, advanced_at)
		SELECT $1, s.tenant_id, $2::jsonb, $3 FROM incident.alert_sources s WHERE s.id = $1
		ON CONFLICT (source_id) DO UPDATE
		   SET cursor = EXCLUDED.cursor, advanced_at = EXCLUDED.advanced_at,
		       version = incident.source_cursors.version + 1`,
		sourceID.UUID, string(raw), at)
	if err != nil {
		return fmt.Errorf("avançar cursor: %w", err)
	}
	return nil
}

func (s *SourceStore) Upsert(ctx context.Context, c *ingestion.SourceConfig) error {
	raw, err := json.Marshal(c.Config)
	if err != nil {
		return err
	}
	_, err = s.tx.DB(ctx).Exec(ctx, `
		INSERT INTO incident.alert_sources
		  (tenant_id, slug, name, kind, mode, config, default_incident_type, enabled)
		VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8)
		ON CONFLICT (tenant_id, slug) DO UPDATE
		   SET name=EXCLUDED.name, kind=EXCLUDED.kind, mode=EXCLUDED.mode,
		       config=EXCLUDED.config, default_incident_type=EXCLUDED.default_incident_type,
		       enabled=EXCLUDED.enabled`,
		c.TenantID.UUID, c.Slug, c.Name, c.Kind, c.Mode, string(raw),
		c.DefaultIncidentType, c.Enabled)
	if err != nil {
		return fmt.Errorf("gravar fonte: %w", err)
	}
	return nil
}

type RunStore struct{ tx *pg.TxManager }

func NewRunStore(tx *pg.TxManager) *RunStore { return &RunStore{tx: tx} }

func (s *RunStore) Begin(ctx context.Context, tenant id.TenantID,
	source id.SourceID, before ingestion.Cursor) (string, error) {

	raw, _ := json.Marshal(before)
	var runID uuid.UUID
	err := s.tx.DB(ctx).QueryRow(ctx, `
		INSERT INTO platform.connector_runs (tenant_id, source_id, cursor_before, status)
		VALUES ($1,$2,$3::jsonb,'running') RETURNING id`,
		tenant.UUID, source.UUID, string(raw)).Scan(&runID)
	if err != nil {
		return "", fmt.Errorf("abrir execução de conector: %w", err)
	}
	return runID.String(), nil
}

func (s *RunStore) End(ctx context.Context, runID string, st ingestion.RunStats) error {
	after, _ := json.Marshal(st.After)
	_, err := s.tx.DB(ctx).Exec(ctx, `
		UPDATE platform.connector_runs
		   SET finished_at=now(), fetched=$2, accepted=$3, duplicates=$4, quarantined=$5,
		       incidents_created=$6, incidents_updated=$7, cursor_after=$8::jsonb,
		       status=$9, error=NULLIF($10,''), duration_ms=$11
		 WHERE id=$1`,
		runID, st.Fetched, st.Accepted, st.Duplicates, st.Quarantined,
		st.IncidentsCreated, st.IncidentsUpdated, string(after),
		st.Status, st.Err, int(st.Duration.Milliseconds()))
	if err != nil {
		return fmt.Errorf("fechar execução de conector: %w", err)
	}
	return nil
}
