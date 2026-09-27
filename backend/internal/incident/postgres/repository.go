// Package postgres implements incident.Repository.
//
// This is the only package in the incident domain that knows SQL exists. The
// dependency points inwards: the interface lives with its consumer, the
// implementation lives here.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/titas/soar/backend/internal/core/errs"
	"github.com/titas/soar/backend/internal/core/id"
	"github.com/titas/soar/backend/internal/core/pagination"
	"github.com/titas/soar/backend/internal/incident"
	pg "github.com/titas/soar/backend/internal/platform/postgres"
)

// Repository reads and writes through the TxManager rather than the pool
// directly: that is what lets FindForUpdate take a row lock and Save write in
// the same transaction as the audit entry and the outbox row.
type Repository struct{ tx *pg.TxManager }

func New(tx *pg.TxManager) *Repository { return &Repository{tx: tx} }

const columns = `
    i.id, i.tenant_id, i.key, t.slug AS type_slug,
    i.title, COALESCE(i.description,''), i.status, i.severity, i.priority,
    i.owner_id, COALESCE(u.display_name,''), i.assigned_at, i.source_id,
    COALESCE(i.source_rule,''), i.fingerprint, i.dedupe_until,
    i.alert_count, i.first_seen, i.last_seen,
    COALESCE(i.resolution,''), COALESCE(i.closed_reason,''), i.closed_at, i.closed_by, i.first_ack_at,
    i.attack_tactics, i.attack_techniques, i.tags,
    i.open_mandatory_tasks, i.version, i.created_at, i.updated_at`

func scan(row pgx.Row) (*incident.Incident, error) {
	var (
		inc      incident.Incident
		tenant   uuid.UUID
		incID    uuid.UUID
		owner    *uuid.UUID
		closedBy *uuid.UUID
		sourceID *uuid.UUID
		res      string
	)
	err := row.Scan(
		&incID, &tenant, &inc.Key, &inc.TypeSlug,
		&inc.Title, &inc.Description, &inc.Status, &inc.Severity, &inc.Priority,
		&owner, &inc.OwnerName, &inc.AssignedAt, &sourceID,
		&inc.SourceRule, &inc.Fingerprint, &inc.DedupeUntil,
		&inc.AlertCount, &inc.FirstSeen, &inc.LastSeen,
		&res, &inc.ClosedReason, &inc.ClosedAt, &closedBy, &inc.FirstAckAt,
		&inc.AttackTactics, &inc.AttackTechniques, &inc.Tags,
		&inc.OpenMandatoryTasks, &inc.Version, &inc.CreatedAt, &inc.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	inc.ID = id.IncidentID{UUID: incID}
	inc.TenantID = id.TenantID{UUID: tenant}
	inc.Resolution = incident.Resolution(res)
	if owner != nil {
		inc.OwnerID = &id.UserID{UUID: *owner}
	}
	if closedBy != nil {
		inc.ClosedBy = &id.UserID{UUID: *closedBy}
	}
	if sourceID != nil {
		inc.SourceID = &id.SourceID{UUID: *sourceID}
	}
	return &inc, nil
}

// List does keyset pagination on (last_seen DESC, id DESC), which is the order
// the partial index incidents_queue is built for. OFFSET is never used: it
// skips rows when the data moves under the reader, and on this queue the data
// always moves.
func (r *Repository) List(ctx context.Context, tenant id.TenantID, f incident.Filter) (incident.Page, error) {
	var (
		where = []string{"i.tenant_id = $1"}
		args  = []any{tenant.UUID}
	)
	add := func(clause string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if f.Status != nil {
		add("i.status = $%d", string(*f.Status))
	} else if f.OpenOnly {
		where = append(where, "i.status <> 'closed'")
	}
	if f.Severity != nil {
		add("i.severity = $%d", string(*f.Severity))
	}
	if f.OwnerID != nil {
		add("i.owner_id = $%d", f.OwnerID.UUID)
	}
	if f.After != nil {
		args = append(args, f.After.LastSeen, f.After.ID)
		where = append(where, fmt.Sprintf("(i.last_seen, i.id) < ($%d, $%d)", len(args)-1, len(args)))
	}

	// Fetch one extra row: its presence is how we know there is a next page
	// without a second COUNT query over the whole table.
	args = append(args, f.Limit+1)
	query := fmt.Sprintf(`
		SELECT %s
		  FROM incident.incidents i
		  JOIN incident.incident_types t ON t.id = i.type_id
		  LEFT JOIN iam.users u ON u.id = i.owner_id AND u.tenant_id = i.tenant_id
		 WHERE %s
		 ORDER BY i.last_seen DESC, i.id DESC
		 LIMIT $%d`, columns, strings.Join(where, " AND "), len(args))

	rows, err := r.tx.DB(ctx).Query(ctx, query, args...)
	if err != nil {
		return incident.Page{}, fmt.Errorf("consultar incidentes: %w", err)
	}
	defer rows.Close()

	var page incident.Page
	for rows.Next() {
		inc, err := scan(rows)
		if err != nil {
			return incident.Page{}, fmt.Errorf("ler linha: %w", err)
		}
		page.Items = append(page.Items, inc)
	}
	if err := rows.Err(); err != nil {
		return incident.Page{}, fmt.Errorf("iterar: %w", err)
	}
	if len(page.Items) > f.Limit {
		last := page.Items[f.Limit-1]
		page.Items = page.Items[:f.Limit]
		page.NextCursor = &pagination.Key{LastSeen: last.LastSeen, ID: last.ID.UUID}
	}
	return page, nil
}

func (r *Repository) FindByID(ctx context.Context, tenant id.TenantID, incidentID id.IncidentID) (*incident.Incident, error) {
	return r.one(ctx, tenant, incidentID, false)
}

// FindForUpdate takes a row lock, so that two analysts closing the same
// incident serialise instead of racing.
func (r *Repository) FindForUpdate(ctx context.Context, tenant id.TenantID, incidentID id.IncidentID) (*incident.Incident, error) {
	return r.one(ctx, tenant, incidentID, true)
}

func (r *Repository) one(ctx context.Context, tenant id.TenantID, incidentID id.IncidentID, lock bool) (*incident.Incident, error) {
	suffix := ""
	if lock {
		suffix = " FOR UPDATE OF i"
	}
	query := fmt.Sprintf(`
		SELECT %s
		  FROM incident.incidents i
		  JOIN incident.incident_types t ON t.id = i.type_id
		  LEFT JOIN iam.users u ON u.id = i.owner_id AND u.tenant_id = i.tenant_id
		 WHERE i.tenant_id = $1 AND i.id = $2%s`, columns, suffix)

	inc, err := scan(r.tx.DB(ctx).QueryRow(ctx, query, tenant.UUID, incidentID.UUID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("buscar incidente: %w", err)
	}
	return inc, nil
}

// Save applies optimistic locking: the UPDATE only matches while the row is
// still at the version the caller read. Zero rows affected means somebody else
// won, and the caller gets 409 instead of silently overwriting their work.
func (r *Repository) Save(ctx context.Context, inc *incident.Incident) error {
	var owner, closedBy *uuid.UUID
	if inc.OwnerID != nil {
		owner = &inc.OwnerID.UUID
	}
	if inc.ClosedBy != nil {
		closedBy = &inc.ClosedBy.UUID
	}
	var resolution *string
	if inc.Resolution != "" {
		s := string(inc.Resolution)
		resolution = &s
	}
	var closedReason *string
	if inc.ClosedReason != "" {
		s := inc.ClosedReason
		closedReason = &s
	}

	tag, err := r.tx.DB(ctx).Exec(ctx, `
		UPDATE incident.incidents SET
		    title = $3, description = NULLIF($4,''), status = $5, severity = $6, priority = $7,
		    owner_id = $8, assigned_at = $9,
		    alert_count = $10, first_seen = $11, last_seen = $12,
		    resolution = $13, closed_reason = $14, closed_at = $15, closed_by = $16,
		    first_ack_at = $17,
		    attack_tactics = $18, attack_techniques = $19, tags = $20,
		    open_mandatory_tasks = $21,
		    version = version + 1, updated_at = now()
		 WHERE tenant_id = $1 AND id = $2 AND version = $22`,
		inc.TenantID.UUID, inc.ID.UUID,
		inc.Title, inc.Description, string(inc.Status), string(inc.Severity), inc.Priority,
		owner, inc.AssignedAt,
		inc.AlertCount, inc.FirstSeen, inc.LastSeen,
		resolution, closedReason, inc.ClosedAt, closedBy,
		inc.FirstAckAt,
		emptyIfNil(inc.AttackTactics), emptyIfNil(inc.AttackTechniques), emptyIfNil(inc.Tags),
		inc.OpenMandatoryTasks,
		inc.Version,
	)
	if err != nil {
		return fmt.Errorf("gravar incidente: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errs.Coded(errs.ErrVersionConflict, "VERSION_CONFLICT",
			"o incidente mudou desde a leitura; recarregue e tente de novo")
	}
	inc.Version++
	return nil
}

// FindOpenByFingerprint is the dedupe lookup. FOR UPDATE because the caller
// is about to increment the counter, and two alerts of the same burst
// arriving in parallel must serialise rather than race.
func (r *Repository) FindOpenByFingerprint(ctx context.Context, tenant id.TenantID,
	fingerprint []byte) (*incident.Incident, error) {

	query := fmt.Sprintf(`
		SELECT %s
		  FROM incident.incidents i
		  JOIN incident.incident_types t ON t.id = i.type_id
		  LEFT JOIN iam.users u ON u.id = i.owner_id AND u.tenant_id = i.tenant_id
		 WHERE i.tenant_id = $1 AND i.fingerprint = $2 AND i.status <> 'closed'
		 FOR UPDATE OF i`, columns)
	inc, err := scan(r.tx.DB(ctx).QueryRow(ctx, query, tenant.UUID, fingerprint))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("buscar incidente por fingerprint: %w", err)
	}
	return inc, nil
}

func (r *Repository) Create(ctx context.Context, inc *incident.Incident) error {
	var resolution, closedReason *string
	if inc.Resolution != "" {
		s := string(inc.Resolution)
		resolution = &s
	}
	if inc.ClosedReason != "" {
		closedReason = &inc.ClosedReason
	}
	err := r.tx.DB(ctx).QueryRow(ctx, `
		INSERT INTO incident.incidents
		  (tenant_id, key, type_id, title, description, status, severity, priority,
		   source_id, source_rule, fingerprint, dedupe_until,
		   alert_count, first_seen, last_seen, resolution, closed_reason,
		   attack_tactics, attack_techniques, tags)
		SELECT $1, $2, t.id, $3, NULLIF($4,''), $5, $6, $7,
		       $8, NULLIF($9,''), $10, $11, $12, $13, $14, $15, $16, $17, $18, $19
		  FROM incident.incident_types t
		 WHERE t.tenant_id = $1 AND t.slug = $20
		RETURNING id, key, version, created_at, updated_at`,
		inc.TenantID.UUID, inc.Key, inc.Title, inc.Description, string(inc.Status),
		string(inc.Severity), inc.Priority, nullUUID(inc.SourceID), inc.SourceRule,
		inc.Fingerprint, inc.DedupeUntil, inc.AlertCount, inc.FirstSeen, inc.LastSeen,
		resolution, closedReason,
		emptyIfNil(inc.AttackTactics), emptyIfNil(inc.AttackTechniques), emptyIfNil(inc.Tags),
		inc.TypeSlug,
	).Scan(&inc.ID.UUID, &inc.Key, &inc.Version, &inc.CreatedAt, &inc.UpdatedAt)
	if err != nil {
		return fmt.Errorf("criar incidente: %w", err)
	}
	return nil
}

// NextKey builds the human-readable key. A sequence per tenant and year keeps
// INC-2026-000123 readable and sortable without leaking how many incidents
// other tenants have.
func (r *Repository) NextKey(ctx context.Context, tenant id.TenantID, year int) (string, error) {
	var n int64
	err := r.tx.DB(ctx).QueryRow(ctx, `
		SELECT count(*) + 1 FROM incident.incidents
		 WHERE tenant_id = $1 AND key LIKE $2`, tenant.UUID, fmt.Sprintf("INC-%d-%%", year)).Scan(&n)
	if err != nil {
		return "", fmt.Errorf("gerar chave: %w", err)
	}
	return fmt.Sprintf("INC-%d-%06d", year, n), nil
}

func nullUUID(s *id.SourceID) *uuid.UUID {
	if s == nil {
		return nil
	}
	return &s.UUID
}

// emptyIfNil keeps NOT NULL array columns honest: a nil Go slice encodes as
// SQL NULL, and "no tags" is an empty list, not the absence of the concept.
func emptyIfNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
