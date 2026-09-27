package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/titas/soar/backend/internal/core/id"
	"github.com/titas/soar/backend/internal/integration"
	pg "github.com/titas/soar/backend/internal/platform/postgres"
	"github.com/titas/soar/backend/internal/response"
)

type RunStore struct{ tx *pg.TxManager }

func NewRunStore(tx *pg.TxManager) *RunStore { return &RunStore{tx: tx} }

const runColumns = `
	r.id, r.tenant_id, r.incident_id, r.asset_id, r.integration_slug, r.action,
	r.approval_id, r.idempotency_key, r.plan_fingerprint, r.autonomy, r.status,
	r.input, r.output, COALESCE(r.error,''), r.affected_count,
	r.actor_kind, r.actor_id, r.requested_at, r.started_at, r.finished_at, r.latency_ms`

func scanRun(row pgx.Row) (*response.Run, error) {
	var (
		r             response.Run
		rid, tid      uuid.UUID
		incidentID    *uuid.UUID
		assetID       uuid.UUID
		approvalID    *uuid.UUID
		input, output []byte
		autonomy      string
	)
	err := row.Scan(&rid, &tid, &incidentID, &assetID, &r.Integration, &r.Action,
		&approvalID, &r.IdempotencyKey, &r.Fingerprint, &autonomy, &r.Status,
		&input, &output, &r.Error, &r.Affected,
		&r.ActorKind, &r.ActorID, &r.RequestedAt, &r.StartedAt, &r.FinishedAt, &r.LatencyMS)
	if err != nil {
		return nil, err
	}
	r.ID = id.ActionRunID{UUID: rid}
	r.TenantID = id.TenantID{UUID: tid}
	r.AssetID = id.AssetID{UUID: assetID}
	r.Autonomy = integration.Autonomy(autonomy)
	if incidentID != nil {
		r.IncidentID = &id.IncidentID{UUID: *incidentID}
	}
	if approvalID != nil {
		r.ApprovalID = &id.ApprovalID{UUID: *approvalID}
	}
	_ = json.Unmarshal(input, &r.Input)
	if len(output) > 0 {
		_ = json.Unmarshal(output, &r.Output)
	}
	return &r, nil
}

func (s *RunStore) Start(ctx context.Context, r *response.Run) error {
	input, err := json.Marshal(r.Input)
	if err != nil {
		return fmt.Errorf("serializar entrada: %w", err)
	}
	var incidentID, approvalID *uuid.UUID
	if r.IncidentID != nil {
		incidentID = &r.IncidentID.UUID
	}
	if r.ApprovalID != nil {
		approvalID = &r.ApprovalID.UUID
	}
	_, err = s.tx.DB(ctx).Exec(ctx, `
		INSERT INTO response.action_runs
		  (id, tenant_id, incident_id, asset_id, integration_slug, action, approval_id,
		   idempotency_key, plan_fingerprint, autonomy, status, input,
		   actor_kind, actor_id, requested_at, started_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'running',$11::jsonb,$12,$13,$14,$15)`,
		r.ID.UUID, r.TenantID.UUID, incidentID, r.AssetID.UUID, r.Integration, r.Action,
		approvalID, r.IdempotencyKey, r.Fingerprint, string(r.Autonomy), string(input),
		r.ActorKind, r.ActorID, r.RequestedAt, r.StartedAt)
	if err != nil {
		return fmt.Errorf("registrar execução: %w", err)
	}
	return nil
}

func (s *RunStore) Finish(ctx context.Context, r *response.Run) error {
	var output []byte
	if r.Output != nil {
		var err error
		if output, err = json.Marshal(r.Output); err != nil {
			return fmt.Errorf("serializar saída: %w", err)
		}
	}
	_, err := s.tx.DB(ctx).Exec(ctx, `
		UPDATE response.action_runs
		   SET status=$2, output=$3::jsonb, error=NULLIF($4,''), affected_count=$5,
		       finished_at=$6, latency_ms=$7
		 WHERE id=$1`,
		r.ID.UUID, r.Status, nullableJSON(output), r.Error, r.Affected, r.FinishedAt, r.LatencyMS)
	if err != nil {
		return fmt.Errorf("concluir execução: %w", err)
	}
	return nil
}

// ByIdempotencyKey só devolve execuções TERMINADAS. Uma ainda `running`
// significa que outra requisição está no meio da chamada externa; devolvê-la
// como resultado seria mentir sobre algo que ainda não aconteceu.
func (s *RunStore) ByIdempotencyKey(ctx context.Context, tenant id.TenantID, key string) (*response.Run, error) {
	r, err := scanRun(s.tx.DB(ctx).QueryRow(ctx,
		`SELECT `+runColumns+`
		   FROM response.action_runs r
		  WHERE r.tenant_id=$1 AND r.idempotency_key=$2
		    AND r.status IN ('succeeded','failed','skipped')`,
		tenant.UUID, key))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("buscar por idempotency key: %w", err)
	}
	return r, nil
}

func (s *RunStore) ListByIncident(ctx context.Context, tenant id.TenantID,
	incidentID id.IncidentID, limit int) ([]*response.Run, error) {

	rows, err := s.tx.DB(ctx).Query(ctx,
		`SELECT `+runColumns+`
		   FROM response.action_runs r
		  WHERE r.tenant_id=$1 AND r.incident_id=$2
		  ORDER BY r.requested_at DESC
		  LIMIT $3`, tenant.UUID, incidentID.UUID, limit)
	if err != nil {
		return nil, fmt.Errorf("listar execuções: %w", err)
	}
	defer rows.Close()

	var out []*response.Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// nullableJSON preserva o NULL: uma execução sem saída deve gravar NULL, e
// não a string "null", que o JSONB aceitaria e confundiria depois.
func nullableJSON(b []byte) *string {
	if len(b) == 0 {
		return nil
	}
	s := string(b)
	return &s
}
