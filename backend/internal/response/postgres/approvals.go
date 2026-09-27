package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/titas/soar/backend/internal/core/errs"
	"github.com/titas/soar/backend/internal/core/id"
	"github.com/titas/soar/backend/internal/integration"
	pg "github.com/titas/soar/backend/internal/platform/postgres"
	"github.com/titas/soar/backend/internal/response"
)

type ApprovalStore struct{ tx *pg.TxManager }

func NewApprovalStore(tx *pg.TxManager) *ApprovalStore { return &ApprovalStore{tx: tx} }

const approvalColumns = `
	a.id, a.tenant_id, a.incident_id, a.asset_id, a.action, a.permission,
	a.plan, a.plan_fingerprint, a.affected_count, a.status,
	a.requested_by, a.requested_at, a.expires_at,
	a.decided_by, a.decided_at, COALESCE(a.decision_note,''), a.version`

func scanApproval(row pgx.Row) (*response.Approval, error) {
	var (
		a          response.Approval
		aid, tid   uuid.UUID
		incidentID *uuid.UUID
		assetID    uuid.UUID
		decidedBy  *uuid.UUID
		planRaw    []byte
	)
	err := row.Scan(&aid, &tid, &incidentID, &assetID, &a.Action, &a.Permission,
		&planRaw, &a.Fingerprint, &a.Affected, &a.Status,
		&a.RequestedBy, &a.RequestedAt, &a.ExpiresAt,
		&decidedBy, &a.DecidedAt, &a.Note, &a.Version)
	if err != nil {
		return nil, err
	}
	a.ID = id.ApprovalID{UUID: aid}
	a.TenantID = id.TenantID{UUID: tid}
	a.AssetID = id.AssetID{UUID: assetID}
	if incidentID != nil {
		a.IncidentID = &id.IncidentID{UUID: *incidentID}
	}
	if decidedBy != nil {
		a.DecidedBy = &id.UserID{UUID: *decidedBy}
	}
	var plan integration.Plan
	if err := json.Unmarshal(planRaw, &plan); err == nil {
		a.Plan = plan
	}
	return &a, nil
}

func (s *ApprovalStore) Create(ctx context.Context, a *response.Approval) error {
	planRaw, err := json.Marshal(a.Plan)
	if err != nil {
		return fmt.Errorf("serializar plano: %w", err)
	}
	var incidentID *uuid.UUID
	if a.IncidentID != nil {
		incidentID = &a.IncidentID.UUID
	}
	_, err = s.tx.DB(ctx).Exec(ctx, `
		INSERT INTO response.approvals
		  (id, tenant_id, incident_id, asset_id, action, permission,
		   plan, plan_fingerprint, affected_count, status, requested_by, requested_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,'requested',$10,$11,$12)`,
		a.ID.UUID, a.TenantID.UUID, incidentID, a.AssetID.UUID, a.Action, a.Permission,
		string(planRaw), a.Fingerprint, a.Affected, a.RequestedBy, a.RequestedAt, a.ExpiresAt)
	if err != nil {
		return fmt.Errorf("criar aprovação: %w", err)
	}
	return nil
}

func (s *ApprovalStore) Get(ctx context.Context, tenant id.TenantID, approvalID id.ApprovalID) (*response.Approval, error) {
	a, err := scanApproval(s.tx.DB(ctx).QueryRow(ctx,
		`SELECT `+approvalColumns+` FROM response.approvals a WHERE a.tenant_id=$1 AND a.id=$2`,
		tenant.UUID, approvalID.UUID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("buscar aprovação: %w", err)
	}
	return a, nil
}

func (s *ApprovalStore) ListPending(ctx context.Context, tenant id.TenantID, limit int) ([]*response.Approval, error) {
	// Só o que ainda pode ser decidido: uma aprovação vencida na fila é ruído
	// que o analista tem de filtrar mentalmente.
	rows, err := s.tx.DB(ctx).Query(ctx,
		`SELECT `+approvalColumns+`
		   FROM response.approvals a
		  WHERE a.tenant_id=$1 AND a.status='requested' AND a.expires_at > now()
		  ORDER BY a.requested_at
		  LIMIT $2`, tenant.UUID, limit)
	if err != nil {
		return nil, fmt.Errorf("listar aprovações: %w", err)
	}
	defer rows.Close()

	var out []*response.Approval
	for rows.Next() {
		a, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Decide applies the decision under optimistic locking, so two analysts
// deciding the same approval do not both believe they won.
func (s *ApprovalStore) Decide(ctx context.Context, tenant id.TenantID, approvalID id.ApprovalID,
	expectedVersion int, status string, by id.UserID, note string, at time.Time) (*response.Approval, error) {

	tag, err := s.tx.DB(ctx).Exec(ctx, `
		UPDATE response.approvals
		   SET status=$4, decided_by=$5, decided_at=$6, decision_note=NULLIF($7,''),
		       version = version + 1
		 WHERE tenant_id=$1 AND id=$2 AND version=$3
		   AND status='requested' AND expires_at > $6`,
		tenant.UUID, approvalID.UUID, expectedVersion, status, by.UUID, at, note)
	if err != nil {
		return nil, fmt.Errorf("decidir aprovação: %w", err)
	}
	if tag.RowsAffected() == 0 {
		current, err := s.Get(ctx, tenant, approvalID)
		if err != nil {
			return nil, err
		}
		switch {
		case current == nil:
			return nil, errs.Coded(errs.ErrNotFound, "APPROVAL_NOT_FOUND", "aprovação não encontrada")
		case current.Status != "requested":
			return nil, errs.Coded(errs.ErrConflict, "APPROVAL_ALREADY_DECIDED",
				"esta aprovação já está em %q", current.Status)
		case !at.Before(current.ExpiresAt):
			return nil, errs.Coded(errs.ErrConflict, "APPROVAL_EXPIRED",
				"a aprovação expirou; planeje de novo")
		default:
			return nil, errs.Coded(errs.ErrVersionConflict, "VERSION_CONFLICT",
				"a aprovação mudou desde a leitura")
		}
	}
	return s.Get(ctx, tenant, approvalID)
}

func (s *ApprovalStore) Supersede(ctx context.Context, tenant id.TenantID, approvalID id.ApprovalID) error {
	_, err := s.tx.DB(ctx).Exec(ctx,
		`UPDATE response.approvals SET status='superseded', version=version+1
		  WHERE tenant_id=$1 AND id=$2 AND status IN ('requested','approved')`,
		tenant.UUID, approvalID.UUID)
	return err
}

func (s *ApprovalStore) Consume(ctx context.Context, tenant id.TenantID, approvalID id.ApprovalID) error {
	// A condição status='approved' é o que impede a mesma aprovação servir
	// duas execuções concorrentes: a segunda não encontra linha.
	tag, err := s.tx.DB(ctx).Exec(ctx,
		`UPDATE response.approvals SET status='consumed', version=version+1
		  WHERE tenant_id=$1 AND id=$2 AND status='approved'`,
		tenant.UUID, approvalID.UUID)
	if err != nil {
		return fmt.Errorf("consumir aprovação: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errs.Coded(errs.ErrConflict, "APPROVAL_ALREADY_USED",
			"esta aprovação já foi usada")
	}
	return nil
}
