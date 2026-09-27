// Package postgres implements auth.Repository.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/titas/soar/backend/internal/auth"
	"github.com/titas/soar/backend/internal/core/id"
	pg "github.com/titas/soar/backend/internal/platform/postgres"
)

type Repository struct{ tx *pg.TxManager }

func New(tx *pg.TxManager) *Repository { return &Repository{tx: tx} }

func (r *Repository) FindUserByEmail(ctx context.Context, tenant id.TenantID, email string) (*auth.User, error) {
	var (
		u      auth.User
		uid    uuid.UUID
		tid    uuid.UUID
		hash   *string
		status string
	)
	err := r.tx.DB(ctx).QueryRow(ctx, `
		SELECT id, tenant_id, email, display_name, password_hash, status
		  FROM iam.users WHERE tenant_id = $1 AND lower(email) = lower($2)`,
		tenant.UUID, strings.TrimSpace(email),
	).Scan(&uid, &tid, &u.Email, &u.DisplayName, &hash, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("buscar usuário: %w", err)
	}
	u.ID = id.UserID{UUID: uid}
	u.TenantID = id.TenantID{UUID: tid}
	u.Disabled = status != "active"
	if hash != nil {
		u.PasswordHash = *hash
	}
	return &u, nil
}

func (r *Repository) CreateSession(ctx context.Context, s auth.Session) error {
	_, err := r.tx.DB(ctx).Exec(ctx, `
		INSERT INTO iam.sessions (tenant_id, user_id, token_hash, csrf_hash, expires_at, source_ip, user_agent)
		VALUES ($1,$2,$3,$4,$5,NULLIF($6,'')::inet,NULLIF($7,''))`,
		s.TenantID.UUID, s.UserID.UUID, s.TokenHash, s.CSRFHash, s.ExpiresAt, s.SourceIP, s.UserAgent)
	if err != nil {
		return fmt.Errorf("criar sessão: %w", err)
	}
	return nil
}

func (r *Repository) FindSession(ctx context.Context, tokenHash []byte) (*auth.Session, *auth.User, error) {
	var (
		s      auth.Session
		u      auth.User
		tid    uuid.UUID
		uid    uuid.UUID
		status string
	)
	err := r.tx.DB(ctx).QueryRow(ctx, `
		SELECT s.tenant_id, s.user_id, s.csrf_hash, s.expires_at,
		       u.email, u.display_name, u.status
		  FROM iam.sessions s
		  JOIN iam.users u ON u.id = s.user_id
		 WHERE s.token_hash = $1 AND s.revoked_at IS NULL`,
		tokenHash,
	).Scan(&tid, &uid, &s.CSRFHash, &s.ExpiresAt, &u.Email, &u.DisplayName, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("buscar sessão: %w", err)
	}
	s.TenantID, s.UserID = id.TenantID{UUID: tid}, id.UserID{UUID: uid}
	u.ID, u.TenantID = s.UserID, s.TenantID
	u.Disabled = status != "active"
	if u.Disabled {
		// Desabilitar um usuário derruba as sessões dele imediatamente, em vez
		// de esperar a expiração.
		return nil, nil, nil
	}
	return &s, &u, nil
}

func (r *Repository) RevokeSession(ctx context.Context, tokenHash []byte) error {
	_, err := r.tx.DB(ctx).Exec(ctx,
		`UPDATE iam.sessions SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL`,
		tokenHash)
	return err
}

func (r *Repository) PermissionsOf(ctx context.Context, userID id.UserID) (map[string]bool, error) {
	rows, err := r.tx.DB(ctx).Query(ctx, `
		SELECT DISTINCT rp.permission
		  FROM iam.user_roles ur
		  JOIN iam.role_permissions rp ON rp.role_id = ur.role_id
		 WHERE ur.user_id = $1`, userID.UUID)
	if err != nil {
		return nil, fmt.Errorf("carregar permissões: %w", err)
	}
	defer rows.Close()
	perms := map[string]bool{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		perms[p] = true
	}
	return perms, rows.Err()
}

func (r *Repository) RolePermissions(ctx context.Context, tenant id.TenantID, role string) (map[string]bool, error) {
	rows, err := r.tx.DB(ctx).Query(ctx, `
		SELECT rp.permission FROM iam.roles r
		  JOIN iam.role_permissions rp ON rp.role_id = r.id
		 WHERE r.tenant_id = $1 AND r.name = $2`, tenant.UUID, role)
	if err != nil {
		return nil, fmt.Errorf("carregar permissões do papel: %w", err)
	}
	defer rows.Close()
	perms := map[string]bool{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		perms[p] = true
	}
	return perms, rows.Err()
}
