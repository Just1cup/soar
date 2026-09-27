// Package postgres implements the response repositories.
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
	pg "github.com/titas/soar/backend/internal/platform/postgres"
	"github.com/titas/soar/backend/internal/response"
)

type AssetStore struct{ tx *pg.TxManager }

func NewAssetStore(tx *pg.TxManager) *AssetStore { return &AssetStore{tx: tx} }

func (s *AssetStore) ByIntegration(ctx context.Context, tenant id.TenantID, slug string) (*response.AssetRef, error) {
	var (
		ref     response.AssetRef
		assetID uuid.UUID
		config  []byte
		until   *time.Time
	)
	err := s.tx.DB(ctx).QueryRow(ctx, `
		SELECT a.id, i.slug, a.name, COALESCE(a.endpoint,''), a.credential_ref,
		       a.config, a.enabled AND i.enabled, a.circuit_state, a.circuit_until
		  FROM response.integration_assets a
		  JOIN response.integrations i ON i.id = a.integration_id
		 WHERE a.tenant_id = $1 AND i.slug = $2
		 ORDER BY a.name
		 LIMIT 1`, tenant.UUID, slug,
	).Scan(&assetID, &ref.Integration, &ref.Name, &ref.Endpoint, &ref.CredRef,
		&config, &ref.Enabled, &ref.Circuit, &until)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("buscar asset de %s: %w", slug, err)
	}
	ref.ID = id.AssetID{UUID: assetID}
	if len(config) > 0 {
		_ = json.Unmarshal(config, &ref.Config)
	}
	// Um circuito aberto cuja janela já passou volta sozinho a half_open: sem
	// isso, uma indisponibilidade de dois minutos desligaria a integração até
	// alguém reparar.
	if ref.Circuit == "open" && until != nil && time.Now().After(*until) {
		ref.Circuit = "half_open"
	}
	return &ref, nil
}

func (s *AssetStore) SetCircuit(ctx context.Context, assetID id.AssetID, state string, until *time.Time) error {
	_, err := s.tx.DB(ctx).Exec(ctx,
		`UPDATE response.integration_assets SET circuit_state=$2, circuit_until=$3 WHERE id=$1`,
		assetID.UUID, state, until)
	return err
}

func (s *AssetStore) SetHealth(ctx context.Context, assetID id.AssetID, status, detail string, at time.Time) error {
	_, err := s.tx.DB(ctx).Exec(ctx, `
		UPDATE response.integration_assets
		   SET health_status=$2, health_detail=NULLIF($3,''), health_checked_at=$4
		 WHERE id=$1`, assetID.UUID, status, detail, at)
	return err
}

// UpsertIntegration installs a content pack's manifest. Idempotent by slug, so
// restarting the process cannot duplicate the catalogue, and a changed pack
// updates in place with a new hash.
func (s *AssetStore) UpsertIntegration(ctx context.Context, tenant id.TenantID,
	slug, name, packID string, manifest []byte, sha []byte) error {

	_, err := s.tx.DB(ctx).Exec(ctx, `
		INSERT INTO response.integrations (tenant_id, slug, name, pack_id, manifest, manifest_sha)
		-- $5 como TEXTO com cast: em modo prepareless o pgx codifica []byte
		-- como literal bytea hexadecimal, que não é JSON válido.
		VALUES ($1,$2,$3,$4,$5::jsonb,$6)
		ON CONFLICT (tenant_id, slug) DO UPDATE
		   SET name = EXCLUDED.name, pack_id = EXCLUDED.pack_id,
		       manifest = EXCLUDED.manifest, manifest_sha = EXCLUDED.manifest_sha,
		       updated_at = now()`,
		tenant.UUID, slug, name, packID, string(manifest), sha)
	if err != nil {
		return fmt.Errorf("instalar integração %s: %w", slug, err)
	}
	return nil
}

// ConfigureAsset is an operator action: it names the endpoint and the
// credential POINTER. The secret itself never passes through here.
func (s *AssetStore) ConfigureAsset(ctx context.Context, tenant id.TenantID,
	slug, name, endpoint, credRef string, config map[string]any) error {

	raw, err := json.Marshal(config)
	if err != nil {
		return err
	}
	_, err = s.tx.DB(ctx).Exec(ctx, `
		INSERT INTO response.integration_assets
		  (tenant_id, integration_id, name, endpoint, credential_ref, config)
		-- Casts explícitos: numa lista de SELECT o Postgres não infere o tipo
		-- do parâmetro pela coluna de destino, e o JSONB chegaria como texto.
		SELECT $1::uuid, i.id, $3::text, NULLIF($4,'')::text, $5::text, $6::jsonb
		  FROM response.integrations i
		 WHERE i.tenant_id = $1 AND i.slug = $2
		ON CONFLICT (tenant_id, integration_id, name) DO UPDATE
		   SET endpoint = EXCLUDED.endpoint,
		       credential_ref = EXCLUDED.credential_ref,
		       config = EXCLUDED.config,
		       version = response.integration_assets.version + 1`,
		tenant.UUID, slug, name, endpoint, credRef, string(raw))
	if err != nil {
		return fmt.Errorf("configurar asset %s/%s: %w", slug, name, err)
	}
	return nil
}
