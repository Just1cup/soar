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

type RuleStore struct{ tx *pg.TxManager }

func NewRuleStore(tx *pg.TxManager) *RuleStore { return &RuleStore{tx: tx} }

type ruleDefinition struct {
	Conditions ingestion.Conditions   `json:"conditions"`
	Actions    []ingestion.RuleAction `json:"actions"`
}

// ActivePreprocess returns enabled, unexpired rules in explicit order.
// Sequential, never parallel: one of the outcomes is "this alert disappears",
// and that must not depend on a race.
func (s *RuleStore) ActivePreprocess(ctx context.Context, tenant id.TenantID) ([]ingestion.Rule, error) {
	rows, err := s.tx.DB(ctx).Query(ctx, `
		SELECT id, slug, name, trigger, run_order, definition, expires_at, enabled
		  FROM automation.rules
		 WHERE tenant_id = $1 AND kind = 'preprocess' AND enabled
		   AND (expires_at IS NULL OR expires_at > now())
		 ORDER BY run_order, slug`, tenant.UUID)
	if err != nil {
		return nil, fmt.Errorf("carregar regras: %w", err)
	}
	defer rows.Close()

	var out []ingestion.Rule
	for rows.Next() {
		var (
			r   ingestion.Rule
			rid uuid.UUID
			raw []byte
		)
		if err := rows.Scan(&rid, &r.Slug, &r.Name, &r.Trigger, &r.Order,
			&raw, &r.ExpiresAt, &r.Enabled); err != nil {
			return nil, err
		}
		var def ruleDefinition
		if err := json.Unmarshal(raw, &def); err != nil {
			// Uma regra ilegível é ignorada com o erro registrado, nunca
			// aplicada por adivinhação: adivinhar aqui suprime alertas.
			return nil, fmt.Errorf("regra %s tem definição inválida: %w", r.Slug, err)
		}
		r.ID = id.RuleID{UUID: rid}
		r.Conditions, r.Actions = def.Conditions, def.Actions
		out = append(out, r)
	}
	return out, rows.Err()
}

// All lists rules regardless of state, for the operator's screen.
func (s *RuleStore) All(ctx context.Context, tenant id.TenantID) ([]ingestion.Rule, int, error) {
	rows, err := s.tx.DB(ctx).Query(ctx, `
		SELECT id, slug, name, trigger, run_order, definition, expires_at, enabled
		  FROM automation.rules WHERE tenant_id = $1 AND kind = 'preprocess'
		 ORDER BY run_order, slug`, tenant.UUID)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []ingestion.Rule
	for rows.Next() {
		var (
			r   ingestion.Rule
			rid uuid.UUID
			raw []byte
		)
		if err := rows.Scan(&rid, &r.Slug, &r.Name, &r.Trigger, &r.Order,
			&raw, &r.ExpiresAt, &r.Enabled); err != nil {
			return nil, 0, err
		}
		var def ruleDefinition
		_ = json.Unmarshal(raw, &def)
		r.ID = id.RuleID{UUID: rid}
		r.Conditions, r.Actions = def.Conditions, def.Actions
		out = append(out, r)
	}
	return out, len(out), rows.Err()
}

func (s *RuleStore) RecordRun(ctx context.Context, tenant id.TenantID, ruleID id.RuleID,
	incidentID *id.IncidentID, matched, dryRun bool, outcome string) error {

	var incident *uuid.UUID
	if incidentID != nil {
		incident = &incidentID.UUID
	}
	_, err := s.tx.DB(ctx).Exec(ctx, `
		INSERT INTO automation.rule_runs (tenant_id, rule_id, incident_id, matched, dry_run, outcome)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		tenant.UUID, ruleID.UUID, incident, matched, dryRun, outcome)
	return err
}

// Upsert installs a rule from a content pack. It lands DISABLED: enabling
// requires a successful dry-run, and the database enforces that.
func (s *RuleStore) Upsert(ctx context.Context, tenant id.TenantID, r ingestion.Rule, packID string) error {
	def, err := json.Marshal(ruleDefinition{Conditions: r.Conditions, Actions: r.Actions})
	if err != nil {
		return err
	}
	_, err = s.tx.DB(ctx).Exec(ctx, `
		INSERT INTO automation.rules
		  (tenant_id, slug, name, kind, trigger, run_order, definition, expires_at, pack_id)
		VALUES ($1,$2,$3,'preprocess',$4,$5,$6::jsonb,$7,$8)
		ON CONFLICT (tenant_id, slug) DO UPDATE
		   SET name=EXCLUDED.name, trigger=EXCLUDED.trigger, run_order=EXCLUDED.run_order,
		       definition=EXCLUDED.definition, expires_at=EXCLUDED.expires_at,
		       version=automation.rules.version+1, updated_at=now()`,
		tenant.UUID, r.Slug, r.Name, r.Trigger, r.Order, string(def), r.ExpiresAt, packID)
	if err != nil {
		return fmt.Errorf("instalar regra %s: %w", r.Slug, err)
	}
	return nil
}

// RecordDryRun is the gate: a rule cannot be enabled until this has run.
func (s *RuleStore) RecordDryRun(ctx context.Context, tenant id.TenantID, slug string,
	matched int, at time.Time) error {

	_, err := s.tx.DB(ctx).Exec(ctx, `
		UPDATE automation.rules SET dry_run_at=$3, dry_run_matched=$4, updated_at=now()
		 WHERE tenant_id=$1 AND slug=$2`, tenant.UUID, slug, at, matched)
	return err
}

func (s *RuleStore) SetEnabled(ctx context.Context, tenant id.TenantID, slug string, on bool) error {
	_, err := s.tx.DB(ctx).Exec(ctx,
		`UPDATE automation.rules SET enabled=$3, updated_at=now() WHERE tenant_id=$1 AND slug=$2`,
		tenant.UUID, slug, on)
	if err != nil {
		return fmt.Errorf("a regra não pôde ser ligada (dry-run pendente?): %w", err)
	}
	return nil
}
