// Package postgres persists assessments and feeds the case context.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/titas/soar/backend/internal/assessment"
	"github.com/titas/soar/backend/internal/core/errs"
	"github.com/titas/soar/backend/internal/core/id"
	pg "github.com/titas/soar/backend/internal/platform/postgres"
)

type Store struct{ tx *pg.TxManager }

func New(tx *pg.TxManager) *Store { return &Store{tx: tx} }

const columns = `
	a.id, a.tenant_id, a.incident_id, a.supersedes, a.author_kind,
	COALESCE(a.model,''), a.schema_version, a.verdict, a.confidence,
	a.source_reliability, a.info_credibility, a.title, a.summary,
	a.body, a.case_context, a.attack_tactics, a.attack_techniques,
	a.promoted_at, a.promoted_by, a.generated_at,
	COALESCE(a.latency_ms,0), COALESCE(a.prompt_tokens,0)`

func scan(row pgx.Row) (*assessment.Assessment, error) {
	var (
		a                    assessment.Assessment
		aid, tid, incidentID uuid.UUID
		supersedes, promoter *uuid.UUID
		body, caseCtx        []byte
	)
	err := row.Scan(&aid, &tid, &incidentID, &supersedes, &a.AuthorKind,
		&a.Model, &a.SchemaVersion, &a.Verdict, &a.Confidence,
		&a.SourceReliability, &a.InfoCredibility, &a.Title, &a.Summary,
		&body, &caseCtx, &a.AttackTactics, &a.AttackTechniques,
		&a.PromotedAt, &promoter, &a.GeneratedAt, &a.LatencyMS, &a.PromptTokens)
	if err != nil {
		return nil, err
	}
	a.ID = id.AssessmentID{UUID: aid}
	a.TenantID = id.TenantID{UUID: tid}
	a.IncidentID = id.IncidentID{UUID: incidentID}
	if supersedes != nil {
		a.Supersedes = &id.AssessmentID{UUID: *supersedes}
	}
	if promoter != nil {
		a.PromotedBy = &id.UserID{UUID: *promoter}
	}
	if err := json.Unmarshal(body, &a.Body); err != nil {
		return nil, fmt.Errorf("decodificar corpo da avaliação %s: %w", aid, err)
	}
	if err := json.Unmarshal(caseCtx, &a.CaseContext); err != nil {
		return nil, fmt.Errorf("decodificar contexto da avaliação %s: %w", aid, err)
	}
	return &a, nil
}

func (s *Store) Save(ctx context.Context, a *assessment.Assessment) error {
	body, err := json.Marshal(a.Body)
	if err != nil {
		return fmt.Errorf("serializar corpo: %w", err)
	}
	caseCtx, err := json.Marshal(a.CaseContext)
	if err != nil {
		return err
	}
	var supersedes *uuid.UUID
	if a.Supersedes != nil {
		supersedes = &a.Supersedes.UUID
	}
	_, err = s.tx.DB(ctx).Exec(ctx, `
		INSERT INTO assessment.assessments
		  (id, tenant_id, incident_id, supersedes, author_kind, model, schema_version,
		   verdict, confidence, source_reliability, info_credibility, title, summary,
		   body, case_context, attack_tactics, attack_techniques,
		   generated_at, latency_ms, prompt_tokens)
		VALUES ($1,$2,$3,$4,$5,NULLIF($6,''),$7,$8,$9,$10,$11,$12,$13,
		        $14::jsonb,$15::jsonb,$16,$17,$18,$19,$20)`,
		a.ID.UUID, a.TenantID.UUID, a.IncidentID.UUID, supersedes, a.AuthorKind,
		a.Model, a.SchemaVersion, string(a.Verdict), string(a.Confidence),
		a.SourceReliability, a.InfoCredibility, a.Title, a.Summary,
		string(body), string(caseCtx),
		emptyIfNil(a.AttackTactics), emptyIfNil(a.AttackTechniques),
		a.GeneratedAt, a.LatencyMS, a.PromptTokens)
	if err != nil {
		return fmt.Errorf("gravar avaliação: %w", err)
	}
	return nil
}

func (s *Store) ByIncident(ctx context.Context, tenant id.TenantID,
	incidentID id.IncidentID) ([]*assessment.Assessment, error) {

	rows, err := s.tx.DB(ctx).Query(ctx,
		`SELECT `+columns+` FROM assessment.assessments a
		  WHERE a.tenant_id=$1 AND a.incident_id=$2
		  ORDER BY a.generated_at DESC`, tenant.UUID, incidentID.UUID)
	if err != nil {
		return nil, fmt.Errorf("listar avaliações: %w", err)
	}
	defer rows.Close()

	var out []*assessment.Assessment
	for rows.Next() {
		a, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) Get(ctx context.Context, tenant id.TenantID,
	assessmentID id.AssessmentID) (*assessment.Assessment, error) {

	a, err := scan(s.tx.DB(ctx).QueryRow(ctx,
		`SELECT `+columns+` FROM assessment.assessments a WHERE a.tenant_id=$1 AND a.id=$2`,
		tenant.UUID, assessmentID.UUID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("buscar avaliação: %w", err)
	}
	return a, nil
}

// MarkPromoted records who turned the artefact into a verdict. The condition
// on promoted_at IS NULL is what makes promotion happen once.
func (s *Store) MarkPromoted(ctx context.Context, tenant id.TenantID,
	assessmentID id.AssessmentID, by id.UserID, at time.Time) error {

	tag, err := s.tx.DB(ctx).Exec(ctx, `
		UPDATE assessment.assessments SET promoted_at=$3, promoted_by=$4
		 WHERE tenant_id=$1 AND id=$2 AND promoted_at IS NULL`,
		tenant.UUID, assessmentID.UUID, at, by.UUID)
	if err != nil {
		return fmt.Errorf("promover avaliação: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errs.Coded(errs.ErrConflict, "ALREADY_PROMOTED",
			"esta avaliação já foi promovida")
	}
	return nil
}

// HasAssessment keeps the worker idempotent: delivery is at-least-once, and
// generating twice would burn thirty seconds of GPU for a duplicate.
func (s *Store) HasAssessment(ctx context.Context, tenant id.TenantID,
	incidentID id.IncidentID) (bool, error) {

	var exists bool
	err := s.tx.DB(ctx).QueryRow(ctx, `
		SELECT EXISTS(SELECT 1 FROM assessment.assessments
		               WHERE tenant_id=$1 AND incident_id=$2 AND author_kind='model')`,
		tenant.UUID, incidentID.UUID).Scan(&exists)
	return exists, err
}

func emptyIfNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
