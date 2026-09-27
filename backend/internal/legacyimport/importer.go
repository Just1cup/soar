// Package legacyimport is the one-way bridge from the JSON console to the
// transactional platform. It is deliberately a boundary adapter: legacy JSON
// types do not leak into the incident domain.
package legacyimport

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Files struct {
	Assessments string
	Cases       string
	Labels      string
}

type Report struct {
	Read     int
	Imported int
	Existing int
}

type assessment struct {
	ClusterID        string      `json:"cluster_id"`
	Title            string      `json:"title"`
	Summary          string      `json:"summary"`
	Verdict          string      `json:"verdict"`
	AttackTactics    []string    `json:"attack_tactics"`
	AttackTechniques []string    `json:"attack_techniques"`
	CaseContext      caseContext `json:"case_context"`
}

type caseContext struct {
	Window struct {
		First  time.Time `json:"first"`
		Last   time.Time `json:"last"`
		Alerts int       `json:"alerts"`
	} `json:"window"`
}

type legacyCase struct {
	Status    string         `json:"status"`
	UpdatedAt time.Time      `json:"updated_at"`
	Notes     string         `json:"notes"`
	Actions   []legacyAction `json:"actions"`
}

type legacyAction struct {
	At      time.Time      `json:"at"`
	Action  string         `json:"action"`
	Outcome string         `json:"outcome"`
	Detail  map[string]any `json:"detail"`
}

type label struct {
	Verdict          string   `json:"verdict"`
	Notes            string   `json:"notes"`
	AttackTechniques []string `json:"attack_techniques"`
}

func Run(ctx context.Context, pool *pgxpool.Pool, tenant uuid.UUID, files Files) (Report, error) {
	var assessments []assessment
	if err := readJSON(files.Assessments, &assessments); err != nil {
		return Report{}, fmt.Errorf("assessments: %w", err)
	}
	cases := map[string]legacyCase{}
	if err := readJSON(files.Cases, &cases); err != nil {
		return Report{}, fmt.Errorf("cases: %w", err)
	}
	labels, err := readLabels(files.Labels)
	if err != nil {
		return Report{}, fmt.Errorf("labels: %w", err)
	}

	report := Report{Read: len(assessments)}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return report, fmt.Errorf("iniciar importação: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, a := range assessments {
		created, err := importOne(ctx, tx, tenant, a, cases[a.ClusterID], labels[a.ClusterID])
		if err != nil {
			return report, fmt.Errorf("cluster %s: %w", a.ClusterID, err)
		}
		if created {
			report.Imported++
		} else {
			report.Existing++
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return report, fmt.Errorf("commit da importação: %w", err)
	}
	return report, nil
}

func readJSON(path string, dest any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	dec := json.NewDecoder(f)
	if err := dec.Decode(dest); err != nil {
		return fmt.Errorf("decodificar %s: %w", path, err)
	}
	return nil
}

func readLabels(path string) (map[string]label, error) {
	raw := map[string]json.RawMessage{}
	if err := readJSON(path, &raw); err != nil {
		return nil, err
	}
	out := make(map[string]label, len(raw))
	for key, value := range raw {
		if strings.HasPrefix(key, "_") {
			continue
		}
		var item label
		if err := json.Unmarshal(value, &item); err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		out[key] = item
	}
	return out, nil
}

func importOne(ctx context.Context, tx pgx.Tx, tenant uuid.UUID, a assessment, c legacyCase, l label) (bool, error) {
	fingerprint, err := hex.DecodeString(a.ClusterID)
	if err != nil || len(fingerprint) == 0 {
		return false, fmt.Errorf("cluster_id não é hexadecimal")
	}
	var existing uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id FROM incident.incidents WHERE tenant_id=$1 AND fingerprint=$2 LIMIT 1`,
		tenant, fingerprint).Scan(&existing)
	if err == nil {
		return false, nil
	}
	if err != pgx.ErrNoRows {
		return false, fmt.Errorf("verificar existência: %w", err)
	}

	first, last := a.CaseContext.Window.First, a.CaseContext.Window.Last
	if first.IsZero() {
		first = time.Now().UTC()
	}
	if last.IsZero() {
		last = first
	}
	status := "new"
	var resolution, reason any
	var closedAt any
	if c.Status == "closed" {
		status = "closed"
		verdict := l.Verdict
		if !validResolution(verdict) {
			verdict = "inconclusive"
		}
		resolution = verdict
		reasonText := strings.TrimSpace(c.Notes)
		if reasonText == "" {
			reasonText = "Importado do legado sem motivo de fechamento registrado"
		}
		reason = reasonText
		if c.UpdatedAt.IsZero() {
			closedAt = last
		} else {
			closedAt = c.UpdatedAt
		}
	}
	techniques := a.AttackTechniques
	if len(l.AttackTechniques) > 0 {
		techniques = l.AttackTechniques
	}
	incidentID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("legacy:"+a.ClusterID))
	key := "LEGACY-" + strings.ToUpper(a.ClusterID)
	_, err = tx.Exec(ctx, `
		INSERT INTO incident.incidents
		  (id,tenant_id,key,type_id,title,description,status,severity,priority,
		   fingerprint,alert_count,first_seen,last_seen,resolution,closed_reason,closed_at,
		   attack_tactics,attack_techniques,tags,created_at,updated_at)
		SELECT $1,$2,$3,t.id,$4,NULLIF($5,''),$6,'medium',3,
		       $7,$8,$9::timestamptz,$10::timestamptz,$11::text,$12::text,$13::timestamptz,
		       $14::text[],$15::text[],ARRAY['legacy-import'],$9::timestamptz,
		       COALESCE($13::timestamptz,$10::timestamptz)
		  FROM incident.incident_types t
		 WHERE t.tenant_id=$2 AND t.slug='generic'`,
		incidentID, tenant, key, fallback(a.Title, "Caso legado "+a.ClusterID), a.Summary,
		status, fingerprint, max(a.CaseContext.Window.Alerts, 1), first, last,
		resolution, reason, closedAt, a.AttackTactics, techniques)
	if err != nil {
		return false, fmt.Errorf("inserir incidente: %w", err)
	}

	actorID := "legacy:unknown"
	now := first
	if c.UpdatedAt.After(now) {
		now = c.UpdatedAt
	}
	var auditID uuid.UUID
	err = tx.QueryRow(ctx, `
		INSERT INTO audit.audit_events
		  (tenant_id,occurred_at,actor_kind,actor_id,action,resource_type,resource_id,
		   incident_id,result,reason,after_state,metadata)
		VALUES ($1,$2,'system',$3,'incident.import','incident',$4::uuid::text,$4::uuid,'succeeded',
		        'Importado dos arquivos JSON do console legado',$5,$6)
		RETURNING id`, tenant, now, actorID, incidentID,
		jsonBytes(map[string]any{"status": status, "legacy_cluster_id": a.ClusterID}),
		jsonBytes(map[string]any{"source": "legacy-json", "cluster_id": a.ClusterID}),
	).Scan(&auditID)
	if err != nil {
		return false, fmt.Errorf("auditar importação: %w", err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO audit.timeline_events
		 (tenant_id,incident_id,occurred_at,event_type,actor_kind,actor_id,actor_label,title,detail,payload,audit_id)
		VALUES ($1,$2,$3,'incident.imported','system',$4,'Legado','Caso importado do console legado',$5,$6,$7)`,
		tenant, incidentID, now, actorID, c.Notes,
		jsonBytes(map[string]any{"cluster_id": a.ClusterID}), auditID)
	if err != nil {
		return false, fmt.Errorf("timeline da importação: %w", err)
	}
	for index, action := range c.Actions {
		at := action.At
		if at.IsZero() {
			at = now
		}
		result := action.Outcome
		if result != "failed" {
			result = "succeeded"
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO audit.audit_events
			 (tenant_id,occurred_at,actor_kind,actor_id,action,resource_type,resource_id,
			  incident_id,result,reason,metadata)
			VALUES ($1,$2,'system',$3,$4,'incident',$5::uuid::text,$5::uuid,$6,
			        'Ação importada; autor original desconhecido',$7)`,
			tenant, at, actorID, "legacy."+action.Action, incidentID, result,
			jsonBytes(map[string]any{"legacy_index": index, "detail": action.Detail}))
		if err != nil {
			return false, fmt.Errorf("ação legado %d: %w", index, err)
		}
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO platform.outbox_events
		 (tenant_id,topic,aggregate_id,actor_kind,actor_id,payload)
		VALUES ($1,'incident.imported',$2,'system',$3,$4)`,
		tenant, incidentID, actorID, jsonBytes(map[string]any{"cluster_id": a.ClusterID}))
	if err != nil {
		return false, fmt.Errorf("outbox da importação: %w", err)
	}
	return true, nil
}

func validResolution(v string) bool {
	return v == "true_positive" || v == "benign_true_positive" || v == "false_positive" || v == "inconclusive"
}

func fallback(value, def string) string {
	if strings.TrimSpace(value) == "" {
		return def
	}
	return value
}
func jsonBytes(value any) string { out, _ := json.Marshal(value); return string(out) }
