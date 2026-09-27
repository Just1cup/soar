package casework

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/titas/soar/backend/internal/audit"
	"github.com/titas/soar/backend/internal/core/errs"
	"github.com/titas/soar/backend/internal/core/id"
	"github.com/titas/soar/backend/internal/incident"
	pg "github.com/titas/soar/backend/internal/platform/postgres"
	"github.com/titas/soar/backend/internal/platform/telemetry"
	"github.com/titas/soar/backend/internal/rbac"
)

type Task struct {
	ID          uuid.UUID  `json:"id"`
	Phase       string     `json:"phase"`
	Title       string     `json:"title"`
	Instruction string     `json:"instruction"`
	Position    int        `json:"position"`
	Mandatory   bool       `json:"mandatory"`
	Status      string     `json:"status"`
	CompletedAt *time.Time `json:"completed_at"`
	Version     int        `json:"version"`
}

type Note struct {
	ID          uuid.UUID `json:"id"`
	TaskID      uuid.UUID `json:"task_id"`
	AuthorLabel string    `json:"author_label"`
	Body        string    `json:"body"`
	CreatedAt   time.Time `json:"created_at"`
}

type Service struct {
	Tx        *pg.TxManager
	Incidents incident.Repository
	Audit     audit.Writer
	Perms     rbac.Checker
}

func (s Service) List(ctx context.Context, incidentID id.IncidentID) ([]Task, error) {
	actor, err := s.Perms.Require(ctx, rbac.IncidentRead)
	if err != nil {
		return nil, err
	}
	if _, err = s.Incidents.FindByID(ctx, actor.TenantID, incidentID); err != nil {
		return nil, err
	}
	rows, err := s.Tx.DB(ctx).Query(ctx, `SELECT id, phase, title, instruction, position, mandatory, status, completed_at, version
        FROM incident.tasks WHERE tenant_id=$1 AND incident_id=$2 ORDER BY position, id`, actor.TenantID.UUID, incidentID.UUID)
	if err != nil {
		return nil, fmt.Errorf("listar tarefas: %w", err)
	}
	defer rows.Close()
	out := []Task{}
	for rows.Next() {
		var task Task
		if err := rows.Scan(&task.ID, &task.Phase, &task.Title, &task.Instruction, &task.Position, &task.Mandatory, &task.Status, &task.CompletedAt, &task.Version); err != nil {
			return nil, err
		}
		out = append(out, task)
	}
	return out, rows.Err()
}

func (s Service) Notes(ctx context.Context, incidentID id.IncidentID, taskID uuid.UUID) ([]Note, error) {
	actor, err := s.Perms.Require(ctx, rbac.IncidentRead)
	if err != nil {
		return nil, err
	}
	if _, err = s.Incidents.FindByID(ctx, actor.TenantID, incidentID); err != nil {
		return nil, err
	}
	var found int
	err = s.Tx.DB(ctx).QueryRow(ctx, `SELECT 1 FROM incident.tasks WHERE tenant_id=$1 AND incident_id=$2 AND id=$3`, actor.TenantID.UUID, incidentID.UUID, taskID).Scan(&found)
	if err == pgx.ErrNoRows {
		return nil, errs.Coded(errs.ErrNotFound, "TASK_NOT_FOUND", "tarefa não encontrada")
	}
	if err != nil {
		return nil, err
	}
	rows, err := s.Tx.DB(ctx).Query(ctx, `SELECT n.id, n.task_id, n.author_label, n.body, n.created_at
        FROM incident.task_notes n JOIN incident.tasks t ON t.id=n.task_id
        WHERE n.tenant_id=$1 AND n.incident_id=$2 AND n.task_id=$3 AND t.tenant_id=$1 AND t.incident_id=$2
        ORDER BY n.created_at, n.id LIMIT 500`, actor.TenantID.UUID, incidentID.UUID, taskID)
	if err != nil {
		return nil, fmt.Errorf("listar notas: %w", err)
	}
	defer rows.Close()
	out := []Note{}
	for rows.Next() {
		var note Note
		if err := rows.Scan(&note.ID, &note.TaskID, &note.AuthorLabel, &note.Body, &note.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, note)
	}
	return out, rows.Err()
}

func (s Service) Complete(ctx context.Context, incidentID id.IncidentID, taskID uuid.UUID, version int) (Task, error) {
	actor, err := s.Perms.Require(ctx, rbac.CaseTaskComplete)
	if err != nil {
		return Task{}, err
	}
	if version < 1 {
		return Task{}, errs.Coded(errs.ErrPreconditionFailed, "EXPECTED_VERSION_REQUIRED", "informe a versão da tarefa")
	}
	var task Task
	err = s.Tx.InTx(ctx, func(ctx context.Context) error {
		inc, err := s.Incidents.FindForUpdate(ctx, actor.TenantID, incidentID)
		if err != nil {
			return err
		}
		if !inc.Status.Open() {
			return errs.Coded(errs.ErrConflict, "INCIDENT_CLOSED", "incidente fechado")
		}
		row := s.Tx.DB(ctx).QueryRow(ctx, `SELECT id, phase, title, instruction, position, mandatory, status, completed_at, version
            FROM incident.tasks WHERE tenant_id=$1 AND incident_id=$2 AND id=$3 FOR UPDATE`, actor.TenantID.UUID, incidentID.UUID, taskID)
		if err := row.Scan(&task.ID, &task.Phase, &task.Title, &task.Instruction, &task.Position, &task.Mandatory, &task.Status, &task.CompletedAt, &task.Version); err != nil {
			if err == pgx.ErrNoRows {
				return errs.Coded(errs.ErrNotFound, "TASK_NOT_FOUND", "tarefa não encontrada")
			}
			return err
		}
		if task.Version != version {
			return errs.Coded(errs.ErrVersionConflict, "VERSION_CONFLICT", "tarefa alterada; atualize a página")
		}
		if task.Status == "done" {
			return errs.Coded(errs.ErrConflict, "TASK_ALREADY_DONE", "tarefa já concluída")
		}
		now := time.Now().UTC()
		var userID *uuid.UUID
		if actor.UserID != nil {
			userID = &actor.UserID.UUID
		}
		if err := s.Tx.DB(ctx).QueryRow(ctx, `UPDATE incident.tasks SET status='done', completed_at=$1, completed_by=$2, version=version+1
            WHERE id=$3 RETURNING version`, now, userID, taskID).Scan(&task.Version); err != nil {
			return err
		}
		if task.Mandatory {
			if _, err := s.Tx.DB(ctx).Exec(ctx, `UPDATE incident.incidents SET open_mandatory_tasks=open_mandatory_tasks-1 WHERE id=$1 AND tenant_id=$2`, incidentID.UUID, actor.TenantID.UUID); err != nil {
				return err
			}
		}
		task.Status, task.CompletedAt = "done", &now
		return s.Audit.Record(ctx, audit.Fact{Classification: audit.Both, TenantID: actor.TenantID, IncidentID: &incidentID,
			OccurredAt: now, Actor: audit.Actor{Kind: audit.ActorKind(actor.Kind), ID: actor.ID, Label: actor.Label},
			Action: "case.task.complete", ResourceType: "task", ResourceID: task.ID.String(), Result: audit.Succeeded,
			EventType: "task.completed", Title: "Tarefa concluída: " + task.Title, Payload: map[string]any{"task_id": task.ID.String()},
			RequestID: telemetry.RequestID(ctx), TraceID: telemetry.TraceID(ctx)})
	})
	return task, err
}

func (s Service) AddNote(ctx context.Context, incidentID id.IncidentID, taskID uuid.UUID, body string) (Note, error) {
	actor, err := s.Perms.Require(ctx, rbac.CaseComment)
	if err != nil {
		return Note{}, err
	}
	body = strings.TrimSpace(body)
	if len([]rune(body)) < 1 || len([]rune(body)) > 4000 {
		return Note{}, errs.Coded(errs.ErrValidation, "INVALID_NOTE", "nota deve ter entre 1 e 4000 caracteres")
	}
	var note Note
	err = s.Tx.InTx(ctx, func(ctx context.Context) error {
		if _, err := s.Incidents.FindForUpdate(ctx, actor.TenantID, incidentID); err != nil {
			return err
		}
		var taskTitle string
		err := s.Tx.DB(ctx).QueryRow(ctx, `SELECT title FROM incident.tasks WHERE tenant_id=$1 AND incident_id=$2 AND id=$3`, actor.TenantID.UUID, incidentID.UUID, taskID).Scan(&taskTitle)
		if err == pgx.ErrNoRows {
			return errs.Coded(errs.ErrNotFound, "TASK_NOT_FOUND", "tarefa não encontrada")
		}
		if err != nil {
			return err
		}
		var userID *uuid.UUID
		if actor.UserID != nil {
			userID = &actor.UserID.UUID
		}
		note = Note{TaskID: taskID, AuthorLabel: actor.Label, Body: body}
		err = s.Tx.DB(ctx).QueryRow(ctx, `INSERT INTO incident.task_notes (tenant_id, incident_id, task_id, author_id, author_label, body)
            VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, created_at`, actor.TenantID.UUID, incidentID.UUID, taskID, userID, actor.Label, body).Scan(&note.ID, &note.CreatedAt)
		if err != nil {
			return err
		}
		return s.Audit.Record(ctx, audit.Fact{Classification: audit.Both, TenantID: actor.TenantID, IncidentID: &incidentID,
			OccurredAt: note.CreatedAt, Actor: audit.Actor{Kind: audit.ActorKind(actor.Kind), ID: actor.ID, Label: actor.Label},
			Action: "case.task.note", ResourceType: "task", ResourceID: taskID.String(), Result: audit.Succeeded,
			EventType: "task.note.added", Title: "Nota em: " + taskTitle, Detail: body,
			Payload:   map[string]any{"task_id": taskID.String(), "note_id": note.ID.String()},
			RequestID: telemetry.RequestID(ctx), TraceID: telemetry.TraceID(ctx)})
	})
	return note, err
}
