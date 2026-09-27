package incident

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/titas/soar/backend/internal/core/errs"
	"github.com/titas/soar/backend/internal/core/id"
)

var (
	now   = time.Date(2026, 9, 20, 18, 0, 0, 0, time.UTC)
	actor = id.UserID{UUID: uuid.MustParse("00000000-0000-0000-0000-0000000000aa")}
)

func base(status Status) *Incident {
	return &Incident{
		ID:          id.IncidentID{UUID: uuid.New()},
		Key:         "INC-2026-000001",
		Title:       "teste",
		Status:      status,
		Severity:    SeverityHigh,
		Priority:    2,
		Fingerprint: []byte{1, 2, 3},
		FirstSeen:   now.Add(-time.Hour),
		LastSeen:    now,
	}
}

func TestTransitions(t *testing.T) {
	cases := []struct {
		name  string
		from  Status
		to    Status
		legal bool
	}{
		{"novo para triagem", StatusNew, StatusTriage, true},
		{"novo para fechado", StatusNew, StatusClosed, true},
		{"triagem para investigando", StatusTriage, StatusInvestigating, true},
		{"investigando para aguardando ação", StatusInvestigating, StatusPendingAction, true},
		{"resolvido para fechado", StatusResolved, StatusClosed, true},
		{"resolvido volta a investigando", StatusResolved, StatusInvestigating, true},
		{"fechado é terminal", StatusClosed, StatusInvestigating, false},
		{"fechado não volta a triagem", StatusClosed, StatusTriage, false},
		{"aguardando ação não fecha direto", StatusPendingAction, StatusClosed, false},
		{"novo não pula para resolvido", StatusNew, StatusResolved, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := base(c.from).CanTransitionTo(c.to); got != c.legal {
				t.Fatalf("%s -> %s: got %v, want %v", c.from, c.to, got, c.legal)
			}
		})
	}
}

func TestCloseRequiresReasonAndResolution(t *testing.T) {
	cases := []struct {
		name    string
		res     Resolution
		reason  string
		wantErr error
		code    string
	}{
		{"fecha com motivo", ResolutionBenignTruePositive, "processo de infraestrutura conhecido", nil, ""},
		{"sem motivo", ResolutionFalsePositive, "", errs.ErrValidation, "REASON_REQUIRED"},
		{"resolução inválida", Resolution("meh"), "qualquer", errs.ErrValidation, "INVALID_RESOLUTION"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			inc := base(StatusInvestigating)
			err := inc.Close(c.res, c.reason, &actor, now)
			if c.wantErr == nil {
				if err != nil {
					t.Fatalf("esperava sucesso, veio %v", err)
				}
				if inc.Status != StatusClosed || inc.ClosedAt == nil {
					t.Fatalf("estado não fechou: %+v", inc.Status)
				}
				return
			}
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("erro %v não é %v", err, c.wantErr)
			}
			if got := errs.CodeOf(err); got != c.code {
				t.Fatalf("code = %q, want %q", got, c.code)
			}
			if inc.Status == StatusClosed {
				t.Fatal("incidente não deveria ter fechado")
			}
		})
	}
}

// O invariante que existe para impedir o fechamento apressado: se alguém marcou
// um passo como obrigatório, ele é obrigatório.
func TestCloseBlockedByMandatoryTasks(t *testing.T) {
	inc := base(StatusInvestigating)
	inc.OpenMandatoryTasks = 2

	err := inc.Close(ResolutionTruePositive, "contido", &actor, now)
	if !errors.Is(err, errs.ErrPreconditionFailed) {
		t.Fatalf("esperava ErrPreconditionFailed, veio %v", err)
	}
	if errs.CodeOf(err) != "MANDATORY_TASKS_OPEN" {
		t.Fatalf("code = %q", errs.CodeOf(err))
	}

	inc.OpenMandatoryTasks = 0
	if err := inc.Close(ResolutionTruePositive, "contido", &actor, now); err != nil {
		t.Fatalf("deveria fechar depois das tarefas: %v", err)
	}
}

func TestReopenKeepsHistoryAndNeedsReason(t *testing.T) {
	inc := base(StatusInvestigating)
	if err := inc.Close(ResolutionFalsePositive, "engano", &actor, now); err != nil {
		t.Fatal(err)
	}
	if err := inc.Reopen("", &actor, now); !errors.Is(err, errs.ErrValidation) {
		t.Fatalf("reabrir sem motivo deveria falhar, veio %v", err)
	}
	if err := inc.Reopen("nova evidência", &actor, now); err != nil {
		t.Fatalf("reabertura legítima falhou: %v", err)
	}
	if inc.Status != StatusInvestigating || inc.ClosedAt != nil {
		t.Fatalf("reabertura não limpou o fechamento: %v %v", inc.Status, inc.ClosedAt)
	}
	// Reabrir de novo, agora que está aberto, é ilegal.
	if err := inc.Reopen("de novo", &actor, now); !errors.Is(err, errs.ErrInvalidStateTransition) {
		t.Fatalf("esperava transição ilegal, veio %v", err)
	}
}

// A razão de existir da deduplicação: 50 000 alertas de uma regra quebrada
// viram UM incidente cujo contador anda — não 50 000 incidentes.
func TestAbsorbAlertMovesCounterNotIdentity(t *testing.T) {
	inc := base(StatusNew)
	original := inc.ID
	first, last := inc.FirstSeen, inc.LastSeen

	inc.AbsorbAlert(last.Add(30*time.Minute), now)
	inc.AbsorbAlert(first.Add(-2*time.Hour), now) // chegada tardia

	if inc.ID != original {
		t.Fatal("a identidade do incidente mudou")
	}
	if inc.AlertCount != 2 {
		t.Fatalf("alert_count = %d, want 2", inc.AlertCount)
	}
	if !inc.LastSeen.Equal(last.Add(30 * time.Minute)) {
		t.Fatalf("last_seen não avançou: %v", inc.LastSeen)
	}
	if !inc.FirstSeen.Equal(first.Add(-2 * time.Hour)) {
		t.Fatalf("first_seen não recuou com a chegada tardia: %v", inc.FirstSeen)
	}
}

func TestAcknowledgeIsIdempotent(t *testing.T) {
	inc := base(StatusNew)
	inc.Acknowledge(actor, now)
	firstAck := *inc.FirstAckAt
	inc.Acknowledge(actor, now.Add(time.Hour))
	if !inc.FirstAckAt.Equal(firstAck) {
		t.Fatal("o primeiro ack é o que conta; foi sobrescrito")
	}
}

func TestPendingEventsDrain(t *testing.T) {
	inc := base(StatusInvestigating)
	inc.Acknowledge(actor, now)
	if err := inc.Close(ResolutionInconclusive, "sem evidência", &actor, now); err != nil {
		t.Fatal(err)
	}
	first := inc.PendingEvents()
	if len(first) != 2 {
		t.Fatalf("esperava 2 eventos, veio %d", len(first))
	}
	if got := inc.PendingEvents(); len(got) != 0 {
		t.Fatalf("drenar duas vezes reenfileiraria %d evento(s)", len(got))
	}
}

func TestAssignRefusesClosedIncident(t *testing.T) {
	inc := base(StatusInvestigating)
	_ = inc.Close(ResolutionTruePositive, "contido", &actor, now)
	if err := inc.Assign(actor, now); !errors.Is(err, errs.ErrInvalidStateTransition) {
		t.Fatalf("esperava recusa, veio %v", err)
	}
}

func TestSystemActorDoesNotForgeHumanClosedBy(t *testing.T) {
	inc := base(StatusInvestigating)
	if err := inc.Close(ResolutionBenignTruePositive, "regra automática explícita", nil, now); err != nil {
		t.Fatal(err)
	}
	if inc.ClosedBy != nil {
		t.Fatalf("automação fabricou closed_by humano: %v", inc.ClosedBy)
	}
	if inc.FirstAckAt != nil {
		t.Fatal("fechamento automático não deve contar como atenção humana")
	}
}

// O motivo entra na trilha append-only: um texto absurdo gravado por engano
// não pode ser apagado depois. O limite mora no domínio, não só no schema.
func TestCloseRejectsOversizedReason(t *testing.T) {
	inc := base(StatusInvestigating)
	err := inc.Close(ResolutionFalsePositive, strings.Repeat("a", MaxReasonLength+1), &actor, now)
	if !errors.Is(err, errs.ErrValidation) {
		t.Fatalf("esperava ErrValidation, veio %v", err)
	}
	if errs.CodeOf(err) != "REASON_TOO_LONG" {
		t.Fatalf("code = %q", errs.CodeOf(err))
	}

	// Exatamente no limite passa.
	inc2 := base(StatusInvestigating)
	if err := inc2.Close(ResolutionFalsePositive, strings.Repeat("a", MaxReasonLength), &actor, now); err != nil {
		t.Fatalf("no limite deveria passar: %v", err)
	}
}

// Contar runes e não bytes: 4000 caracteres acentuados ocupam ~8000 bytes e
// ainda são 4000 caracteres para quem escreveu.
func TestReasonLimitCountsRunesNotBytes(t *testing.T) {
	inc := base(StatusInvestigating)
	if err := inc.Close(ResolutionTruePositive, strings.Repeat("ç", MaxReasonLength), &actor, now); err != nil {
		t.Fatalf("4000 runes multibyte deveriam passar: %v", err)
	}
}
