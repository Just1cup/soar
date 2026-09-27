package ingestion

import (
	"context"
	"log/slog"
	"time"

	"github.com/titas/soar/backend/internal/core/clock"
	"github.com/titas/soar/backend/internal/core/id"
)

// Runner drives the pull connectors on a schedule.
//
// The order inside one cycle is the whole safety property:
//
//	buscar -> ACEITAR DURAVELMENTE -> avançar o cursor -> processar
//
// The cursor advances only after Accept returned. If the sink fails, the
// cursor does not move, the next cycle fetches the same page, and the
// duplicate dies in the alert's unique constraint. That is what makes pull
// at-least-once instead of best effort.
type Runner struct {
	Tenant     id.TenantID
	Sources    SourceRepository
	Sink       IntakeSink
	Pipeline   *Pipeline
	Runs       RunRecorder
	Connectors map[string]Source
	Clock      clock.Clock
	Log        *slog.Logger
	Interval   time.Duration
	MaxFetch   int
}

// Run blocks until the context is cancelled.
func (r *Runner) Run(ctx context.Context) {
	ticker := time.NewTicker(r.Interval)
	defer ticker.Stop()
	r.cycle(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.cycle(ctx)
		}
	}
}

func (r *Runner) cycle(ctx context.Context) {
	sources, err := r.Sources.ListEnabled(ctx, r.Tenant)
	if err != nil {
		r.Log.Error("ingestão: não foi possível listar fontes", "error", err)
		return
	}
	for _, src := range sources {
		if src.Mode != "pull" {
			continue // push e agente chegam pela API de ingestão, não por aqui
		}
		if err := r.RunOnce(ctx, src); err != nil {
			r.Log.Error("ingestão: ciclo falhou", "source", src.Slug, "error", err)
		}
	}
}

// RunOnce executes one fetch cycle for one source. Exported so the operator
// can trigger it and see the result immediately, instead of waiting out the
// interval and guessing.
func (r *Runner) RunOnce(ctx context.Context, src SourceConfig) error {
	connector, ok := r.Connectors[src.Kind]
	if !ok {
		return nil
	}
	started := r.Clock.Now()
	before, err := r.Sources.Cursor(ctx, src.ID)
	if err != nil {
		return err
	}
	runID, err := r.Runs.Begin(ctx, r.Tenant, src.ID, before)
	if err != nil {
		return err
	}
	stats := RunStats{After: before, Status: "succeeded"}

	fail := func(err error) error {
		stats.Status, stats.Err = "failed", err.Error()
		stats.Duration = r.Clock.Now().Sub(started)
		_ = r.Runs.End(ctx, runID, stats)
		return err
	}

	fetched, err := connector.Fetch(ctx, src.Config, before, r.MaxFetch)
	if err != nil {
		return fail(err)
	}
	stats.Fetched = len(fetched.Events)

	if len(fetched.Events) > 0 {
		receipt, err := r.Sink.Accept(ctx, r.Tenant, src.ID, fetched.Events)
		if err != nil {
			return fail(err)
		}
		stats.Accepted = receipt.Accepted
		stats.Duplicates = receipt.Received - receipt.Accepted

		// SÓ AGORA o cursor anda.
		if err := r.Sources.AdvanceCursor(ctx, src.ID, fetched.Next, r.Clock.Now()); err != nil {
			return fail(err)
		}
		stats.After = fetched.Next
	}

	processed, err := r.Pipeline.Process(ctx, r.Tenant, src, r.MaxFetch)
	if err != nil {
		return fail(err)
	}
	stats.Quarantined = processed.Quarantined
	stats.IncidentsCreated = processed.IncidentsCreated
	stats.IncidentsUpdated = processed.IncidentsUpdated
	stats.Duplicates += processed.Duplicates
	stats.Duration = r.Clock.Now().Sub(started)

	if stats.Fetched > 0 || stats.IncidentsCreated > 0 {
		r.Log.Info("ingestão",
			"source", src.Slug, "buscados", stats.Fetched, "aceitos", stats.Accepted,
			"duplicados", stats.Duplicates, "suprimidos", processed.Suppressed,
			"quarentena", stats.Quarantined,
			"incidentes_novos", stats.IncidentsCreated,
			"incidentes_atualizados", stats.IncidentsUpdated,
			"ms", stats.Duration.Milliseconds())
	}
	return r.Runs.End(ctx, runID, stats)
}

// DryRun evaluates a rule against recent alerts WITHOUT applying anything.
//
// It is the gate for enabling a suppression: the database refuses to enable a
// rule that has never been dry-run. A rule that drops the wrong thing removes
// a real attack, silently — so "how many would this have suppressed, and
// which?" has to be answerable before it is armed.
type DryRunResult struct {
	Evaluated int
	Matched   int
	Samples   []DryRunSample
}

type DryRunSample struct {
	RuleName  string
	Host      string
	Entity    string
	Title     string
	EventTime time.Time
}

// DryRun replays the rule against alerts already ingested. It writes nothing.
func (p *Pipeline) DryRun(ctx context.Context, tenant id.TenantID, rule Rule,
	sample []*Alert) DryRunResult {

	out := DryRunResult{Evaluated: len(sample)}
	// Avaliada isolada e forçada a ligada: o operador quer saber o que ESTA
	// regra faria, não o que a pilha inteira faria.
	rule.Enabled = true
	if rule.ExpiresAt != nil && !p.Clock.Now().Before(*rule.ExpiresAt) {
		far := p.Clock.Now().Add(time.Hour)
		rule.ExpiresAt = &far
	}
	for _, a := range sample {
		if !rule.Conditions.Match(a) {
			continue
		}
		out.Matched++
		if len(out.Samples) < 10 {
			out.Samples = append(out.Samples, DryRunSample{
				RuleName: a.RuleName, Host: a.Host, Entity: a.Entity,
				Title: a.Title, EventTime: a.EventTime,
			})
		}
	}
	return out
}

// AlertSampler reads recent alerts for a dry run.
type AlertSampler interface {
	Recent(ctx context.Context, tenant id.TenantID, since time.Time, limit int) ([]*Alert, error)
}
