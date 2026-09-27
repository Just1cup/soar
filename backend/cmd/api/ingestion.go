package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/titas/soar/backend/internal/core/clock"
	"github.com/titas/soar/backend/internal/core/id"
	"github.com/titas/soar/backend/internal/ingestion"
	ingpg "github.com/titas/soar/backend/internal/ingestion/postgres"
	elasticsource "github.com/titas/soar/backend/internal/ingestion/sources/elastic"
	"github.com/titas/soar/backend/internal/integration"
	"github.com/titas/soar/backend/internal/platform/postgres"
)

// installRules reads rules/*.yaml from the content packs.
//
// They land DISABLED. Enabling requires a dry run, and the database refuses
// otherwise: a suppression rule that drops the wrong thing removes a real
// attack, silently.
func installRules(ctx context.Context, dir string, tenant id.TenantID,
	rules *ingpg.RuleStore, log *slog.Logger) error {

	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return nil
	}
	byPack, err := integration.LoadRules(os.DirFS(dir), log)
	if err != nil {
		return err
	}
	for pack, specs := range byPack {
		for _, spec := range specs {
			rule, err := toRule(spec)
			if err != nil {
				log.Error("regra inválida, ignorada", "pack", pack, "rule", spec.ID, "error", err)
				continue
			}
			if err := rules.Upsert(ctx, tenant, rule, pack); err != nil {
				return err
			}
		}
		log.Info("regras instaladas (desligadas)", "pack", pack, "count", len(specs))
	}
	return nil
}

// toRule converts the wire form into the domain rule. Going through JSON
// keeps one parser for the shape instead of two hand-written ones.
func toRule(spec integration.RuleSpec) (ingestion.Rule, error) {
	raw, err := json.Marshal(map[string]any{
		"conditions": spec.Conditions, "actions": spec.Actions,
	})
	if err != nil {
		return ingestion.Rule{}, err
	}
	var parsed struct {
		Conditions ingestion.Conditions   `json:"conditions"`
		Actions    []ingestion.RuleAction `json:"actions"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return ingestion.Rule{}, err
	}
	if spec.ID == "" {
		return ingestion.Rule{}, fmt.Errorf("regra sem id")
	}
	if len(parsed.Actions) == 0 {
		return ingestion.Rule{}, fmt.Errorf("regra sem ações")
	}
	trigger := spec.Trigger
	if trigger == "" {
		trigger = "alert.received"
	}
	return ingestion.Rule{
		Slug: spec.ID, Name: spec.Name, Trigger: trigger, Order: spec.Order,
		Conditions: parsed.Conditions, Actions: parsed.Actions, ExpiresAt: spec.ExpiresAt,
	}, nil
}

// configureSource is an operator action: which SIEM, which index, how far
// back the first fetch reaches.
func configureSource(spec string) error {
	fields := map[string]string{}
	config := map[string]any{}
	for _, part := range strings.Split(spec, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return fmt.Errorf("par inválido: %q", part)
		}
		if after, found := strings.CutPrefix(k, "config."); found {
			config[after] = v
			continue
		}
		fields[k] = v
	}
	if fields["slug"] == "" || fields["kind"] == "" {
		return fmt.Errorf("use slug=<nome>,kind=elastic-siem,mode=pull[,enabled=true][,config.k=v]")
	}
	cfg, err := loadConfigOrFail()
	if err != nil {
		return err
	}
	ctx := context.Background()
	pool, tx, err := openPool(ctx, cfg, 2)
	if err != nil {
		return err
	}
	defer pool.Close()

	mode := fields["mode"]
	if mode == "" {
		mode = "pull"
	}
	enabled, _ := strconv.ParseBool(fields["enabled"])
	incidentType := fields["incident_type"]
	if incidentType == "" {
		incidentType = "generic"
	}
	source := &ingestion.SourceConfig{
		TenantID: defaultTenant, Slug: fields["slug"],
		Name: firstNonEmpty(fields["name"], fields["slug"]),
		Kind: fields["kind"], Mode: mode, Config: config,
		DefaultIncidentType: incidentType, Enabled: enabled,
	}
	if err := ingpg.NewSourceStore(tx).Upsert(ctx, source); err != nil {
		return err
	}
	slog.Info("fonte configurada", "slug", source.Slug, "kind", source.Kind,
		"mode", source.Mode, "enabled", source.Enabled)
	return nil
}

// dryRunRule answers the question the database demands before a suppression
// can be armed: how many alerts would this have suppressed, and which?
func dryRunRule(slug string, enable bool) error {
	cfg, err := loadConfigOrFail()
	if err != nil {
		return err
	}
	ctx := context.Background()
	pool, tx, err := openPool(ctx, cfg, 2)
	if err != nil {
		return err
	}
	defer pool.Close()

	rules := ingpg.NewRuleStore(tx)
	all, _, err := rules.All(ctx, defaultTenant)
	if err != nil {
		return err
	}
	var target *ingestion.Rule
	for i := range all {
		if all[i].Slug == slug {
			target = &all[i]
		}
	}
	if target == nil {
		return fmt.Errorf("regra %q não encontrada", slug)
	}

	alerts := ingpg.NewAlertStore(tx)
	sample, err := alerts.Recent(ctx, defaultTenant, time.Now().Add(-30*24*time.Hour), 5000)
	if err != nil {
		return err
	}
	pipeline := &ingestion.Pipeline{Clock: clock.System{}}
	result := pipeline.DryRun(ctx, defaultTenant, *target, sample)

	fmt.Printf("\n  regra:      %s (%s)\n", target.Name, target.Slug)
	fmt.Printf("  avaliados:  %d alertas dos últimos 30 dias\n", result.Evaluated)
	fmt.Printf("  casariam:   %d\n", result.Matched)
	for _, s := range result.Samples {
		fmt.Printf("    %s  %-28s %s\n", s.EventTime.Format("2006-01-02 15:04"),
			truncate(s.RuleName, 28), truncate(s.Entity, 30))
	}
	if err := rules.RecordDryRun(ctx, defaultTenant, slug, result.Matched, time.Now()); err != nil {
		return err
	}
	fmt.Printf("\n  dry-run registrado. A regra pode ser ligada.\n")
	if enable {
		if err := rules.SetEnabled(ctx, defaultTenant, slug, true); err != nil {
			return err
		}
		fmt.Printf("  regra LIGADA.\n")
	}
	return nil
}

// buildRunner assembles the pull loop. It lives in the API process in the
// `edge` profile; when cmd/worker exists it moves there untouched, because it
// only needs a TxManager (docs/soar/08 §5).
func buildRunner(tenant id.TenantID, tx *postgres.TxManager, pipeline *ingestion.Pipeline,
	log *slog.Logger, interval time.Duration) *ingestion.Runner {

	return &ingestion.Runner{
		Tenant:     tenant,
		Sources:    ingpg.NewSourceStore(tx),
		Sink:       ingpg.NewSink(tx),
		Pipeline:   pipeline,
		Runs:       ingpg.NewRunStore(tx),
		Connectors: map[string]ingestion.Source{"elastic-siem": elasticsource.New()},
		Clock:      clock.System{}, Log: log,
		Interval: interval, MaxFetch: 200,
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
