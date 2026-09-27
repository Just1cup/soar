package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/titas/soar/backend/internal/core/id"
	"github.com/titas/soar/backend/internal/integration"
	"github.com/titas/soar/backend/internal/integration/adapters/elastic"
	"github.com/titas/soar/backend/internal/platform/config"
	"github.com/titas/soar/backend/internal/platform/postgres"
	respg "github.com/titas/soar/backend/internal/response/postgres"
)

// loadContentPacks reads the packs from disk, installs their manifests and
// binds the adapters compiled into THIS deployment.
//
// An action declared in a manifest with no adapter bound stays visible in the
// catalogue and answers "not implemented" with its reason. That is how
// containment exists as a capability without existing as a button here.
func loadContentPacks(ctx context.Context, dir string, tenant id.TenantID,
	assets *respg.AssetStore, log *slog.Logger) (*integration.Registry, error) {

	registry := integration.NewRegistry()
	registry.Bind(elastic.New())

	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		// Sem packs a plataforma sobe e serve incidentes; ela só não consegue
		// agir. É estado de configuração, não erro fatal.
		log.Warn("diretório de content packs ausente; nenhuma integração instalada", "dir", dir)
		return registry, nil
	}

	packs, err := integration.LoadPacks(os.DirFS(dir), log)
	if err != nil {
		return nil, err
	}
	for _, p := range packs {
		raw, err := json.Marshal(p.Manifest)
		if err != nil {
			log.Error("manifesto não serializável, ignorado", "pack", p.Manifest.ID, "error", err)
			continue
		}
		if err := assets.UpsertIntegration(ctx, tenant, p.Manifest.ID, p.Manifest.Name,
			p.Manifest.PackID, raw, p.SHA256); err != nil {
			return nil, err
		}
		registry.Install(p.Manifest)
		implemented := 0
		for _, a := range p.Manifest.Actions {
			if a.Implemented {
				implemented++
			}
		}
		log.Info("content pack instalado", "pack", p.Manifest.PackID,
			"integration", p.Manifest.ID,
			"actions", len(p.Manifest.Actions), "implemented", implemented)
	}
	return registry, nil
}

// configureAsset is the operator action that names an endpoint and a
// credential POINTER. The secret never passes through here, and the database
// refuses anything that is not a pointer.
func configureAsset(spec string) error {
	// integração=elastic-siem,endpoint=...,cred=env://VAR,config.k=v
	fields := map[string]string{}
	config := map[string]any{}
	for _, part := range strings.Split(spec, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return fmt.Errorf("par inválido em --configure-asset: %q", part)
		}
		if after, found := strings.CutPrefix(k, "config."); found {
			config[after] = v
			continue
		}
		fields[k] = v
	}
	slug := fields["integration"]
	if slug == "" || fields["cred"] == "" {
		return fmt.Errorf("use integration=<slug>,endpoint=<url>,cred=<env://VAR>[,config.k=v]")
	}
	name := fields["name"]
	if name == "" {
		name = "default"
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

	if err := respg.NewAssetStore(tx).ConfigureAsset(ctx, defaultTenant,
		slug, name, fields["endpoint"], fields["cred"], config); err != nil {
		return err
	}
	slog.Info("asset configurado", "integration", slug, "name", name,
		"endpoint", fields["endpoint"], "credential_ref", fields["cred"])
	return nil
}

// loadConfigOrFail and openPool exist so the one-shot CLI modes (provision a
// user, configure an asset) share the same startup path as the server: a
// second way to build a pool is a second place to get the timeouts wrong.
func loadConfigOrFail() (config.Config, error) {
	return config.Load()
}

func openPool(ctx context.Context, cfg config.Config, maxConns int32) (*pgxpool.Pool, *postgres.TxManager, error) {
	pool, err := postgres.NewPool(ctx, cfg.DatabaseURL, maxConns)
	if err != nil {
		return nil, nil, err
	}
	return pool, postgres.NewTxManager(pool), nil
}
