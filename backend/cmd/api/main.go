// Command api serves the control plane: the analyst-facing API.
//
// It is deliberately separate from cmd/ingest (docs/soar/08 §10): the process
// exposed to third parties gets a database role that can only insert raw
// events, and this one never listens to the internet.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/titas/soar/backend/internal/assessment"
	assessmentelastic "github.com/titas/soar/backend/internal/assessment/elastic"
	assessmenthttp "github.com/titas/soar/backend/internal/assessment/http"
	assessmentpg "github.com/titas/soar/backend/internal/assessment/postgres"
	"github.com/titas/soar/backend/internal/audit"
	auditpg "github.com/titas/soar/backend/internal/audit/postgres"
	"github.com/titas/soar/backend/internal/auth"
	authhttp "github.com/titas/soar/backend/internal/auth/http"
	authpg "github.com/titas/soar/backend/internal/auth/postgres"
	"github.com/titas/soar/backend/internal/casework"
	casehttp "github.com/titas/soar/backend/internal/casework/http"
	"github.com/titas/soar/backend/internal/core/clock"
	"github.com/titas/soar/backend/internal/core/id"
	"github.com/titas/soar/backend/internal/core/pagination"
	"github.com/titas/soar/backend/internal/httpx"
	incidenthttp "github.com/titas/soar/backend/internal/incident/http"
	incidentpg "github.com/titas/soar/backend/internal/incident/postgres"
	"github.com/titas/soar/backend/internal/incident/usecase"
	"github.com/titas/soar/backend/internal/ingestion"
	ingpg "github.com/titas/soar/backend/internal/ingestion/postgres"
	elasticsource "github.com/titas/soar/backend/internal/ingestion/sources/elastic"
	"github.com/titas/soar/backend/internal/integration"
	"github.com/titas/soar/backend/internal/platform/config"
	"github.com/titas/soar/backend/internal/platform/outbox"
	"github.com/titas/soar/backend/internal/platform/postgres"
	"github.com/titas/soar/backend/internal/platform/telemetry"
	"github.com/titas/soar/backend/internal/rbac"
	"github.com/titas/soar/backend/internal/response"
	responsehttp "github.com/titas/soar/backend/internal/response/http"
	respg "github.com/titas/soar/backend/internal/response/postgres"
)

// healthcheck existe porque a imagem é distroless: não há shell, curl ou wget
// para o HEALTHCHECK do Docker chamar. O binário checa a si mesmo.
var (
	healthcheck = flag.Bool("healthcheck", false,
		"consulta /health/ready no endereço local e sai com 0 ou 1")
	// Em cluster, as migrations rodam num Job antes do rollout: aplicar schema
	// a partir de N réplicas competindo é pedir corrida. É o mesmo binário, e
	// as migrations estão embarcadas nele, então imagem e schema não divergem.
	migrateOnly = flag.Bool("migrate-only", false,
		"aplica as migrations e sai, sem servir")
	// Criar o primeiro usuário precisa de um caminho que não seja uma
	// migration com hash fixo, que vazaria uma credencial no repositório.
	configureSourceSpec = flag.String("configure-source", "",
		"configura uma fonte: slug=<nome>,kind=elastic-siem,mode=pull[,enabled=true][,config.k=v]")
	dryRunSlug = flag.String("dry-run-rule", "",
		"avalia uma regra de pré-processamento contra alertas já ingeridos, sem aplicar nada")
	enableAfterDryRun = flag.Bool("enable", false,
		"com -dry-run-rule: liga a regra depois de registrar o dry-run")
	configureAssetSpec = flag.String("configure-asset", "",
		"configura um asset: integration=<slug>,endpoint=<url>,cred=<env://VAR>[,config.k=v]")
	createUser = flag.String("create-user", "",
		"cria ou atualiza um usuário: email:papel; senha vem de SOAR_BOOTSTRAP_PASSWORD")
)

func main() {
	flag.Parse()
	if *healthcheck {
		os.Exit(probe())
	}
	if *createUser != "" {
		password := os.Getenv("SOAR_BOOTSTRAP_PASSWORD")
		if password == "" {
			slog.Error("criar usuário falhou", "error", "SOAR_BOOTSTRAP_PASSWORD ausente")
			os.Exit(1)
		}
		if err := provisionUser(*createUser, password); err != nil {
			slog.Error("criar usuário falhou", "error", err)
			os.Exit(1)
		}
		return
	}
	if *configureSourceSpec != "" {
		if err := configureSource(*configureSourceSpec); err != nil {
			slog.Error("configurar fonte falhou", "error", err)
			os.Exit(1)
		}
		return
	}
	if *dryRunSlug != "" {
		if err := dryRunRule(*dryRunSlug, *enableAfterDryRun); err != nil {
			slog.Error("dry-run falhou", "error", err)
			os.Exit(1)
		}
		return
	}
	if *configureAssetSpec != "" {
		if err := configureAsset(*configureAssetSpec); err != nil {
			slog.Error("configurar asset falhou", "error", err)
			os.Exit(1)
		}
		return
	}
	if *migrateOnly {
		if err := migrateAndExit(); err != nil {
			slog.Error("migrations falharam", "error", err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func migrateAndExit() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := telemetry.NewLogger(cfg.LogLevel)
	applied, err := postgres.Migrate(cfg.DatabaseURL)
	if err != nil {
		return err
	}
	version, dirty, err := postgres.Version(cfg.DatabaseURL)
	if err != nil {
		return err
	}
	if dirty {
		return fmt.Errorf("schema sujo na versão %d", version)
	}
	log.Info("migrations concluídas", "version", version, "applied", applied)
	return nil
}

func probe() int {
	addr := os.Getenv("SOAR_HTTP_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	if strings.HasPrefix(addr, "0.0.0.0:") {
		addr = "127.0.0.1:" + strings.TrimPrefix(addr, "0.0.0.0:")
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + addr + "/health/ready")
	if err != nil {
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := telemetry.NewLogger(cfg.LogLevel)
	slog.SetDefault(log)

	// Migrations run before the pool opens: serving against a schema we did not
	// expect is worse than not serving.
	applied, err := postgres.Migrate(cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("migrations: %w", err)
	}
	version, dirty, err := postgres.Version(cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("versão do schema: %w", err)
	}
	if dirty {
		return fmt.Errorf("schema sujo na versão %d; corrija antes de subir", version)
	}
	log.Info("schema pronto", "version", version, "applied", applied)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := postgres.NewPool(ctx, cfg.DatabaseURL, cfg.DBMaxConns)
	if err != nil {
		return err
	}
	defer pool.Close()
	log.Info("banco conectado", "max_conns", cfg.DBMaxConns, "profile", cfg.Profile)

	handler, runner, publisher, err := router(ctx, cfg, pool, log)
	if err != nil {
		return err
	}

	// No perfil edge, o barramento é in-process e o dispatcher vive junto da
	// API. O contrato Publisher permite mover o mesmo loop para cmd/worker com
	// NATS/Kafka nos perfis standard/scale sem tocar nos use cases.
	dispatchTx := postgres.NewTxManager(pool)
	dispatcher := outbox.Dispatcher{
		Queue: outbox.New(dispatchTx), Publisher: publisher,
		WorkerID: "api-" + uuid.NewString(), Log: log,
	}
	if cfg.AssessmentEnabled {
		// Dois passes podem ocupar a GPU por vários minutos. A lease deve cobrir
		// ambos para que outro worker não reivindique o mesmo incidente no meio.
		dispatcher.Lease = 2*cfg.OllamaTimeout + time.Minute
	}

	// A ingestão roda junto da API no perfil `edge`. Quando cmd/worker
	// existir, ela se muda para lá sem mudar de código.
	if cfg.IngestEnabled {
		go runner.Run(ctx)
		log.Info("ingestão contínua ativa", "intervalo", cfg.IngestInterval)
	}

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	errCh := make(chan error, 2)
	go func() {
		log.Info("api ouvindo", "addr", cfg.HTTPAddr, "env", cfg.Env)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	go func() {
		if err := dispatcher.Run(ctx); err != nil {
			errCh <- fmt.Errorf("outbox dispatcher: %w", err)
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	// Graceful shutdown: stop accepting, let in-flight requests finish, then
	// close the pool. A pod that drops requests on SIGTERM turns every rolling
	// deploy into a handful of 502s.
	log.Info("encerrando", "wait", cfg.ShutdownWait)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownWait)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	log.Info("encerrado")
	return nil
}

func router(ctx context.Context, cfg config.Config, pool *pgxpool.Pool,
	log *slog.Logger) (http.Handler, *ingestion.Runner, outbox.Publisher, error) {
	mux := http.NewServeMux()

	tx := postgres.NewTxManager(pool)
	repo := incidentpg.New(tx)
	trail := auditpg.New(tx)
	events := outbox.New(tx)
	authSvc := &auth.Service{Repo: authpg.New(tx), Clock: clock.System{}}

	deps := usecase.Deps{
		Tx: tx, Repo: repo, Audit: trail, Outbox: events,
		Perms: rbac.Checker{}, Clock: clock.System{},
	}
	handler := &incidenthttp.Handler{
		List:     &usecase.ListIncidents{Repo: repo, Perms: rbac.Checker{}},
		Get:      &usecase.GetIncident{Repo: repo, Perms: rbac.Checker{}},
		Close:    usecase.CloseIncident{Deps: deps},
		Assign:   usecase.AssignIncident{Deps: deps},
		Reopen:   usecase.ReopenIncident{Deps: deps},
		Timeline: usecase.GetTimeline{Reader: trail, Repo: repo, Perms: rbac.Checker{}},
		Cursor:   pagination.NewSigner(cfg.CursorSecret),
		Log:      log,
	}
	handler.Register(mux)
	(casehttp.Handler{Service: casework.Service{Tx: tx, Incidents: repo, Audit: trail, Perms: rbac.Checker{}}, Log: log}).Register(mux)

	// --- catálogo de ações, aprovação e execução (Fase 2) ---
	assets := respg.NewAssetStore(tx)
	registry, err := loadContentPacks(ctx, cfg.ContentPacks, defaultTenant, assets, log)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("carregar content packs: %w", err)
	}
	approvals := respg.NewApprovalStore(tx)
	runs := respg.NewRunStore(tx)
	executor := &response.Executor{
		Tx: tx, Registry: registry, Assets: assets, Approvals: approvals, Runs: runs,
		Audit: trail, Outbox: events, Perms: rbac.Checker{},
		Creds: integration.NewChainProvider(), Clock: clock.System{},
		ApprovalTTL: cfg.ApprovalTTL,
	}
	approver := &response.Approver{
		Tx: tx, Approvals: approvals, Audit: trail,
		Perms: rbac.Checker{}, Clock: clock.System{},
		// Um operador só: exigir que quem pede não aprove impediria qualquer
		// ação de acontecer. A razão fica registrada, não omitida.
		SelfApprovalForbidden: false,
	}
	(&responsehttp.Handler{
		Executor: executor, Approver: approver, Registry: registry,
		Runs: runs, Log: log,
	}).Register(mux)

	// --- ingestão contínua (Fase 2, F-04) ---
	ruleStore := ingpg.NewRuleStore(tx)
	if err := installRules(ctx, cfg.ContentPacks, defaultTenant, ruleStore, log); err != nil {
		return nil, nil, nil, fmt.Errorf("instalar regras: %w", err)
	}
	pipeline := &ingestion.Pipeline{
		Tx: tx, Raw: ingpg.NewRawStore(tx), Alerts: ingpg.NewAlertStore(tx),
		Incidents: repo, Rules: ruleStore, Audit: trail, Outbox: events,
		Clock:        clock.System{},
		Sources:      map[string]ingestion.Source{"elastic-siem": elasticsource.New()},
		DedupeWindow: cfg.DedupeWindow,
	}
	runner := buildRunner(defaultTenant, tx, pipeline, log, cfg.IngestInterval)

	// --- avaliação local em dois passes (F-11) ---
	assessmentStore := assessmentpg.New(tx)
	var search assessment.Searcher
	if cfg.AssessmentElasticURL != "" {
		search = assessmentelastic.New(cfg.AssessmentElasticURL)
	}
	contextBuilder := &assessment.ContextBuilder{
		Store: assessmentStore, Search: search, BurstGap: 10 * time.Minute,
	}
	assessmentService := &assessment.Service{
		Tx: tx, Repo: assessmentStore, Audit: trail, Outbox: events,
		Perms: rbac.Checker{}, Clock: clock.System{}, Log: log, Context: contextBuilder,
	}
	(&assessmenthttp.Handler{Service: assessmentService, Log: log}).Register(mux)

	publisher := outbox.Publisher(outbox.LoggingPublisher{Log: log})
	if cfg.AssessmentEnabled {
		assessmentService.Generator = &assessment.Generator{
			LLM: assessment.NewOllama(cfg.OllamaURL, cfg.OllamaModel,
				cfg.OllamaNumCtx, cfg.OllamaTimeout),
			Context: contextBuilder,
			Clock:   clock.System{},
		}
		publisher = outbox.TopicPublisher{
			Default: publisher,
			Handlers: map[string]outbox.Handler{
				"incident.created": assessmentService.HandleIncidentCreated,
			},
		}
		log.Info("avaliação local ativa", "model", cfg.OllamaModel,
			"num_ctx", cfg.OllamaNumCtx, "siem_enrichment", search != nil)
	}

	(&authhttp.Handler{
		Service: authSvc, Tenant: defaultTenant, Log: log,
		SecureCookie: cfg.Env != "development",
		Limiter:      authhttp.NewLoginLimiter(5, 25, time.Minute),
	}).Register(mux)

	// Liveness must not depend on anything external. If VirusTotal is down,
	// Kubernetes must not restart this pod.
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, r *http.Request) {
		httpx.OK(w, r, http.StatusOK, map[string]any{"status": "alive"}, nil)
	})

	// Readiness checks what we cannot serve without.
	mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := pool.Ping(ctx); err != nil {
			httpx.OK(w, r, http.StatusServiceUnavailable,
				map[string]any{"status": "not_ready", "database": "unreachable"}, nil)
			return
		}
		httpx.OK(w, r, http.StatusOK,
			map[string]any{"status": "ready", "database": "ok", "profile": cfg.Profile}, nil)
	})

	return httpx.Chain(mux,
		httpx.RequestID,
		httpx.SecurityHeaders,
		httpx.LimitBody(1<<20),
		httpx.Logging(log),
		// Fail closed: tudo exige sessão, exceto a lista curta e explícita
		// abaixo. Saúde fica de fora porque o kubelet não tem cookie.
		authhttp.Middleware(authSvc, log,
			"/health/live", "/health/ready", "/api/v1/auth/login"),
	), runner, publisher, nil
}

// defaultTenant is the single tenant of the `edge` profile. Multi-tenant
// management is not built (docs/soar/07 §4.2); the column exists everywhere so
// that adding it later is a migration, not a rewrite.
var defaultTenant = id.TenantID{
	UUID: uuid.MustParse("00000000-0000-7000-8000-000000000001"),
}

// provisionUser creates or updates a user from the command line, so the first
// credential never has to live as a fixed hash inside a migration.
func provisionUser(spec, password string) error {
	parts := strings.SplitN(spec, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("use email:papel")
	}
	email, role := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	if email == "" || len(email) > 254 {
		return fmt.Errorf("e-mail inválido")
	}
	if len(password) < 12 {
		return fmt.Errorf("senha curta demais: mínimo 12 caracteres")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx := context.Background()
	if _, err := postgres.Migrate(cfg.DatabaseURL); err != nil {
		return fmt.Errorf("aplicar migrations: %w", err)
	}
	pool, err := postgres.NewPool(ctx, cfg.DatabaseURL, 2)
	if err != nil {
		return err
	}
	defer pool.Close()

	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("iniciar transação: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var roleID uuid.UUID
	if err := tx.QueryRow(ctx,
		`SELECT id FROM iam.roles WHERE tenant_id = $1 AND name = $2 AND NOT is_system`,
		defaultTenant.UUID, role).Scan(&roleID); err != nil {
		return fmt.Errorf("papel humano desconhecido %q", role)
	}

	var userID uuid.UUID
	if err := tx.QueryRow(ctx, `
		INSERT INTO iam.users (tenant_id, email, display_name, password_hash)
		VALUES ($1, $2, split_part($2,'@',1), $3)
		ON CONFLICT (tenant_id, email)
		  DO UPDATE SET password_hash = EXCLUDED.password_hash, updated_at = now()
		RETURNING id`, defaultTenant.UUID, email, hash).Scan(&userID); err != nil {
		return fmt.Errorf("gravar usuário: %w", err)
	}
	// O comando expressa o papel desejado, não um papel adicional. Remover os
	// anteriores evita que trocar admin por analyst_l1 preserve privilégios.
	if _, err := tx.Exec(ctx, `DELETE FROM iam.user_roles WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("remover papéis anteriores: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO iam.user_roles (user_id, role_id) VALUES ($1, $2)`, userID, roleID); err != nil {
		return fmt.Errorf("atribuir papel: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("confirmar usuário: %w", err)
	}
	slog.Info("usuário provisionado", "email", email, "role", role, "id", userID)
	return nil
}

var _ = audit.Succeeded
