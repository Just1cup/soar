package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/google/uuid"
	"github.com/titas/soar/backend/internal/legacyimport"
	"github.com/titas/soar/backend/internal/platform/config"
	"github.com/titas/soar/backend/internal/platform/postgres"
)

func main() {
	assessments := flag.String("assessments", "", "caminho de assessments.json")
	cases := flag.String("cases", "", "caminho de cases.json")
	labels := flag.String("labels", "", "caminho de labels.json")
	flag.Parse()
	if *assessments == "" || *cases == "" || *labels == "" {
		fmt.Fprintln(os.Stderr, "--assessments, --cases e --labels são obrigatórios")
		os.Exit(2)
	}
	cfg, err := config.Load()
	if err != nil {
		slog.Error("configuração", "error", err)
		os.Exit(1)
	}
	if _, err := postgres.Migrate(cfg.DatabaseURL); err != nil {
		slog.Error("migrations", "error", err)
		os.Exit(1)
	}
	ctx := context.Background()
	pool, err := postgres.NewPool(ctx, cfg.DatabaseURL, 2)
	if err != nil {
		slog.Error("banco", "error", err)
		os.Exit(1)
	}
	defer pool.Close()
	report, err := legacyimport.Run(ctx, pool,
		uuid.MustParse("00000000-0000-7000-8000-000000000001"),
		legacyimport.Files{Assessments: *assessments, Cases: *cases, Labels: *labels})
	if err != nil {
		slog.Error("importação", "error", err)
		os.Exit(1)
	}
	slog.Info("importação concluída", "lidos", report.Read, "importados", report.Imported, "existentes", report.Existing)
}
