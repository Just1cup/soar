package legacyimport

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/titas/soar/backend/internal/platform/postgres"
)

func TestRunIsIdempotent(t *testing.T) {
	if os.Getenv("SOAR_INTEGRATION_TEST") != "1" {
		t.Skip("set SOAR_INTEGRATION_TEST=1 against a disposable PostgreSQL")
	}
	databaseURL := os.Getenv("SOAR_DATABASE_URL")
	if _, err := postgres.Migrate(databaseURL); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	pool, err := postgres.NewPool(ctx, databaseURL, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	dir := t.TempDir()
	cluster := fmt.Sprintf("%016x", uuid.New().ID())
	assessments := filepath.Join(dir, "assessments.json")
	cases := filepath.Join(dir, "cases.json")
	labels := filepath.Join(dir, "labels.json")
	mustWrite(t, assessments, fmt.Sprintf(`[{
		"cluster_id":%q,"title":"Caso legado","summary":"Resumo","verdict":"inconclusive",
		"attack_tactics":[],"attack_techniques":[],"case_context":{"window":{
		"first":"2026-09-20T10:00:00Z","last":"2026-09-20T11:00:00Z","alerts":2}}}]`, cluster))
	mustWrite(t, cases, fmt.Sprintf(`{%q:{"status":"closed","updated_at":"2026-09-20T12:00:00Z","notes":"revisado","actions":[]}}`, cluster))
	mustWrite(t, labels, fmt.Sprintf(`{%q:{"verdict":"false_positive","notes":"","attack_techniques":[]}}`, cluster))
	files := Files{Assessments: assessments, Cases: cases, Labels: labels}
	tenant := uuid.MustParse("00000000-0000-7000-8000-000000000001")

	first, err := Run(ctx, pool, tenant, files)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Run(ctx, pool, tenant, files)
	if err != nil {
		t.Fatal(err)
	}
	if first.Imported != 1 || second.Imported != 0 || second.Existing != 1 {
		t.Fatalf("primeira=%+v segunda=%+v", first, second)
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
