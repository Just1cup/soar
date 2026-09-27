// Command assessment-eval replays frozen Python case inputs through the exact
// production Go generator and writes a harness-compatible candidate artifact.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/titas/soar/backend/internal/assessment"
	"github.com/titas/soar/backend/internal/core/clock"
	"github.com/titas/soar/backend/internal/core/id"
)

type candidate struct {
	ClusterID        string             `json:"cluster_id"`
	Verdict          assessment.Verdict `json:"verdict"`
	AttackTechniques []string           `json:"attack_techniques"`
	Diamond          assessment.Diamond `json:"diamond"`
	LatencyMS        int                `json:"latency_ms"`
	PromptTokens     int                `json:"prompt_tokens"`
	Model            string             `json:"model"`
	GeneratedAt      string             `json:"generated_at"`
}

func main() {
	fixtures := flag.String("fixtures", "../test/golden/assessment-evaluation", "diretório do corpus congelado")
	output := flag.String("output", "", "arquivo JSON de saída (obrigatório)")
	ollamaURL := flag.String("ollama-url", envOr("OLLAMA_URL", "http://127.0.0.1:11434"), "URL do Ollama")
	model := flag.String("model", envOr("OLLAMA_MODEL", "qwen3:8b"), "modelo Ollama")
	numCtx := flag.Int("num-ctx", envInt("OLLAMA_NUM_CTX", 8192), "janela de contexto")
	timeout := flag.Duration("timeout", 420*time.Second, "timeout por chamada")
	flag.Parse()
	if *output == "" {
		fatal(errors.New("-output é obrigatório"))
	}

	dirs, err := fixtureDirs(*fixtures)
	if err != nil {
		fatal(err)
	}
	llm := assessment.NewOllama(*ollamaURL, *model, *numCtx, *timeout)
	generator := &assessment.Generator{LLM: llm, Clock: clock.System{}}
	results := make([]candidate, 0, len(dirs))
	for index, dir := range dirs {
		bundle, err := loadBundle(dir)
		if err != nil {
			fatal(err)
		}
		fmt.Fprintf(os.Stderr, "[%d/%d] %s\n", index+1, len(dirs), bundle.Cluster.ClusterID)
		result, err := generator.GenerateReference(context.Background(), id.TenantID{}, id.IncidentID{}, bundle)
		if err != nil {
			fatal(fmt.Errorf("%s: %w", bundle.Cluster.ClusterID, err))
		}
		results = append(results, candidate{
			ClusterID: bundle.Cluster.ClusterID, Verdict: result.Verdict,
			AttackTechniques: result.AttackTechniques, Diamond: result.Body.Diamond,
			LatencyMS: result.LatencyMS, PromptTokens: result.PromptTokens,
			Model: result.Model, GeneratedAt: result.GeneratedAt.Format(time.RFC3339),
		})
	}
	if err := writeAtomic(*output, results); err != nil {
		fatal(err)
	}
	fmt.Fprintf(os.Stderr, "wrote %d assessments to %s\n", len(results), *output)
}

func fixtureDirs(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var dirs []string
	for _, entry := range entries {
		if entry.IsDir() {
			dir := filepath.Join(root, entry.Name())
			if _, err := os.Stat(filepath.Join(dir, "cluster.json")); err == nil {
				dirs = append(dirs, dir)
			}
		}
	}
	sort.Strings(dirs)
	if len(dirs) == 0 {
		return nil, fmt.Errorf("nenhum fixture encontrado em %s", root)
	}
	return dirs, nil
}

func loadBundle(dir string) (*assessment.ReferenceBundle, error) {
	var cluster assessment.ReferenceCluster
	if err := readJSON(filepath.Join(dir, "cluster.json"), &cluster); err != nil {
		return nil, err
	}
	var caseContext assessment.ReferenceCase
	if err := readJSON(filepath.Join(dir, "case_context.json"), &caseContext); err != nil {
		return nil, err
	}
	return &assessment.ReferenceBundle{
		Cluster: cluster, Case: caseContext, IncidentTitle: cluster.RuleName,
	}, nil
}

func readJSON(path string, target any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

func writeAtomic(path string, value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".assessment-eval-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envInt(name string, fallback int) int {
	value, err := strconv.Atoi(os.Getenv(name))
	if err == nil && value > 0 {
		return value
	}
	return fallback
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "assessment-eval:", err)
	os.Exit(1)
}
