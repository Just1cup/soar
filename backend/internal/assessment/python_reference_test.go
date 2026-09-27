package assessment

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPythonReferenceEvidenceGolden(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..", "..", "test", "golden", "assessment")
	if _, err := os.Stat(root); os.IsNotExist(err) {
		t.Skip("private assessment corpus is not distributed in the public repository")
	} else if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"endpoint-process", "remote-login"} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var cluster ReferenceCluster
			readGoldenJSON(t, filepath.Join(root, name, "cluster.json"), &cluster)
			var context ReferenceCase
			readGoldenJSON(t, filepath.Join(root, name, "case_context.json"), &context)
			want, err := os.ReadFile(filepath.Join(root, name, "evidence.txt"))
			if err != nil {
				t.Fatal(err)
			}
			got := RenderReferenceEvidence(cluster, context, MaxEvidenceChars)
			if got != string(want) {
				t.Fatalf("Go evidence differs from frozen Python bytes:\n--- Go\n%s\n--- Python\n%s", got, want)
			}
			decisionWant, err := os.ReadFile(filepath.Join(root, name, "decision_evidence.txt"))
			if err != nil {
				t.Fatal(err)
			}
			decisionGot := RenderReferenceDecisionEvidence(cluster, 4500)
			if decisionGot != string(decisionWant) {
				t.Fatalf("Go decision evidence differs from frozen Python bytes:\n--- Go\n%s\n--- Python\n%s", decisionGot, decisionWant)
			}
		})
	}
}

func TestPythonEvaluationCorpusEvidenceGolden(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..", "..", "test", "golden", "assessment-evaluation")
	if _, err := os.Stat(root); os.IsNotExist(err) {
		t.Skip("private assessment evaluation corpus is not distributed in the public repository")
	} else if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		count++
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var cluster ReferenceCluster
			readGoldenJSON(t, filepath.Join(root, name, "cluster.json"), &cluster)
			var context ReferenceCase
			readGoldenJSON(t, filepath.Join(root, name, "case_context.json"), &context)
			assertGoldenText(t, RenderReferenceEvidence(cluster, context, MaxEvidenceChars),
				filepath.Join(root, name, "evidence.txt"))
			assertGoldenText(t, RenderReferenceDecisionEvidence(cluster, 4500),
				filepath.Join(root, name, "decision_evidence.txt"))
		})
	}
	if count != 9 {
		t.Fatalf("evaluation corpus has %d cases, want 9", count)
	}
}

func assertGoldenText(t *testing.T, got, path string) {
	t.Helper()
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("Go output differs from frozen Python bytes in %s:\n--- Go\n%s\n--- Python\n%s", path, got, want)
	}
}

func readGoldenJSON(t *testing.T, path string, into any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}
