package elastic

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/titas/soar/backend/internal/assessment"
)

// This test is intentionally opt-in: it proves the port against retained live
// telemetry, while the ordinary golden tests remain hermetic and deterministic.
func TestLiveReferenceCaseMatchesFrozenPython(t *testing.T) {
	endpoint := os.Getenv("SOAR_ASSESSMENT_ELASTIC_URL")
	if endpoint == "" {
		t.Skip("SOAR_ASSESSMENT_ELASTIC_URL não definido")
	}
	root := filepath.Join("..", "..", "..", "..", "test", "golden", "assessment")
	searcher := New(endpoint)
	for _, name := range []string{"endpoint-process", "remote-login"} {
		t.Run(name, func(t *testing.T) {
			var cluster assessment.ReferenceCluster
			readReferenceJSON(t, filepath.Join(root, name, "cluster.json"), &cluster)
			var want assessment.ReferenceCase
			readReferenceJSON(t, filepath.Join(root, name, "case_context.json"), &want)
			_, got := searcher.BuildReferenceCase(t.Context(), cluster)

			// These sections describe immutable process/file/network facts and
			// must remain exact. Timeline, correlations and prevalence are live
			// queries: late alerts legitimately extend them after the snapshot.
			stableGot, stableWant := got, want
			stableGot.Timeline, stableWant.Timeline = nil, nil
			stableGot.RelatedAlerts, stableWant.RelatedAlerts = nil, nil
			stableGot.Prevalence, stableWant.Prevalence = assessment.ReferencePrevalence{}, assessment.ReferencePrevalence{}
			stableGotJSON, _ := json.Marshal(stableGot)
			stableWantJSON, _ := json.Marshal(stableWant)
			if !bytes.Equal(stableGotJSON, stableWantJSON) {
				gotJSON, _ := json.MarshalIndent(got, "", "  ")
				wantJSON, _ := json.MarshalIndent(want, "", "  ")
				t.Fatalf("stable Go case differs from frozen Python context:\n--- Go\n%s\n--- Python\n%s", gotJSON, wantJSON)
			}
			if !timelinePrefix(got.Timeline, want.Timeline) {
				t.Fatalf("live timeline no longer contains the frozen prefix: got=%#v want=%#v", got.Timeline, want.Timeline)
			}
			if !relatedContains(got.RelatedAlerts, want.RelatedAlerts) {
				t.Fatalf("live correlations lost frozen rules: got=%#v want=%#v", got.RelatedAlerts, want.RelatedAlerts)
			}
			if got.Prevalence.Kind != want.Prevalence.Kind ||
				!atLeast(got.Prevalence.Executions30d, want.Prevalence.Executions30d) ||
				!atLeast(got.Prevalence.AlertsAllRules, want.Prevalence.AlertsAllRules) {
				t.Fatalf("live prevalence regressed: got=%#v want=%#v", got.Prevalence, want.Prevalence)
			}
		})
	}
}

func timelinePrefix(got, want []assessment.ReferenceTimeline) bool {
	if len(got) < len(want) {
		return false
	}
	return reflect.DeepEqual(got[:len(want)], want)
}

func relatedContains(got, want []assessment.ReferenceRelated) bool {
	for _, expected := range want {
		found := false
		for _, actual := range got {
			if actual.Rule == expected.Rule && actual.Count >= expected.Count && reflect.DeepEqual(actual.Severity, expected.Severity) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func atLeast(got, want *int) bool {
	if want == nil {
		return true
	}
	return got != nil && *got >= *want
}

func readReferenceJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, value); err != nil {
		t.Fatal(err)
	}
}
