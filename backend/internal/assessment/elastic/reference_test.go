package elastic

import (
	"fmt"
	"strings"
	"testing"

	"github.com/titas/soar/backend/internal/assessment"
)

func doc(at string, fields map[string]any) map[string]any {
	value := map[string]any{"@timestamp": at}
	for key, item := range fields {
		value[key] = item
	}
	return value
}

func TestReferenceClusterIDMatchesPython(t *testing.T) {
	entity := "/usr/bin/wl-copy"
	got := enrichCluster(assessment.ReferenceCluster{
		RuleName: "Linux Clipboard Activity Detected", Host: "0102",
		EntityKind: "process.executable", Entity: &entity,
	}, nil)
	if got.ClusterID != "cd38bc3a6a44b602" {
		t.Fatalf("cluster id = %s", got.ClusterID)
	}
}

func TestReferenceTimelineCollapsesFilesInOneDirectory(t *testing.T) {
	alerts := make([]map[string]any, 0, 24)
	for index := 0; index < 24; index++ {
		alerts = append(alerts, doc(fmt.Sprintf("2026-09-04T23:49:17.%03dZ", index), map[string]any{
			"event.action": "creation", "file.path": fmt.Sprintf("/usr/lib/app/lib/lib%d.so", index),
		}))
	}
	rows := referenceTimeline(alerts)
	if len(rows) != 1 || rows[0].Count != 24 {
		t.Fatalf("timeline = %#v", rows)
	}
}

func TestReferenceTimelineKeepsSeparateRuns(t *testing.T) {
	rows := referenceTimeline([]map[string]any{
		doc("2026-09-04T23:49:17.000Z", map[string]any{"event.action": "creation", "file.path": "/usr/lib/app/lib/a.so"}),
		doc("2026-09-04T23:49:18.000Z", map[string]any{"event.action": "creation", "file.path": "/usr/lib/app/lib/b.so"}),
		doc("2026-09-17T11:25:53.000Z", map[string]any{"event.action": "creation", "file.path": "/usr/lib/app/lib/a.so"}),
	})
	if len(rows) != 2 || rows[0].Count != 2 || rows[1].Count != 1 {
		t.Fatalf("timeline = %#v", rows)
	}
}

func TestReferenceTimelineGroupsWebRequestsByEmbeddedTarget(t *testing.T) {
	alerts := []map[string]any{}
	for index, endpoint := range []string{"/fetch", "/proxy", "/redirect", "/fetch"} {
		alerts = append(alerts, doc(fmt.Sprintf("2026-09-05T02:50:42.%03dZ", index), map[string]any{
			"url.original": endpoint + "?url=http%3A%2F%2F169.254.169.254%2Flatest%2F",
		}))
	}
	rows := referenceTimeline(alerts)
	if len(rows) != 1 || rows[0].Count != 4 || !strings.HasPrefix(rows[0].Subject, "requests targeting 169.254.169.254") {
		t.Fatalf("timeline = %#v", rows)
	}
}

func TestReferenceTimelineKeepsFirstAndLastEvents(t *testing.T) {
	alerts := make([]map[string]any, 0, 28)
	for day := 1; day <= 28; day++ {
		alerts = append(alerts, doc(fmt.Sprintf("2026-09-%02dT00:00:00Z", day), map[string]any{
			"event.action": fmt.Sprintf("a%d", day), "process.executable": "/bin/x",
		}))
	}
	rows := referenceTimeline(alerts)
	if rows[0].What != "a1" || rows[len(rows)-1].What != "a28" {
		t.Fatalf("lost timeline endpoints: %#v", rows)
	}
	foundEllipsis := false
	for _, row := range rows {
		foundEllipsis = foundEllipsis || row.What == "…"
	}
	if !foundEllipsis {
		t.Fatal("collapsed timeline has no ellipsis")
	}
}

func TestReferenceFileExtensionTreatsVersionedSharedObjectsAsSO(t *testing.T) {
	for _, value := range []string{"/usr/lib/app/libQt5Core.so.5", "/usr/lib/app/libicudata.so.56"} {
		if got := fileExtension(value); got != ".so" {
			t.Fatalf("fileExtension(%q) = %q", value, got)
		}
	}
	if got := fileExtension("/etc/app/config.json"); got != ".json" {
		t.Fatalf("fileExtension(json) = %q", got)
	}
}

func TestHitSourcesDoesNotDropSingleHit(t *testing.T) {
	response := map[string]any{"hits": map[string]any{"hits": []any{
		map[string]any{"_source": map[string]any{"source.ip": "203.0.113.4"}},
	}}}
	if got := hitSources(response); len(got) != 1 {
		t.Fatalf("hitSources(single) = %#v", got)
	}
}
