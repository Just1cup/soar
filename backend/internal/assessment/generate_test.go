package assessment

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/titas/soar/backend/internal/core/clock"
	"github.com/titas/soar/backend/internal/core/id"
)

func TestGenerateReferenceKeepsDecisionWhenInvestigationFails(t *testing.T) {
	responses := []modelResponse{
		{content: `{"verdict":"benign_true_positive","source_reliability":"A","info_credibility":"4","title":"decision","summary":"short","reasoning":"because"}`, tokens: 11},
		{status: http.StatusInternalServerError},
	}
	generator := testGenerator(t, responses)

	got, err := generator.GenerateReference(context.Background(), id.TenantID{}, id.IncidentID{}, testBundle())
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != BenignTruePositive || got.Title != "decision" {
		t.Fatalf("decision fallback lost: %#v", got)
	}
	if got.SourceReliability != "A" || got.InfoCredibility != "4" || got.PromptTokens != 11 {
		t.Fatalf("decision metadata lost: %#v", got)
	}
	if got.CaseContext == nil || got.Body.InvestigationVerdict != "" {
		t.Fatalf("fallback must retain case context without inventing an investigation: %#v", got)
	}
}

func TestGenerateReferenceUsesInvestigationWhenDecisionFails(t *testing.T) {
	responses := []modelResponse{
		{status: http.StatusInternalServerError},
		{content: `{"title":"case","summary":"long","behaviour_occurred":true,"favoured_hypothesis":"suspicious","confidence":"medium","source_reliability":"B","info_credibility":"2","attack_techniques":["T1190"],"diamond":{"adversary":null,"capability":"probe","infrastructure":"203.0.113.2","victim":"host"}}`, tokens: 23},
	}
	generator := testGenerator(t, responses)

	got, err := generator.GenerateReference(context.Background(), id.TenantID{}, id.IncidentID{}, testBundle())
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != TruePositive || got.Body.InvestigationVerdict != TruePositive {
		t.Fatalf("investigation verdict not derived: %#v", got)
	}
	if got.SourceReliability != "B" || got.InfoCredibility != "2" || got.PromptTokens != 23 {
		t.Fatalf("investigation metadata lost: %#v", got)
	}
}

func TestGenerateReferenceFailsOnlyWhenBothPassesFail(t *testing.T) {
	generator := testGenerator(t, []modelResponse{
		{status: http.StatusInternalServerError},
		{status: http.StatusInternalServerError},
	})
	if _, err := generator.GenerateReference(context.Background(), id.TenantID{}, id.IncidentID{}, testBundle()); err == nil {
		t.Fatal("expected both model failures to be returned")
	}
}

type modelResponse struct {
	status  int
	content string
	tokens  int
}

func testGenerator(t *testing.T, responses []modelResponse) *Generator {
	t.Helper()
	call := 0
	client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		if call >= len(responses) {
			t.Errorf("unexpected model call %d", call+1)
			return httpResponse(http.StatusInternalServerError, "unexpected"), nil
		}
		response := responses[call]
		call++
		if response.status >= 400 {
			return httpResponse(response.status, "model failure"), nil
		}
		raw, err := json.Marshal(map[string]any{
			"message":           map[string]any{"content": response.content},
			"prompt_eval_count": response.tokens,
			"done":              true,
		})
		if err != nil {
			return nil, err
		}
		return httpResponse(http.StatusOK, string(raw)), nil
	})}
	fixed := &clock.Fixed{T: time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)}
	llm := NewOllama("http://ollama.invalid", "test-model", 8192, time.Second)
	llm.client = client
	return &Generator{
		LLM:   llm,
		Clock: fixed,
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func httpResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func testBundle() *ReferenceBundle {
	entity := "203.0.113.2"
	return &ReferenceBundle{
		Cluster: ReferenceCluster{
			ClusterID: "case", RuleName: "rule", Host: "host",
			EntityKind: "source.ip", Entity: &entity, Count: 1,
			FirstSeen: "2026-09-21T10:00:00Z", LastSeen: "2026-09-21T10:00:00Z",
			Severity: "high",
		},
		Case: ReferenceCase{
			Window:   ReferenceWindow{First: "2026-09-21T10:00:00Z", Last: "2026-09-21T10:00:00Z", Alerts: 1},
			Timeline: []ReferenceTimeline{}, RelatedAlerts: []ReferenceRelated{},
			Prevalence: ReferencePrevalence{}, IOCHits: []ReferenceIOCHit{},
		},
		IncidentTitle: "rule",
	}
}
