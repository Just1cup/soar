package elastic

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/titas/soar/backend/internal/ingestion"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestFetchUsesCredentialReference(t *testing.T) {
	t.Setenv("SOAR_TEST_ELASTIC_AUTH", "reader:local-test-password")
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("reader:local-test-password"))
	source := New()
	source.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if got := r.Header.Get("Authorization"); got != want {
			t.Errorf("Authorization=%q, want Basic credential", got)
		}
		if r.URL.Path != "/.alerts-security.alerts-*/_search" {
			t.Errorf("path=%q", r.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"hits":{"hits":[]}}`))}, nil
	})}
	_, err := source.Fetch(context.Background(), map[string]any{
		"elastic_url": "http://elastic.test", "auth_ref": "env://SOAR_TEST_ELASTIC_AUTH",
	}, ingestion.Cursor{}, 20)
	if err != nil {
		t.Fatal(err)
	}
}

func TestFetchRejectsMissingCredentialWithoutSendingRequest(t *testing.T) {
	called := false
	source := New()
	source.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"hits":{"hits":[]}}`))}, nil
	})}
	_, err := source.Fetch(context.Background(), map[string]any{
		"elastic_url": "http://elastic.test", "auth_ref": "env://SOAR_TEST_MISSING_AUTH",
	}, ingestion.Cursor{}, 20)
	if err == nil || called {
		t.Fatalf("missing credential: err=%v, request sent=%v", err, called)
	}
}
