// Package elastic answers the two questions the platform's own data cannot:
// what else fired on this host, and is this process normal here.
package elastic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/titas/soar/backend/internal/assessment"
)

type Searcher struct {
	URL    string
	Index  string
	client *http.Client
}

func New(url string) *Searcher {
	return &Searcher{
		URL: url, Index: ".alerts-security.alerts-*",
		// Curto de propósito: o contexto é best effort. Um SIEM lento não
		// pode segurar a avaliação; a ausência vira uma linha em `missing`.
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

// RelatedRules is the single most useful piece of context in the whole case:
// one rule firing alone is noise, three rules firing together on one host
// within an hour is a story.
func (s *Searcher) RelatedRules(ctx context.Context, host string,
	from, to time.Time, excludeRule string) ([]assessment.RelatedAlert, error) {

	query := map[string]any{
		"size": 0,
		"query": map[string]any{"bool": map[string]any{
			"filter": []any{
				map[string]any{"term": map[string]any{"host.name": host}},
				map[string]any{"range": map[string]any{"@timestamp": map[string]any{
					"gte": from.UTC().Format(time.RFC3339), "lte": to.UTC().Format(time.RFC3339),
				}}},
			},
			"must_not": []any{
				map[string]any{"term": map[string]any{"kibana.alert.rule.name": excludeRule}},
			},
		}},
		"aggs": map[string]any{"rules": map[string]any{
			"terms": map[string]any{"field": "kibana.alert.rule.name", "size": 8},
			"aggs": map[string]any{"first": map[string]any{
				"min": map[string]any{"field": "@timestamp"},
			}},
		}},
	}
	var parsed struct {
		Aggregations struct {
			Rules struct {
				Buckets []struct {
					Key   string `json:"key"`
					Count int    `json:"doc_count"`
					First struct {
						Value float64 `json:"value"`
					} `json:"first"`
				} `json:"buckets"`
			} `json:"rules"`
		} `json:"aggregations"`
	}
	if err := s.search(ctx, query, &parsed); err != nil {
		return nil, err
	}
	out := make([]assessment.RelatedAlert, 0, len(parsed.Aggregations.Rules.Buckets))
	for _, b := range parsed.Aggregations.Rules.Buckets {
		out = append(out, assessment.RelatedAlert{
			Rule: b.Key, Count: b.Count,
			FirstSeen: time.UnixMilli(int64(b.First.Value)).UTC(),
		})
	}
	return out, nil
}

// ProcessPrevalence answers "is this normal here?". A process seen on one
// host of forty is interesting; the same process on all forty is the
// estate's plumbing — and telling those apart is most of triage.
func (s *Searcher) ProcessPrevalence(ctx context.Context, process string,
	since time.Time) (assessment.Prevalence, error) {

	query := map[string]any{
		"size": 0,
		"query": map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"term": map[string]any{"process.executable": process}},
			map[string]any{"range": map[string]any{"@timestamp": map[string]any{
				"gte": since.UTC().Format(time.RFC3339),
			}}},
		}}},
		"aggs": map[string]any{"hosts": map[string]any{
			"cardinality": map[string]any{"field": "host.name"},
		}},
	}
	var parsed struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
		} `json:"hits"`
		Aggregations struct {
			Hosts struct {
				Value int `json:"value"`
			} `json:"hosts"`
		} `json:"aggregations"`
	}
	if err := s.search(ctx, query, &parsed); err != nil {
		return assessment.Prevalence{}, err
	}
	return assessment.Prevalence{
		Subject: process,
		Hosts:   parsed.Aggregations.Hosts.Value,
		Alerts:  parsed.Hits.Total.Value,
	}, nil
}

func (s *Searcher) search(ctx context.Context, query map[string]any, into any) error {
	return s.searchIndex(ctx, s.Index, query, into)
}

func (s *Searcher) searchIndex(ctx context.Context, index string, query map[string]any, into any) error {
	payload, err := json.Marshal(query)
	if err != nil {
		return err
	}
	url := strings.TrimRight(s.URL, "/") + "/" + index + "/_search"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("Elasticsearch inalcançável: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("Elasticsearch respondeu %d", resp.StatusCode)
	}
	return json.Unmarshal(raw, into)
}
