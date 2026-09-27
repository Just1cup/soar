// Package elastic pulls alerts from Elastic Security.
//
// It is a PULL connector, which matters: the source keeps the data and we
// own a durable cursor, so a crash costs nothing. The cursor only advances
// after the batch is durably accepted (docs/soar/08 §6.1).
package elastic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/titas/soar/backend/internal/ingestion"
	"github.com/titas/soar/backend/internal/integration"
)

// Entity kinds, ported verbatim from the Python clusterer. They are part of
// the fingerprint material, so renaming one would orphan every incident the
// old console created.
const (
	entitySourceIP = "source.ip"
	entityProcess  = "process.executable"
	entityNone     = "none"
)

type Source struct{ client *http.Client }

func New() *Source {
	return &Source{client: &http.Client{Timeout: 60 * time.Second}}
}

func (s *Source) Kind() string { return "elastic-siem" }

// Fetch implements the XSOAR lastRun model.
//
// The query is INCLUSIVE on last_fetch_time and seen_ids filters what already
// arrived. With `>` alerts sharing a millisecond are lost; with `>=` and no
// filter they are duplicated forever. The timestamp only advances when the
// page is not full — mid-pagination it stays put.
func (s *Source) Fetch(ctx context.Context, cfg map[string]any,
	cursor ingestion.Cursor, maxFetch int) (ingestion.FetchResult, error) {

	elasticURL := str(cfg["elastic_url"])
	if elasticURL == "" {
		return ingestion.FetchResult{}, fmt.Errorf("fonte sem elastic_url")
	}
	index := str(cfg["index"])
	if index == "" {
		index = ".alerts-security.alerts-*"
	}
	if maxFetch <= 0 || maxFetch > 500 {
		// O teto vem da recomendação da própria Palo Alto para fetch: um
		// ciclo sem limite transforma um backlog de uma semana num lote só.
		maxFetch = 200
	}
	from := cursor.LastFetchTime
	if from.IsZero() {
		first := str(cfg["first_fetch"])
		if first == "" {
			first = "24h"
		}
		d, err := time.ParseDuration(first)
		if err != nil {
			d = 24 * time.Hour
		}
		// Sem first_fetch, o primeiro ciclo contra um SIEM com cinco anos de
		// histórico derruba a instalação no dia 1.
		from = time.Now().Add(-d)
	}

	query := map[string]any{
		"size": maxFetch,
		"sort": []any{
			map[string]any{"@timestamp": "asc"},
			map[string]any{"kibana.alert.uuid": "asc"},
		},
		"query": map[string]any{"bool": map[string]any{
			"filter": []any{
				map[string]any{"range": map[string]any{
					"@timestamp": map[string]any{"gte": from.UTC().Format(time.RFC3339Nano)},
				}},
			},
		}},
	}
	raw, err := s.search(ctx, elasticURL, index, str(cfg["auth_ref"]), query)
	if err != nil {
		return ingestion.FetchResult{}, err
	}

	var parsed struct {
		Hits struct {
			Hits []struct {
				ID     string         `json:"_id"`
				Index  string         `json:"_index"`
				Source map[string]any `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return ingestion.FetchResult{}, fmt.Errorf("resposta inesperada: %w", err)
	}

	seen := map[string]bool{}
	for _, s := range cursor.SeenIDs {
		seen[s] = true
	}

	result := ingestion.FetchResult{Next: cursor}
	var newest time.Time
	var newestIDs []string
	for _, hit := range parsed.Hits.Hits {
		external := externalID(hit.Source, hit.ID)
		if seen[external] {
			continue
		}
		ts := timeOf(hit.Source, "@timestamp")
		hit.Source["__index"] = hit.Index
		hit.Source["__id"] = hit.ID
		result.Events = append(result.Events, ingestion.RawEvent{
			ExternalID: external, Payload: hit.Source, EventTime: ts, Mode: "pull",
		})
		switch {
		case ts.After(newest):
			newest, newestIDs = ts, []string{external}
		case ts.Equal(newest):
			// Guarda TODOS os ids do instante mais recente: são exatamente os
			// que o próximo ciclo, sendo inclusivo, veria de novo.
			newestIDs = append(newestIDs, external)
		}
	}

	if !newest.IsZero() {
		result.Next = ingestion.Cursor{LastFetchTime: newest, SeenIDs: newestIDs}
	}
	result.HasMore = len(parsed.Hits.Hits) == maxFetch
	return result, nil
}

func (s *Source) Map(raw ingestion.RawEvent) (*ingestion.Alert, error) {
	p := raw.Payload
	ruleName := str(dig(p, "kibana.alert.rule.name"))
	if ruleName == "" {
		return nil, fmt.Errorf("evento sem kibana.alert.rule.name")
	}
	external := externalID(p, str(p["__id"]))
	if external == "" {
		return nil, fmt.Errorf("evento sem identificador estável")
	}
	kind, entity := chooseEntity(p)
	severity := strings.ToLower(str(dig(p, "kibana.alert.severity")))
	switch severity {
	case "critical", "high", "medium", "low":
	default:
		severity = "medium"
	}
	host := str(dig(p, "host.name"))

	title := str(dig(p, "kibana.alert.reason"))
	if title == "" {
		title = ruleName
		if host != "" {
			title += " — " + host
		}
	}
	return &ingestion.Alert{
		ExternalID: external,
		Title:      truncate(title, 200),
		RuleID:     str(dig(p, "kibana.alert.rule.uuid")),
		RuleName:   ruleName,
		Severity:   severity,
		Host:       host,
		Entity:     entity,
		EntityKind: kind,
		EventTime:  timeOf(p, "@timestamp"),
		Normalized: map[string]any{
			"process": map[string]any{
				"executable": str(dig(p, "process.executable")),
				"name":       str(dig(p, "process.name")),
			},
			"user":        map[string]any{"name": str(dig(p, "user.name"))},
			"source":      map[string]any{"ip": str(dig(p, "source.ip"))},
			"destination": map[string]any{"ip": str(dig(p, "destination.ip"))},
		},
		// Ponteiro, não cópia: o Postgres guarda o que aconteceu e qual é o
		// estado, não trinta milhões de eventos brutos.
		SourceRef: map[string]any{
			"index":      str(p["__index"]),
			"alert_uuid": external,
		},
	}, nil
}

// chooseEntity is ported verbatim: it decides the fingerprint, so changing it
// would re-cluster everything the old console produced.
func chooseEntity(p map[string]any) (kind, entity string) {
	if ip := str(dig(p, "source.ip")); meaningfulRemote(ip) {
		return entitySourceIP, ip
	}
	exe := str(dig(p, "process.executable"))
	if exe == "" {
		exe = str(dig(p, "process.name"))
	}
	if exe != "" {
		return entityProcess, exe
	}
	return entityNone, ""
}

// meaningfulRemote excludes loopback, which on endpoint DNS alerts is the
// systemd-resolved stub (127.0.0.53) or Docker's embedded DNS (127.0.0.11) —
// neither says anything about who was involved.
func meaningfulRemote(address string) bool {
	if address == "" {
		return false
	}
	ip := net.ParseIP(address)
	return ip != nil && !ip.IsLoopback() && !ip.IsUnspecified()
}

func (s *Source) search(ctx context.Context, elasticURL, index, authRef string, body map[string]any) ([]byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	url := strings.TrimRight(elasticURL, "/") + "/" + index + "/_search"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if authRef != "" {
		credential, err := integration.NewChainProvider().Resolve(authRef)
		if err != nil {
			return nil, fmt.Errorf("credencial do Elasticsearch indisponível: %w", err)
		}
		switch {
		case strings.HasPrefix(credential, "ApiKey "), strings.HasPrefix(credential, "Bearer "):
			req.Header.Set("Authorization", credential)
		default:
			user, password, ok := strings.Cut(credential, ":")
			if !ok || user == "" || password == "" {
				return nil, fmt.Errorf("credencial do Elasticsearch deve ser usuário:senha, ApiKey ou Bearer")
			}
			req.SetBasicAuth(user, password)
		}
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Elasticsearch inalcançável: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("Elasticsearch respondeu %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	return raw, nil
}

// dig resolves a dotted path, because Elastic documents mix nested objects
// with flattened dotted keys in the same response.
func dig(m map[string]any, path string) any {
	if v, ok := m[path]; ok {
		return v
	}
	var cur any = m
	for _, part := range strings.Split(path, ".") {
		asMap, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = asMap[part]
		if !ok {
			return nil
		}
	}
	return cur
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		if len(t) > 0 {
			return str(t[0])
		}
	}
	return ""
}

func externalID(p map[string]any, fallback string) string {
	if v := str(dig(p, "kibana.alert.uuid")); v != "" {
		return v
	}
	return fallback
}

func timeOf(p map[string]any, field string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, str(dig(p, field)))
	if err != nil {
		return time.Now().UTC()
	}
	return t
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
