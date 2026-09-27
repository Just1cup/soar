package assessment

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/titas/soar/backend/internal/core/id"
)

// CaseContext is what the analyst — and the model — get to see.
//
// Everything here is built by CODE from telemetry. The model is never asked
// to produce a fact: it is asked to weigh facts. That separation is the
// difference between an assessment and fluent prose, and it is why the
// context is stored alongside the assessment: a later reader can tell whether
// the conclusion was reasonable GIVEN WHAT WAS AVAILABLE.
type CaseContext struct {
	Incident   IncidentFacts  `json:"incident"`
	Timeline   []Burst        `json:"timeline"`
	Entities   Entities       `json:"entities"`
	Related    []RelatedAlert `json:"related_alerts"`
	Prevalence []Prevalence   `json:"prevalence"`
	Actions    []ActionFact   `json:"actions"`
	// Missing names what could NOT be collected. An analyst who does not know
	// what is missing cannot tell a quiet system from a broken collector.
	Missing []string `json:"missing"`
}

type IncidentFacts struct {
	Key        string    `json:"key"`
	Title      string    `json:"title"`
	Rule       string    `json:"rule"`
	Severity   string    `json:"severity"`
	Host       string    `json:"host"`
	AlertCount int       `json:"alert_count"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Window     string    `json:"window"`
	Entity     string    `json:"entity"`
	EntityKind string    `json:"entity_kind"`
	Tactics    []string  `json:"rule_tactics"`
	Techniques []string  `json:"rule_techniques"`
}

// Burst groups alerts that arrived together. Ten alerts in one minute and ten
// spread over a day are different stories, and a flat list hides which one
// this is.
type Burst struct {
	Start  time.Time `json:"start"`
	End    time.Time `json:"end"`
	Count  int       `json:"count"`
	Detail string    `json:"detail"`
}

type Entities struct {
	Hosts     []Counted `json:"hosts"`
	Processes []Counted `json:"processes"`
	Users     []Counted `json:"users"`
	SourceIPs []Counted `json:"source_ips"`
	DestIPs   []Counted `json:"destination_ips"`
}

type Counted struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

// RelatedAlert is a DIFFERENT rule firing on the same host around the same
// time. It is the single most useful piece of context: one rule firing alone
// is noise; three rules firing together on one host within an hour is a
// story.
type RelatedAlert struct {
	Rule      string    `json:"rule"`
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
}

// Prevalence answers "is this normal here?". A process seen on one host of
// forty is interesting; the same process on all forty is the estate's
// plumbing.
type Prevalence struct {
	Subject string `json:"subject"`
	Hosts   int    `json:"hosts"`
	Alerts  int    `json:"alerts"`
}

type ActionFact struct {
	Action   string    `json:"action"`
	Status   string    `json:"status"`
	Affected *int      `json:"affected"`
	Actor    string    `json:"actor"`
	At       time.Time `json:"at"`
}

// ContextBuilder assembles the case from the platform's own data plus
// targeted queries against the SIEM.
type ContextBuilder struct {
	Store  ContextStore
	Search Searcher
	// BurstGap is the silence that separates two bursts. Ten minutes, ported
	// from the Python case builder, where it was chosen by looking at real
	// alert spacing in this environment.
	BurstGap time.Duration
}

type ContextStore interface {
	IncidentFacts(ctx context.Context, tenant id.TenantID, incidentID id.IncidentID) (IncidentFacts, error)
	AlertTimes(ctx context.Context, tenant id.TenantID, incidentID id.IncidentID, limit int) ([]AlertRow, error)
	ActionHistory(ctx context.Context, tenant id.TenantID, incidentID id.IncidentID) ([]ActionFact, error)
}

type AlertRow struct {
	EventTime time.Time
	RuleName  string
	Host      string
	Process   string
	User      string
	SourceIP  string
	DestIP    string
}

// Searcher is the port to the SIEM. It is an interface so the builder is
// testable without Elasticsearch, and so a different SIEM is an adapter.
type Searcher interface {
	RelatedRules(ctx context.Context, host string, from, to time.Time, excludeRule string) ([]RelatedAlert, error)
	ProcessPrevalence(ctx context.Context, process string, since time.Time) (Prevalence, error)
}

// ReferenceCaseSearcher is implemented by adapters capable of reproducing
// the complete Python casebuild contract. The older, two-query Searcher stays
// available only as a degraded fallback while other SIEM adapters migrate.
type ReferenceCaseSearcher interface {
	BuildReferenceCase(ctx context.Context, seed ReferenceCluster) (ReferenceCluster, ReferenceCase)
}

type ReferenceBundle struct {
	Cluster       ReferenceCluster
	Case          ReferenceCase
	IncidentTitle string
}

// BuildReference assembles the exact model input contract frozen under
// test/golden/assessment. Elasticsearch enrichment is best effort by design:
// the adapter returns explicit `missing` entries instead of hiding failures.
func (b *ContextBuilder) BuildReference(ctx context.Context, tenant id.TenantID,
	incidentID id.IncidentID) (*ReferenceBundle, error) {
	facts, err := b.Store.IncidentFacts(ctx, tenant, incidentID)
	if err != nil {
		return nil, fmt.Errorf("fatos do incidente: %w", err)
	}
	rows, err := b.Store.AlertTimes(ctx, tenant, incidentID, 500)
	if err != nil {
		return nil, fmt.Errorf("alertas do incidente: %w", err)
	}

	seed := referenceSeed(facts, rows)
	if search, ok := b.Search.(ReferenceCaseSearcher); ok {
		cluster, c := search.BuildReferenceCase(ctx, seed)
		return &ReferenceBundle{Cluster: cluster, Case: c, IncidentTitle: facts.Title}, nil
	}
	return &ReferenceBundle{
		Cluster: seed, Case: fallbackReferenceCase(seed, rows), IncidentTitle: facts.Title,
	}, nil
}

func referenceSeed(facts IncidentFacts, rows []AlertRow) ReferenceCluster {
	var entity *string
	if facts.Entity != "" {
		value := facts.Entity
		entity = &value
	}
	observables := map[string][]string{}
	add := func(field, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		for _, existing := range observables[field] {
			if existing == value {
				return
			}
		}
		observables[field] = append(observables[field], value)
	}
	for _, row := range rows {
		add("process.executable", row.Process)
		add("user.name", row.User)
		add("source.ip", row.SourceIP)
		add("destination.ip", row.DestIP)
	}
	for _, values := range observables {
		sort.Strings(values)
	}
	samples := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		samples = append(samples, map[string]any{
			"@timestamp": referenceTime(row.EventTime), "host.name": row.Host,
			"process.executable": row.Process, "user.name": row.User,
			"source.ip": row.SourceIP, "destination.ip": row.DestIP,
		})
	}
	if len(samples) > 5 {
		samples = append(samples[:4], samples[len(samples)-1])
	}
	return ReferenceCluster{
		ClusterID: incidentIDForReference(facts.Key), RuleName: facts.Rule,
		Host: facts.Host, EntityKind: facts.EntityKind, Entity: entity,
		Count: facts.AlertCount, FirstSeen: referenceTime(facts.FirstSeen),
		LastSeen: referenceTime(facts.LastSeen), Severity: facts.Severity,
		RuleTactics: facts.Tactics, RuleTechniques: facts.Techniques,
		Observables: observables, Samples: samples,
	}
}

func fallbackReferenceCase(cluster ReferenceCluster, rows []AlertRow) ReferenceCase {
	timeline := make([]ReferenceTimeline, 0, len(rows))
	for _, row := range rows {
		at := referenceTime(row.EventTime)
		subject := firstNonEmpty(row.Process, row.SourceIP, row.DestIP)
		timeline = append(timeline, ReferenceTimeline{
			At: &at, Last: &at, What: "alert", Subject: subject, Count: 1,
		})
	}
	if len(timeline) > 14 {
		timeline = append(append([]ReferenceTimeline{}, timeline[:11]...), timeline[len(timeline)-2:]...)
	}
	entities := countEntities(rows)
	return ReferenceCase{
		Window:    ReferenceWindow{First: cluster.FirstSeen, Last: cluster.LastSeen, Alerts: cluster.Count},
		Collected: []string{},
		Missing: []string{
			"complete SIEM case enrichment unavailable",
		},
		Timeline: timeline, RelatedAlerts: []ReferenceRelated{},
		Prevalence: ReferencePrevalence{}, IOCHits: []ReferenceIOCHit{},
		Entities: ReferenceEntityCounts{
			Hosts: len(entities.Hosts), Users: len(entities.Users), Process: len(entities.Processes),
			IPs: len(entities.SourceIPs) + len(entities.DestIPs),
		},
	}
}

func referenceTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format("2006-01-02T15:04:05.000Z")
}

func incidentIDForReference(key string) string {
	// The Python cluster id is a hash of rule/host/entity. The SOAR incident key
	// is still a stable identifier when an adapter cannot reconstruct that hash;
	// a complete adapter replaces it before inference.
	return key
}

func (b *ContextBuilder) Build(ctx context.Context, tenant id.TenantID, incidentID id.IncidentID) (*CaseContext, error) {
	facts, err := b.Store.IncidentFacts(ctx, tenant, incidentID)
	if err != nil {
		return nil, fmt.Errorf("fatos do incidente: %w", err)
	}
	rows, err := b.Store.AlertTimes(ctx, tenant, incidentID, 500)
	if err != nil {
		return nil, fmt.Errorf("alertas do incidente: %w", err)
	}

	cc := &CaseContext{Incident: facts}
	cc.Incident.Window = humanWindow(facts.FirstSeen, facts.LastSeen)
	cc.Timeline = bursts(rows, b.BurstGap)
	cc.Entities = countEntities(rows)

	if actions, err := b.Store.ActionHistory(ctx, tenant, incidentID); err == nil {
		cc.Actions = actions
	} else {
		cc.Missing = append(cc.Missing, "histórico de ações indisponível")
	}

	// As consultas ao SIEM são best effort: uma delas falhar empobrece o
	// contexto, e isso é dito em `missing` — nunca finge que o silêncio é
	// ausência de atividade.
	if b.Search == nil {
		cc.Missing = append(cc.Missing, "SIEM não consultado: alertas relacionados e prevalência ausentes")
		return cc, nil
	}
	if facts.Host != "" {
		from, to := facts.FirstSeen.Add(-time.Hour), facts.LastSeen.Add(time.Hour)
		related, err := b.Search.RelatedRules(ctx, facts.Host, from, to, facts.Rule)
		if err != nil {
			cc.Missing = append(cc.Missing, "alertas relacionados: "+err.Error())
		} else {
			cc.Related = related
		}
	} else {
		cc.Missing = append(cc.Missing, "incidente sem host: alertas relacionados não consultados")
	}

	for _, p := range top(cc.Entities.Processes, 2) {
		prev, err := b.Search.ProcessPrevalence(ctx, p.Value, facts.FirstSeen.AddDate(0, 0, -30))
		if err != nil {
			cc.Missing = append(cc.Missing, "prevalência de "+p.Value+": "+err.Error())
			continue
		}
		cc.Prevalence = append(cc.Prevalence, prev)
	}
	return cc, nil
}

// bursts groups alerts separated by less than the gap.
func bursts(rows []AlertRow, gap time.Duration) []Burst {
	if len(rows) == 0 {
		return nil
	}
	sorted := append([]AlertRow(nil), rows...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].EventTime.Before(sorted[j].EventTime) })

	var out []Burst
	current := Burst{Start: sorted[0].EventTime, End: sorted[0].EventTime, Count: 1}
	for _, r := range sorted[1:] {
		if r.EventTime.Sub(current.End) <= gap {
			current.End, current.Count = r.EventTime, current.Count+1
			continue
		}
		out = append(out, current)
		current = Burst{Start: r.EventTime, End: r.EventTime, Count: 1}
	}
	out = append(out, current)

	for i := range out {
		out[i].Detail = describeBurst(out[i])
	}
	// Muitas rajadas não cabem no contexto do modelo; as primeiras e as
	// últimas são as informativas — mostram se o comportamento mudou ou
	// apenas se repetiu.
	if len(out) > 12 {
		head := out[:6]
		tail := out[len(out)-6:]
		out = append(append([]Burst{}, head...), tail...)
	}
	return out
}

func describeBurst(b Burst) string {
	span := b.End.Sub(b.Start)
	switch {
	case b.Count == 1:
		return "1 alerta"
	case span < time.Minute:
		return fmt.Sprintf("%d alertas em menos de um minuto", b.Count)
	default:
		return fmt.Sprintf("%d alertas em %s", b.Count, humanDuration(span))
	}
}

func countEntities(rows []AlertRow) Entities {
	hosts, processes, users, srcs, dsts := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	for _, r := range rows {
		bump(hosts, r.Host)
		bump(processes, r.Process)
		bump(users, r.User)
		bump(srcs, r.SourceIP)
		bump(dsts, r.DestIP)
	}
	return Entities{
		Hosts: rank(hosts), Processes: rank(processes), Users: rank(users),
		SourceIPs: rank(srcs), DestIPs: rank(dsts),
	}
}

func bump(m map[string]int, v string) {
	if v = strings.TrimSpace(v); v != "" {
		m[v]++
	}
}

func rank(m map[string]int) []Counted {
	out := make([]Counted, 0, len(m))
	for v, n := range m {
		out = append(out, Counted{Value: v, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Value < out[j].Value
	})
	if len(out) > 6 {
		out = out[:6]
	}
	return out
}

func top(c []Counted, n int) []Counted {
	if len(c) < n {
		return c
	}
	return c[:n]
}

func humanWindow(from, to time.Time) string {
	if from.IsZero() || to.IsZero() {
		return ""
	}
	return humanDuration(to.Sub(from))
}

func humanDuration(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d s", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%.1f h", d.Hours())
	default:
		return fmt.Sprintf("%.1f dias", d.Hours()/24)
	}
}
