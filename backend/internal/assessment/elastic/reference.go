package elastic

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/titas/soar/backend/internal/assessment"
)

const (
	processEvents = "logs-endpoint.events.process-*"
	fileEvents    = "logs-endpoint.events.file-*"
	networkEvents = "logs-endpoint.events.network-*"
	threatIndices = "logs-ti_*"
	maxTimeline   = 14
)

var observableFields = []string{
	"source.ip", "destination.ip", "destination.domain", "dns.question.name",
	"url.original", "url.path", "http.request.method", "http.response.status_code",
	"process.executable", "process.command_line", "process.parent.executable",
	"user.name", "file.path",
}

// BuildReferenceCase ports ioc_engine.report.casebuild. Every query is best
// effort: partial telemetry is returned with explicit collection gaps rather
// than turning a useful assessment into an outbox retry loop.
func (s *Searcher) BuildReferenceCase(ctx context.Context,
	seed assessment.ReferenceCluster) (assessment.ReferenceCluster, assessment.ReferenceCase) {
	c := assessment.ReferenceCase{
		Window:    assessment.ReferenceWindow{First: seed.FirstSeen, Last: seed.LastSeen, Alerts: seed.Count},
		Collected: []string{}, Missing: []string{}, Timeline: []assessment.ReferenceTimeline{},
		RelatedAlerts: []assessment.ReferenceRelated{}, IOCHits: []assessment.ReferenceIOCHit{},
	}
	alerts, err := s.clusterAlerts(ctx, seed)
	if err != nil {
		alerts = append([]map[string]any(nil), seed.Samples...)
		c.Missing = append(c.Missing, "cluster alerts unavailable from the SIEM")
	}
	seed = enrichCluster(seed, alerts)
	c.Window = assessment.ReferenceWindow{First: seed.FirstSeen, Last: seed.LastSeen, Alerts: seed.Count}
	c.Timeline = referenceTimeline(alerts)

	entityIDs := distinct(alerts, "process.entity_id")
	if len(entityIDs) > 3 {
		entityIDs = entityIDs[:3]
	}
	if seed.EntityKind == "process.executable" || len(entityIDs) > 0 {
		c.ProcessChain = s.processChain(ctx, alerts, &c)
		c.Files = s.files(ctx, alerts, entityIDs, &c)
		c.Network = s.network(ctx, entityIDs, &c)
	}
	if seed.EntityKind == "source.ip" {
		web := referenceWeb(alerts)
		c.Web = &web
	}
	c.RelatedAlerts = s.relatedAlerts(ctx, seed, c.Timeline, &c)
	c.Prevalence = s.prevalence(ctx, seed, &c)
	c.IOCHits = s.iocHits(ctx, alerts, &c)
	c.Entities = referenceEntities(alerts, c)
	return seed, c
}

func (s *Searcher) clusterAlerts(ctx context.Context, cluster assessment.ReferenceCluster) ([]map[string]any, error) {
	filters := []any{map[string]any{"term": map[string]any{"kibana.alert.rule.name": cluster.RuleName}}}
	if cluster.Host != "" && cluster.Host != "unknown host" {
		filters = append(filters, map[string]any{"term": map[string]any{"host.name": cluster.Host}})
	}
	if cluster.Entity != nil && *cluster.Entity != "" {
		switch cluster.EntityKind {
		case "source.ip":
			filters = append(filters, map[string]any{"term": map[string]any{"source.ip": *cluster.Entity}})
		case "process.executable":
			filters = append(filters, map[string]any{"bool": map[string]any{
				"should": []any{
					map[string]any{"term": map[string]any{"process.executable": *cluster.Entity}},
					map[string]any{"term": map[string]any{"process.name": *cluster.Entity}},
				}, "minimum_should_match": 1,
			}})
		}
	}
	body := map[string]any{
		"size": 200, "query": map[string]any{"bool": map[string]any{"filter": filters}},
		"sort": []any{map[string]any{"@timestamp": "asc"}},
		"_source": append([]string{
			"@timestamp", "host.name", "user.name", "event.action", "event.outcome",
			"process.executable", "process.name", "process.entity_id", "process.command_line",
			"process.args", "process.parent.executable", "process.parent.entity_id",
			"file.path", "file.hash.sha256", "source.ip", "destination.ip",
			"destination.domain", "dns.question.name", "url.original", "url.path",
			"http.response.status_code", "http.request.method", "kibana.alert.severity",
			"kibana.alert.risk_score", "kibana.alert.rule.threat",
		}, "rule.id", "rule.name"),
	}
	response, err := s.searchMap(ctx, s.Index, body)
	if err != nil {
		return nil, err
	}
	return hitSources(response), nil
}

func enrichCluster(cluster assessment.ReferenceCluster, alerts []map[string]any) assessment.ReferenceCluster {
	if cluster.EntityKind == "" {
		cluster.EntityKind = "none"
	}
	materialEntity := "None"
	if cluster.Entity != nil {
		materialEntity = *cluster.Entity
	}
	digest := sha256.Sum256([]byte(strings.Join([]string{
		cluster.RuleName, cluster.Host, cluster.EntityKind, materialEntity,
	}, "|")))
	cluster.ClusterID = fmt.Sprintf("%x", digest[:8])
	if len(alerts) == 0 {
		return cluster
	}
	if value := stringValue(get(alerts[0], "kibana.alert.severity")); value != "" {
		cluster.Severity = value
	}
	for _, alert := range alerts {
		if value, ok := number(get(alert, "kibana.alert.risk_score")); ok {
			value := int(value)
			if cluster.RiskScore == nil || value > *cluster.RiskScore {
				cluster.RiskScore = &value
			}
		}
	}
	if len(cluster.Observables) == 0 {
		cluster.Observables = map[string][]string{}
		for _, field := range observableFields {
			values := distinct(alerts, field)
			sort.Strings(values)
			if len(values) > 12 {
				values = values[:12]
			}
			if len(values) > 0 {
				cluster.Observables[field] = values
			}
		}
	}
	if len(cluster.Samples) == 0 {
		cluster.Samples = sampleAlerts(alerts, 5)
	}
	tactics, techniques := threatMappings(alerts)
	if len(tactics) > 0 {
		cluster.RuleTactics = tactics
	}
	if len(techniques) > 0 {
		cluster.RuleTechniques = techniques
	}
	return cluster
}

func sampleAlerts(alerts []map[string]any, limit int) []map[string]any {
	if len(alerts) <= limit {
		return append([]map[string]any(nil), alerts...)
	}
	out := append([]map[string]any(nil), alerts[:limit-1]...)
	return append(out, alerts[len(alerts)-1])
}

func threatMappings(alerts []map[string]any) ([]string, []string) {
	tactics, techniques := map[string]struct{}{}, map[string]struct{}{}
	for _, alert := range alerts {
		values := asObjects(rawGet(alert, "kibana.alert.rule.threat"))
		for _, threat := range values {
			if tactic, ok := rawGet(threat, "tactic").(map[string]any); ok {
				addMapping(tactics, tactic)
			}
			for _, technique := range asObjects(rawGet(threat, "technique")) {
				addMapping(techniques, technique)
				for _, sub := range asObjects(rawGet(technique, "subtechnique")) {
					addMapping(techniques, sub)
				}
			}
		}
	}
	return sortedSet(tactics), sortedSet(techniques)
}

func addMapping(target map[string]struct{}, value map[string]any) {
	id, name := stringValue(rawGet(value, "id")), stringValue(rawGet(value, "name"))
	if id == "" {
		return
	}
	if name != "" {
		id += ":" + name
	}
	target[id] = struct{}{}
}

type timelineWork struct {
	row   assessment.ReferenceTimeline
	key   string
	items []string
}

func referenceTimeline(alerts []map[string]any) []assessment.ReferenceTimeline {
	work := make([]timelineWork, 0, len(alerts))
	for _, alert := range alerts {
		what := pythonString(get(alert, "event.action"))
		if what == "" {
			what = "alert"
		}
		key, subject, item := activity(alert)
		atValue := stringValue(get(alert, "@timestamp"))
		var at *string
		if atValue != "" {
			value := atValue
			at = &value
		}
		if len(work) > 0 {
			last := &work[len(work)-1]
			if last.row.What == what && last.key == key && timeGap(last.row.Last, at) <= 10*time.Minute {
				last.row.Count++
				last.row.Last = at
				if item != "" && !contains(last.items, item) && len(last.items) < 4 {
					last.items = append(last.items, item)
				}
				continue
			}
		}
		items := []string{}
		if item != "" {
			items = append(items, item)
		}
		work = append(work, timelineWork{key: key, items: items, row: assessment.ReferenceTimeline{
			At: at, Last: at, What: what, Subject: subject, Count: 1,
			Outcome: get(alert, "event.outcome"), Status: get(alert, "http.response.status_code"),
		}})
	}
	rows := make([]assessment.ReferenceTimeline, 0, len(work))
	for _, item := range work {
		if len(item.items) > 0 && item.row.Count > 1 {
			more := ""
			if item.row.Count > len(item.items) {
				more = "…"
			}
			item.row.Subject += " (" + strings.Join(item.items, ", ") + more + ")"
		}
		rows = append(rows, item.row)
	}
	if len(rows) > maxTimeline {
		skipped := 0
		for _, row := range rows[maxTimeline-3 : len(rows)-2] {
			skipped += row.Count
		}
		collapsed := assessment.ReferenceTimeline{What: "…", Subject: fmt.Sprintf("%d more events", skipped), Count: skipped}
		rows = append(append(append([]assessment.ReferenceTimeline{}, rows[:maxTimeline-3]...), collapsed), rows[len(rows)-2:]...)
	}
	return rows
}

func activity(alert map[string]any) (string, string, string) {
	if value := stringValue(get(alert, "file.path")); value != "" {
		directory := path.Dir(value) + "/"
		return "file:" + directory, directory, path.Base(value)
	}
	if value := stringValue(get(alert, "url.original")); value != "" {
		decoded, err := url.PathUnescape(value)
		if err != nil {
			decoded = value
		}
		parts, _ := url.Parse(decoded)
		for _, pair := range strings.Split(parts.RawQuery, "&") {
			_, encoded, found := strings.Cut(pair, "=")
			if !found {
				continue
			}
			value, err := url.QueryUnescape(encoded)
			if err != nil {
				continue
			}
			inner, _ := url.Parse(value)
			if inner.Hostname() != "" {
				return "url-target:" + inner.Hostname(), "requests targeting " + inner.Hostname() + " via", parts.Path
			}
		}
		return "url:" + parts.Path, parts.Path, ""
	}
	for _, field := range []string{"dns.question.name", "destination.ip"} {
		if value := stringValue(get(alert, field)); value != "" {
			return field + ":" + value, value, ""
		}
	}
	subject := stringValue(get(alert, "process.command_line"))
	if subject == "" {
		subject = stringValue(get(alert, "process.executable"))
	}
	if len([]rune(subject)) > 160 {
		subject = string([]rune(subject)[:160])
	}
	return "proc:" + subject, subject, ""
}

func (s *Searcher) processChain(ctx context.Context, alerts []map[string]any,
	c *assessment.ReferenceCase) []assessment.ReferenceProcess {
	first := map[string]any{}
	if len(alerts) > 0 {
		first = alerts[0]
	}
	process := assessment.ReferenceProcess{
		Level: "process", Executable: stringPointer(get(first, "process.executable")),
		CommandLine: stringPointer(firstValue(get(first, "process.command_line"), args(first))),
		User:        stringPointer(get(first, "user.name")), Source: "alert",
	}
	parentExe := stringPointer(get(first, "process.parent.executable"))
	parent := assessment.ReferenceProcess{Level: "parent", Executable: parentExe, Source: "unknown"}
	if parentExe != nil {
		parent.Source = "alert"
	}
	grandparent := assessment.ReferenceProcess{Level: "grandparent", Source: "unknown"}
	parentID := stringValue(get(first, "process.parent.entity_id"))
	if parentID == "" {
		c.Missing = append(c.Missing, "parent entity id absent from the alert")
		return []assessment.ReferenceProcess{grandparent, parent, process}
	}
	event, err := s.processStart(ctx, parentID)
	if err != nil || event == nil {
		c.Missing = append(c.Missing, "parent process start event not in retained telemetry")
		return []assessment.ReferenceProcess{grandparent, parent, process}
	}
	c.Collected = append(c.Collected, "parent process start event")
	if parent.Executable == nil {
		parent.Executable = stringPointer(get(event, "process.executable"))
	}
	parent.CommandLine = stringPointer(firstValue(get(event, "process.command_line"), args(event)))
	parent.User = stringPointer(get(event, "user.name"))
	parent.Source = "process events"
	grandparent.Executable = stringPointer(get(event, "process.parent.executable"))
	if grandparent.Executable != nil {
		grandparent.Source = "process events"
	}
	return []assessment.ReferenceProcess{grandparent, parent, process}
}

func (s *Searcher) processStart(ctx context.Context, entityID string) (map[string]any, error) {
	response, err := s.searchMap(ctx, processEvents, map[string]any{
		"size":    1,
		"query":   map[string]any{"bool": map[string]any{"filter": []any{map[string]any{"term": map[string]any{"process.entity_id": entityID}}}}},
		"sort":    []any{map[string]any{"@timestamp": "asc"}},
		"_source": []string{"process.executable", "process.command_line", "process.args", "process.parent.executable", "user.name"},
	})
	if err != nil {
		return nil, err
	}
	hits := hitSources(response)
	if len(hits) == 0 {
		return nil, nil
	}
	return hits[0], nil
}

func (s *Searcher) files(ctx context.Context, alerts []map[string]any, entityIDs []string,
	c *assessment.ReferenceCase) *assessment.ReferenceFiles {
	paths, hashes := distinct(alerts, "file.path"), distinct(alerts, "file.hash.sha256")
	var events *int
	actions := assessment.ReferenceCounts{}
	if len(entityIDs) > 0 {
		response, err := s.searchMap(ctx, fileEvents, map[string]any{
			"size":  0,
			"query": map[string]any{"bool": map[string]any{"filter": []any{map[string]any{"terms": map[string]any{"process.entity_id": entityIDs}}}}},
			"aggs": map[string]any{
				"paths":   map[string]any{"terms": map[string]any{"field": "file.path", "size": 12}},
				"actions": map[string]any{"terms": map[string]any{"field": "event.action", "size": 6}},
				"hashes":  map[string]any{"terms": map[string]any{"field": "file.hash.sha256", "size": 5}},
			},
		})
		if err == nil {
			value := totalHits(response)
			events = &value
			paths = merge(paths, bucketKeys(buckets(response, "aggregations.paths.buckets")))
			hashes = merge(hashes, bucketKeys(buckets(response, "aggregations.hashes.buckets")))
			actions = bucketCounts(buckets(response, "aggregations.actions.buckets"))
			c.Collected = append(c.Collected, "file events of the process")
		}
	}
	if len(hashes) == 0 && len(paths) > 0 {
		c.Missing = append(c.Missing, "file hashes (SHA256) not present in telemetry")
	}
	directories := uniqueStrings(nil)
	extensions := assessment.ReferenceCounts{}
	extensionIndex := map[string]int{}
	for _, value := range paths {
		directories = appendUnique(directories, path.Dir(value))
		extension := fileExtension(value)
		if index, ok := extensionIndex[extension]; ok {
			extensions[index].Count++
		} else {
			extensionIndex[extension] = len(extensions)
			extensions = append(extensions, assessment.ReferenceCount{Key: extension, Count: 1})
		}
	}
	sort.Strings(directories)
	sort.SliceStable(extensions, func(i, j int) bool { return extensions[i].Count > extensions[j].Count })
	return &assessment.ReferenceFiles{
		Events: events, Actions: actions, Paths: limitStrings(paths, 10), Count: len(paths),
		Directories: limitStrings(directories, 6), Extensions: limitCounts(extensions, 5), Hashes: limitStrings(hashes, 5),
	}
}

func (s *Searcher) network(ctx context.Context, entityIDs []string,
	c *assessment.ReferenceCase) *assessment.ReferenceNetwork {
	if len(entityIDs) == 0 {
		return nil
	}
	response, err := s.searchMap(ctx, networkEvents, map[string]any{
		"size":  0,
		"query": map[string]any{"bool": map[string]any{"filter": []any{map[string]any{"terms": map[string]any{"process.entity_id": entityIDs}}}}},
		"aggs": map[string]any{
			"dest":   map[string]any{"terms": map[string]any{"field": "destination.ip", "size": 6}, "aggs": map[string]any{"port": map[string]any{"terms": map[string]any{"field": "destination.port", "size": 1}}}},
			"domain": map[string]any{"terms": map[string]any{"field": "destination.domain", "size": 6}},
		},
	})
	if err != nil {
		c.Missing = append(c.Missing, "network events of the process unavailable")
		return nil
	}
	c.Collected = append(c.Collected, "network events of the process")
	destinations := []assessment.ReferenceDestination{}
	for _, bucket := range buckets(response, "aggregations.dest.buckets") {
		var port any
		if ports, ok := rawGet(bucket, "port.buckets").([]any); ok && len(ports) > 0 {
			if first, ok := ports[0].(map[string]any); ok {
				port = rawGet(first, "key")
			}
		}
		destinations = append(destinations, assessment.ReferenceDestination{
			IP: stringValue(rawGet(bucket, "key")), Count: intNumber(rawGet(bucket, "doc_count")), Port: port,
		})
	}
	return &assessment.ReferenceNetwork{
		Events: totalHits(response), Destinations: destinations,
		Domains: bucketKeys(buckets(response, "aggregations.domain.buckets")),
	}
}

func referenceWeb(alerts []map[string]any) assessment.ReferenceWeb {
	return assessment.ReferenceWeb{
		URLs:     limitStrings(distinct(alerts, "url.original"), 8),
		Statuses: countedValues(alerts, "http.response.status_code", 5),
		Methods:  countedValues(alerts, "http.request.method", 3),
	}
}

func (s *Searcher) relatedAlerts(ctx context.Context, cluster assessment.ReferenceCluster,
	timeline []assessment.ReferenceTimeline, c *assessment.ReferenceCase) []assessment.ReferenceRelated {
	if cluster.Host == "" || cluster.Host == "unknown host" || cluster.FirstSeen == "" {
		return []assessment.ReferenceRelated{}
	}
	times := []string{}
	for _, row := range timeline {
		if row.At != nil && *row.At != "" {
			times = appendUnique(times, *row.At)
			if len(times) == 6 {
				break
			}
		}
	}
	if len(times) == 0 {
		times = append(times, cluster.FirstSeen)
	}
	sort.Strings(times)
	windows := make([]any, 0, len(times))
	for _, at := range times {
		windows = append(windows, map[string]any{"range": map[string]any{"@timestamp": map[string]any{
			"gte": shift(at, -time.Hour), "lte": shift(at, time.Hour),
		}}})
	}
	response, err := s.searchMap(ctx, s.Index, map[string]any{
		"size": 0,
		"query": map[string]any{"bool": map[string]any{
			"filter": []any{
				map[string]any{"term": map[string]any{"host.name": cluster.Host}},
				map[string]any{"bool": map[string]any{"should": windows, "minimum_should_match": 1}},
			},
			"must_not": []any{map[string]any{"term": map[string]any{"kibana.alert.rule.name": cluster.RuleName}}},
		}},
		"aggs": map[string]any{"rules": map[string]any{
			"terms": map[string]any{"field": "kibana.alert.rule.name", "size": 8},
			"aggs":  map[string]any{"sev": map[string]any{"terms": map[string]any{"field": "kibana.alert.severity", "size": 1}}},
		}},
	})
	if err != nil {
		return []assessment.ReferenceRelated{}
	}
	c.Collected = append(c.Collected, "other alerts on the host in the same window")
	out := []assessment.ReferenceRelated{}
	for _, bucket := range buckets(response, "aggregations.rules.buckets") {
		var severity *string
		if values, ok := rawGet(bucket, "sev.buckets").([]any); ok && len(values) > 0 {
			if first, ok := values[0].(map[string]any); ok {
				severity = stringPointer(rawGet(first, "key"))
			}
		}
		out = append(out, assessment.ReferenceRelated{
			Rule: stringValue(rawGet(bucket, "key")), Count: intNumber(rawGet(bucket, "doc_count")), Severity: severity,
		})
	}
	return out
}

func (s *Searcher) prevalence(ctx context.Context, cluster assessment.ReferenceCluster,
	c *assessment.ReferenceCase) assessment.ReferencePrevalence {
	if cluster.Entity == nil || *cluster.Entity == "" {
		return assessment.ReferencePrevalence{}
	}
	if cluster.EntityKind == "process.executable" {
		response, err := s.searchMap(ctx, processEvents, map[string]any{
			"size": 0, "track_total_hits": true,
			"query": map[string]any{"bool": map[string]any{"filter": []any{
				map[string]any{"term": map[string]any{"process.executable": *cluster.Entity}},
				map[string]any{"range": map[string]any{"@timestamp": map[string]any{"gte": "now-30d"}}},
			}}},
			"aggs": map[string]any{"hosts": map[string]any{"cardinality": map[string]any{"field": "host.name"}}, "first": map[string]any{"min": map[string]any{"field": "@timestamp"}}},
		})
		if err != nil {
			return assessment.ReferencePrevalence{}
		}
		c.Collected = append(c.Collected, "30-day prevalence of the executable")
		executions, hosts := totalHits(response), intNumber(get(response, "aggregations.hosts.value"))
		return assessment.ReferencePrevalence{Kind: "executable", Executions30d: &executions, Hosts: &hosts,
			FirstSeen30d: stringPointer(get(response, "aggregations.first.value_as_string"))}
	}
	if cluster.EntityKind == "source.ip" {
		response, err := s.searchMap(ctx, s.Index, map[string]any{
			"size": 0, "track_total_hits": true,
			"query": map[string]any{"bool": map[string]any{"filter": []any{map[string]any{"term": map[string]any{"source.ip": *cluster.Entity}}}}},
			"aggs": map[string]any{
				"rules": map[string]any{"cardinality": map[string]any{"field": "kibana.alert.rule.name"}},
				"hosts": map[string]any{"cardinality": map[string]any{"field": "host.name"}},
				"first": map[string]any{"min": map[string]any{"field": "@timestamp"}},
			},
		})
		if err != nil {
			return assessment.ReferencePrevalence{}
		}
		c.Collected = append(c.Collected, "history of the source address across all rules")
		alerts, rules, hosts := totalHits(response), intNumber(get(response, "aggregations.rules.value")), intNumber(get(response, "aggregations.hosts.value"))
		return assessment.ReferencePrevalence{Kind: "source address", AlertsAllRules: &alerts, Rules: &rules, Hosts: &hosts,
			FirstSeen: stringPointer(get(response, "aggregations.first.value_as_string"))}
	}
	return assessment.ReferencePrevalence{}
}

func (s *Searcher) iocHits(ctx context.Context, alerts []map[string]any,
	c *assessment.ReferenceCase) []assessment.ReferenceIOCHit {
	ips := merge(distinct(alerts, "source.ip"), distinct(alerts, "destination.ip"))
	publicIPs := []string{}
	for _, value := range ips {
		parsed := net.ParseIP(value)
		if parsed != nil && !parsed.IsPrivate() && !parsed.IsLoopback() && !parsed.IsLinkLocalUnicast() {
			publicIPs = append(publicIPs, value)
		}
	}
	hashes := distinct(alerts, "file.hash.sha256")
	domains := merge(distinct(alerts, "destination.domain"), distinct(alerts, "dns.question.name"))
	should := []any{}
	if len(publicIPs) > 0 {
		sort.Strings(publicIPs)
		should = append(should, map[string]any{"terms": map[string]any{"threat.indicator.ip": limitStrings(publicIPs, 50)}})
	}
	if len(hashes) > 0 {
		sort.Strings(hashes)
		should = append(should, map[string]any{"terms": map[string]any{"threat.indicator.file.hash.sha256": limitStrings(hashes, 50)}})
	}
	if len(domains) > 0 {
		sort.Strings(domains)
		should = append(should, map[string]any{"terms": map[string]any{"threat.indicator.url.domain": limitStrings(domains, 50)}})
	}
	if len(should) == 0 {
		return []assessment.ReferenceIOCHit{}
	}
	response, err := s.searchMap(ctx, threatIndices, map[string]any{
		"size": 10, "query": map[string]any{"bool": map[string]any{"should": should, "minimum_should_match": 1}},
		"_source": []string{"threat.indicator.ip", "threat.indicator.file.hash.sha256", "threat.indicator.url.domain", "threat.feed.name", "threat.indicator.type", "event.dataset"},
	})
	if err != nil {
		return []assessment.ReferenceIOCHit{}
	}
	c.Collected = append(c.Collected, "lookup of observables in the ingested threat feeds")
	out := []assessment.ReferenceIOCHit{}
	for _, source := range hitSources(response) {
		indicator := firstValue(get(source, "threat.indicator.ip"), get(source, "threat.indicator.file.hash.sha256"), get(source, "threat.indicator.url.domain"))
		feed := firstValue(get(source, "threat.feed.name"), get(source, "event.dataset"))
		out = append(out, assessment.ReferenceIOCHit{Indicator: indicator, Feed: feed, Type: get(source, "threat.indicator.type")})
	}
	return out
}

func referenceEntities(alerts []map[string]any, c assessment.ReferenceCase) assessment.ReferenceEntityCounts {
	hosts := distinct(alerts, "host.name")
	if len(hosts) == 0 {
		hosts = []string{"unknown"}
	}
	processes := map[string]struct{}{}
	for _, item := range c.ProcessChain {
		if item.Executable != nil && *item.Executable != "" {
			processes[*item.Executable] = struct{}{}
		}
	}
	ips := merge(distinct(alerts, "source.ip"), distinct(alerts, "destination.ip"))
	domains := distinct(alerts, "dns.question.name")
	if c.Network != nil {
		for _, destination := range c.Network.Destinations {
			ips = appendUnique(ips, destination.IP)
		}
		domains = merge(domains, c.Network.Domains)
	}
	files, hashes, urls := 0, 0, 0
	if c.Files != nil {
		files, hashes = c.Files.Count, len(c.Files.Hashes)
	}
	if c.Web != nil {
		urls = len(c.Web.URLs)
	}
	return assessment.ReferenceEntityCounts{
		Hosts: len(hosts), Users: len(distinct(alerts, "user.name")), Process: len(processes),
		Files: files, Hashes: hashes, IPs: len(ips), Domains: len(domains), URLs: urls, IOCHits: len(c.IOCHits),
	}
}

func (s *Searcher) searchMap(ctx context.Context, index string, body map[string]any) (map[string]any, error) {
	var response map[string]any
	if err := s.searchIndex(ctx, index, body, &response); err != nil {
		return nil, err
	}
	return response, nil
}

func hitSources(response map[string]any) []map[string]any {
	hits, _ := rawGet(response, "hits.hits").([]any)
	out := make([]map[string]any, 0, len(hits))
	for _, value := range hits {
		if hit, ok := value.(map[string]any); ok {
			if source, ok := rawGet(hit, "_source").(map[string]any); ok {
				out = append(out, source)
			}
		}
	}
	return out
}

func buckets(response map[string]any, dotted string) []map[string]any {
	values, _ := rawGet(response, dotted).([]any)
	out := make([]map[string]any, 0, len(values))
	for _, value := range values {
		if item, ok := value.(map[string]any); ok {
			out = append(out, item)
		}
	}
	return out
}

func bucketKeys(values []map[string]any) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, stringValue(rawGet(value, "key")))
	}
	return out
}

func bucketCounts(values []map[string]any) assessment.ReferenceCounts {
	out := make(assessment.ReferenceCounts, 0, len(values))
	for _, value := range values {
		out = append(out, assessment.ReferenceCount{Key: stringValue(rawGet(value, "key")), Count: intNumber(rawGet(value, "doc_count"))})
	}
	return out
}

func totalHits(response map[string]any) int { return intNumber(get(response, "hits.total.value")) }

func countedValues(alerts []map[string]any, field string, limit int) assessment.ReferenceCounts {
	counts := assessment.ReferenceCounts{}
	index := map[string]int{}
	for _, alert := range alerts {
		value := stringValue(get(alert, field))
		if value == "" || value == "0" {
			continue
		}
		if position, ok := index[value]; ok {
			counts[position].Count++
		} else {
			index[value] = len(counts)
			counts = append(counts, assessment.ReferenceCount{Key: value, Count: 1})
		}
	}
	sort.SliceStable(counts, func(i, j int) bool { return counts[i].Count > counts[j].Count })
	return limitCounts(counts, limit)
}

func rawGet(document map[string]any, dotted string) any {
	if value, ok := document[dotted]; ok {
		return value
	}
	var current any = document
	for _, piece := range strings.Split(dotted, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current, ok = object[piece]
		if !ok {
			return nil
		}
	}
	return current
}

func get(document map[string]any, dotted string) any {
	value := rawGet(document, dotted)
	if values, ok := value.([]any); ok && len(values) == 1 {
		return values[0]
	}
	return value
}

func distinct(documents []map[string]any, dotted string) []string {
	out := []string{}
	for _, document := range documents {
		value := rawGet(document, dotted)
		values, ok := value.([]any)
		if !ok {
			values = []any{value}
		}
		for _, item := range values {
			text := stringValue(item)
			if text != "" {
				out = appendUnique(out, text)
			}
		}
	}
	return out
}

func merge(first, second []string) []string {
	out := append([]string{}, first...)
	for _, value := range second {
		out = appendUnique(out, value)
	}
	return out
}

func appendUnique(values []string, candidate string) []string {
	if candidate == "" || contains(values, candidate) {
		return values
	}
	return append(values, candidate)
}

func contains(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func uniqueStrings(values []string) []string { return append([]string(nil), values...) }

func limitStrings(values []string, limit int) []string {
	if len(values) <= limit {
		return values
	}
	return values[:limit]
}

func limitCounts(values assessment.ReferenceCounts, limit int) assessment.ReferenceCounts {
	if len(values) <= limit {
		return values
	}
	return values[:limit]
}

func sortedSet(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func asObjects(value any) []map[string]any {
	if object, ok := value.(map[string]any); ok {
		return []map[string]any{object}
	}
	values, _ := value.([]any)
	out := []map[string]any{}
	for _, value := range values {
		if object, ok := value.(map[string]any); ok {
			out = append(out, object)
		}
	}
	return out
}

func stringValue(value any) string {
	if value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return fmt.Sprint(value)
	}
}

func pythonString(value any) string {
	if values, ok := value.([]any); ok {
		items := make([]string, 0, len(values))
		for _, item := range values {
			items = append(items, "'"+strings.ReplaceAll(stringValue(item), "'", "\\'")+"'")
		}
		return "[" + strings.Join(items, ", ") + "]"
	}
	return stringValue(value)
}

func stringPointer(value any) *string {
	text := stringValue(value)
	if text == "" {
		return nil
	}
	if len([]rune(text)) > 200 {
		text = string([]rune(text)[:200]) + "…"
	}
	return &text
}

func firstValue(values ...any) any {
	for _, value := range values {
		if stringValue(value) != "" {
			return value
		}
	}
	return nil
}

func args(document map[string]any) any {
	value := rawGet(document, "process.args")
	if values, ok := value.([]any); ok {
		items := make([]string, 0, len(values))
		for _, value := range values {
			items = append(items, stringValue(value))
		}
		return strings.Join(items, " ")
	}
	return value
}

func number(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case int:
		return float64(typed), true
	case jsonNumber:
		value, err := strconv.ParseFloat(string(typed), 64)
		return value, err == nil
	default:
		return 0, false
	}
}

type jsonNumber string

func intNumber(value any) int {
	n, _ := number(value)
	return int(n)
}

func timeGap(first, second *string) time.Duration {
	if first == nil || second == nil {
		return 0
	}
	a, errA := time.Parse(time.RFC3339Nano, *first)
	b, errB := time.Parse(time.RFC3339Nano, *second)
	if errA != nil || errB != nil {
		return 0
	}
	if b.Before(a) {
		return a.Sub(b)
	}
	return b.Sub(a)
}

func shift(value string, delta time.Duration) string {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return value
	}
	return parsed.Add(delta).UTC().Format(time.RFC3339Nano)
}

func fileExtension(value string) string {
	name := strings.ToLower(path.Base(value))
	if strings.Contains(name, ".so.") || strings.HasSuffix(name, ".so") {
		return ".so"
	}
	extension := path.Ext(name)
	if extension == "" {
		return "(none)"
	}
	return extension
}
