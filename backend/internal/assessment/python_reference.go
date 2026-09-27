package assessment

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

// ReferenceCluster is the deterministic, model-independent input used by the
// Python assessment pipeline. Keep the JSON names aligned with AlertCluster in
// ioc_engine.report.cluster: the frozen fixtures are our independent oracle.
type ReferenceCluster struct {
	ClusterID      string              `json:"cluster_id"`
	RuleName       string              `json:"rule_name"`
	Host           string              `json:"host"`
	EntityKind     string              `json:"entity_kind"`
	Entity         *string             `json:"entity"`
	Count          int                 `json:"count"`
	FirstSeen      string              `json:"first_seen"`
	LastSeen       string              `json:"last_seen"`
	Severity       string              `json:"severity"`
	RiskScore      *int                `json:"risk_score"`
	RuleTactics    []string            `json:"rule_tactics"`
	RuleTechniques []string            `json:"rule_techniques"`
	Observables    map[string][]string `json:"observables,omitempty"`
	Samples        []map[string]any    `json:"samples,omitempty"`
}

// ReferenceCase is the exact case_context contract produced before a model is
// called. It deliberately contains facts and collection gaps, never prose
// invented by the model.
type ReferenceCase struct {
	Window        ReferenceWindow       `json:"window"`
	Collected     []string              `json:"collected"`
	Missing       []string              `json:"missing"`
	Timeline      []ReferenceTimeline   `json:"timeline"`
	ProcessChain  []ReferenceProcess    `json:"process_chain,omitempty"`
	Files         *ReferenceFiles       `json:"files,omitempty"`
	Network       *ReferenceNetwork     `json:"network,omitempty"`
	Web           *ReferenceWeb         `json:"web,omitempty"`
	RelatedAlerts []ReferenceRelated    `json:"related_alerts"`
	Prevalence    ReferencePrevalence   `json:"prevalence"`
	IOCHits       []ReferenceIOCHit     `json:"ioc_hits"`
	Entities      ReferenceEntityCounts `json:"entities"`
}

type ReferenceWindow struct {
	First  string `json:"first"`
	Last   string `json:"last"`
	Alerts int    `json:"alerts"`
}

type ReferenceTimeline struct {
	At      *string `json:"at"`
	Last    *string `json:"last,omitempty"`
	What    string  `json:"what"`
	Subject string  `json:"subject"`
	Count   int     `json:"n"`
	Outcome any     `json:"outcome"`
	Status  any     `json:"status"`
}

type ReferenceProcess struct {
	Level       string  `json:"level"`
	Executable  *string `json:"executable"`
	Source      string  `json:"source"`
	CommandLine *string `json:"command_line,omitempty"`
	User        *string `json:"user,omitempty"`
}

type ReferenceFiles struct {
	Events      *int            `json:"events"`
	Actions     ReferenceCounts `json:"actions"`
	Paths       []string        `json:"paths"`
	Count       int             `json:"count"`
	Directories []string        `json:"directories"`
	Extensions  ReferenceCounts `json:"extensions"`
	Hashes      []string        `json:"hashes"`
}

type ReferenceNetwork struct {
	Events       int                    `json:"events"`
	Destinations []ReferenceDestination `json:"destinations"`
	Domains      []string               `json:"domains"`
}

type ReferenceDestination struct {
	IP    string `json:"ip"`
	Count int    `json:"n"`
	Port  any    `json:"port"`
}

type ReferenceWeb struct {
	URLs     []string        `json:"urls"`
	Statuses ReferenceCounts `json:"statuses"`
	Methods  ReferenceCounts `json:"methods"`
}

// ReferenceCounts preserves Python dict insertion order. Elasticsearch terms
// buckets are ordered by count, and render_case_evidence exposes that order in
// the prompt; decoding into a Go map would silently alphabetise the evidence.
type ReferenceCounts []ReferenceCount

type ReferenceCount struct {
	Key   string
	Count int
}

func (c *ReferenceCounts) UnmarshalJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return fmt.Errorf("contagens devem ser objeto JSON")
	}
	var out ReferenceCounts
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		var count int
		if err := decoder.Decode(&count); err != nil {
			return err
		}
		out = append(out, ReferenceCount{Key: keyToken.(string), Count: count})
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	*c = out
	return nil
}

func (c ReferenceCounts) MarshalJSON() ([]byte, error) {
	var out bytes.Buffer
	out.WriteByte('{')
	for index, item := range c {
		if index > 0 {
			out.WriteByte(',')
		}
		key, err := json.Marshal(item.Key)
		if err != nil {
			return nil, err
		}
		out.Write(key)
		fmt.Fprintf(&out, ":%d", item.Count)
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}

type ReferenceRelated struct {
	Rule     string  `json:"rule"`
	Count    int     `json:"n"`
	Severity *string `json:"severity"`
}

// ReferencePrevalence has two shapes. Field order intentionally reproduces
// the insertion order of the Python dictionaries for both entity kinds.
type ReferencePrevalence struct {
	Kind           string  `json:"kind,omitempty"`
	Executions30d  *int    `json:"executions_30d,omitempty"`
	AlertsAllRules *int    `json:"alerts_all_rules,omitempty"`
	Rules          *int    `json:"rules,omitempty"`
	Hosts          *int    `json:"hosts,omitempty"`
	FirstSeen30d   *string `json:"first_seen_30d,omitempty"`
	FirstSeen      *string `json:"first_seen,omitempty"`
}

type ReferenceIOCHit struct {
	Indicator any `json:"indicator"`
	Feed      any `json:"feed"`
	Type      any `json:"type"`
}

type ReferenceEntityCounts struct {
	Hosts   int `json:"hosts"`
	Users   int `json:"users"`
	Process int `json:"processes"`
	Files   int `json:"files"`
	Hashes  int `json:"hashes"`
	IPs     int `json:"ips"`
	Domains int `json:"domains"`
	URLs    int `json:"urls"`
	IOCHits int `json:"ioc_hits"`
}

// RenderReferenceEvidence is a line-for-line port of
// ioc_engine.report.casebuild.render_case_evidence. Changes must be checked
// against test/golden/assessment, never approved from a Go-only fixture.
func RenderReferenceEvidence(cluster ReferenceCluster, c ReferenceCase, maxChars int) string {
	entity := "none"
	if cluster.Entity != nil && *cluster.Entity != "" {
		entity = *cluster.Entity
	}
	lines := []string{
		"## Case",
		"Detection rule: " + cluster.RuleName,
		"Host: " + cluster.Host,
		fmt.Sprintf("Principal entity (%s): %s", cluster.EntityKind, entity),
		fmt.Sprintf("Alerts in this case: %d (first %s, last %s)", cluster.Count, cluster.FirstSeen, cluster.LastSeen),
	}
	severity := "Rule severity: " + cluster.Severity
	if cluster.RiskScore != nil && *cluster.RiskScore != 0 {
		severity += fmt.Sprintf(", risk score %d", *cluster.RiskScore)
	}
	lines = append(lines, severity)
	if len(cluster.RuleTechniques) > 0 {
		lines = append(lines, "Rule author's ATT&CK mapping (a claim, not a finding): "+strings.Join(cluster.RuleTechniques, ", "))
	}

	lines = append(lines, "", "## Timeline of this case (repeats collapsed)")
	for _, row := range c.Timeline {
		at := ""
		if row.At != nil {
			at = *row.At
		}
		count := ""
		if row.Count > 1 {
			count = fmt.Sprintf(" ×%d", row.Count)
		}
		extra := ""
		if truthy(row.Status) {
			extra = fmt.Sprintf(" [http %v]", row.Status)
		}
		lines = append(lines, fmt.Sprintf("- %s %s%s: %s%s", at, row.What, count, row.Subject, extra))
	}

	if len(c.ProcessChain) > 0 {
		lines = append(lines, "", "## Process chain (from telemetry; 'UNKNOWN' means not found)")
		for _, process := range c.ProcessChain {
			executable := "UNKNOWN"
			if process.Executable != nil && *process.Executable != "" {
				executable = *process.Executable
			}
			line := fmt.Sprintf("- %s: %s", process.Level, executable)
			if process.User != nil && *process.User != "" {
				line += " user=" + *process.User
			}
			if process.CommandLine != nil && *process.CommandLine != "" {
				line += " cmd=" + *process.CommandLine
			}
			lines = append(lines, line)
		}
	}

	if c.Files != nil && (c.Files.Count != 0 || (c.Files.Events != nil && *c.Files.Events != 0)) {
		lines = append(lines, "", "## Files touched by these process instances")
		if c.Files.Events != nil {
			lines = append(lines, fmt.Sprintf("File events: %d %s", *c.Files.Events, pythonIntDict(c.Files.Actions)))
		}
		directories := "none"
		if len(c.Files.Directories) > 0 {
			directories = strings.Join(c.Files.Directories, ", ")
		}
		lines = append(lines,
			fmt.Sprintf("Distinct paths: %d; directories: %s", c.Files.Count, directories),
			"Extensions: "+pythonIntDict(c.Files.Extensions),
		)
		for i, path := range c.Files.Paths {
			if i == 6 {
				break
			}
			lines = append(lines, "- "+path)
		}
		hashes := "NOT AVAILABLE"
		if len(c.Files.Hashes) > 0 {
			hashes = strings.Join(c.Files.Hashes, ", ")
		}
		lines = append(lines, "SHA256: "+hashes)
	}

	if c.Network != nil && len(c.ProcessChain) > 0 {
		lines = append(lines, "", "## Network activity of these process instances")
		if c.Network.Events > 0 {
			lines = append(lines, fmt.Sprintf("Network events: %d", c.Network.Events))
			for _, destination := range c.Network.Destinations {
				lines = append(lines, fmt.Sprintf("- %s:%v ×%d", destination.IP, destination.Port, destination.Count))
			}
			if len(c.Network.Domains) > 0 {
				lines = append(lines, "Domains: "+strings.Join(c.Network.Domains, ", "))
			}
		} else {
			lines = append(lines, "None observed.")
		}
	}

	if c.Web != nil {
		lines = append(lines, "", "## Web requests from this source")
		lines = append(lines, fmt.Sprintf("HTTP status codes: %s; methods: %s",
			pythonIntDict(c.Web.Statuses), pythonIntDict(c.Web.Methods)))
		for i, url := range c.Web.URLs {
			if i == 6 {
				break
			}
			lines = append(lines, "- "+truncateRunes(url, 180, ""))
		}
	}

	lines = append(lines, "", "## Other alerts on the same host within ±1h")
	if len(c.RelatedAlerts) == 0 {
		lines = append(lines, "- none")
	} else {
		for _, related := range c.RelatedAlerts {
			severity := "?"
			if related.Severity != nil && *related.Severity != "" {
				severity = *related.Severity
			}
			lines = append(lines, fmt.Sprintf("- %s ×%d (%s)", related.Rule, related.Count, severity))
		}
	}

	lines = append(lines, "", "## Prevalence", renderReferencePrevalence(c.Prevalence))
	lines = append(lines, "", "## Threat intelligence feed matches (local abuse.ch feeds)")
	if len(c.IOCHits) == 0 {
		lines = append(lines, "- no matches")
	} else {
		for _, hit := range c.IOCHits {
			lines = append(lines, fmt.Sprintf("- %v in %v (%v)", hit.Indicator, hit.Feed, hit.Type))
		}
	}
	if len(c.Missing) > 0 {
		lines = append(lines, "", "## Looked for and NOT available")
		for _, missing := range c.Missing {
			lines = append(lines, "- "+missing)
		}
	}

	text := strings.Join(lines, "\n")
	if maxChars > 0 && utf8.RuneCountInString(text) > maxChars {
		text = truncateRunes(text, maxChars, "") + "\n… (evidence truncated to fit context)"
	}
	return text
}

// RenderReferenceDecisionEvidence is a byte-compatible port of
// ioc_engine.report.generate.build_evidence, used by the short verdict pass.
func RenderReferenceDecisionEvidence(cluster ReferenceCluster, maxChars int) string {
	lines := []string{
		"## Alert cluster",
		"Detection rule: " + cluster.RuleName,
		"Host: " + cluster.Host,
		fmt.Sprintf("Alert count: %d", cluster.Count),
		"First seen: " + cluster.FirstSeen,
		"Last seen: " + cluster.LastSeen,
	}
	severity := "Rule severity: " + cluster.Severity
	if cluster.RiskScore != nil && *cluster.RiskScore != 0 {
		severity += fmt.Sprintf(" (risk score %d)", *cluster.RiskScore)
	}
	lines = append(lines, severity)
	if cluster.Entity != nil && *cluster.Entity != "" {
		lines = append(lines, fmt.Sprintf("Principal entity (%s): %s", cluster.EntityKind, *cluster.Entity))
	}
	if len(cluster.RuleTactics) > 0 || len(cluster.RuleTechniques) > 0 {
		lines = append(lines, "", "## What the detection rule itself claims")
		if len(cluster.RuleTactics) > 0 {
			lines = append(lines, "Tactics: "+strings.Join(cluster.RuleTactics, ", "))
		}
		if len(cluster.RuleTechniques) > 0 {
			lines = append(lines, "Techniques: "+strings.Join(cluster.RuleTechniques, ", "))
		}
		lines = append(lines, "(This is the rule author's mapping, not a finding. Assess whether the evidence actually supports it.)")
	}
	if len(cluster.Observables) > 0 {
		lines = append(lines, "", "## Distinct observed values")
		keys := observableKeys(cluster.Observables)
		for _, key := range keys {
			values := cluster.Observables[key]
			shown := values
			if len(shown) > 8 {
				shown = shown[:8]
			}
			rendered := strings.Join(shown, ", ")
			if len(values) > 8 {
				rendered += fmt.Sprintf(", … (%d distinct)", len(values))
			}
			lines = append(lines, fmt.Sprintf("- %s: %s", key, rendered))
		}
	}
	if len(cluster.Samples) > 0 {
		lines = append(lines, "", "## Representative alerts")
		for index, sample := range cluster.Samples {
			if rendered := renderReferenceSample(sample); rendered != "" {
				lines = append(lines, fmt.Sprintf("%d. %s", index+1, rendered))
			}
		}
	}
	text := strings.Join(lines, "\n")
	if maxChars > 0 && utf8.RuneCountInString(text) > maxChars {
		text = truncateRunes(text, maxChars, "") + "\n… (evidence truncated to fit context)"
	}
	return text
}

var referenceSampleFields = []struct{ path, label string }{
	{"@timestamp", "time"},
	{"user.name", "user"},
	{"process.command_line", "cmdline"},
	{"process.executable", "exe"},
	{"process.parent.executable", "parent"},
	{"url.original", "url"},
	{"http.response.status_code", "http_status"},
	{"dns.question.name", "dns"},
	{"destination.ip", "dest_ip"},
	{"file.path", "file"},
	{"event.outcome", "outcome"},
}

func renderReferenceSample(sample map[string]any) string {
	parts := make([]string, 0, len(referenceSampleFields))
	for _, field := range referenceSampleFields {
		value := dottedValue(sample, field.path)
		if !truthy(value) {
			continue
		}
		var text string
		switch values := value.(type) {
		case []any:
			shown := values
			if len(shown) > 3 {
				shown = shown[:3]
			}
			items := make([]string, 0, len(shown))
			for _, item := range shown {
				items = append(items, fmt.Sprint(item))
			}
			text = strings.Join(items, ", ")
		default:
			text = fmt.Sprint(value)
		}
		if utf8.RuneCountInString(text) > 200 {
			text = truncateRunes(text, 200, "…")
		}
		parts = append(parts, field.label+"="+text)
	}
	return strings.Join(parts, " | ")
}

func dottedValue(document map[string]any, path string) any {
	if value, ok := document[path]; ok {
		return value
	}
	var current any = document
	for _, part := range strings.Split(path, ".") {
		object, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current, ok = object[part]
		if !ok {
			return nil
		}
	}
	return current
}

func renderReferencePrevalence(p ReferencePrevalence) string {
	items := make([]string, 0, 5)
	if p.Kind != "" {
		items = append(items, "kind="+p.Kind)
	}
	if p.Executions30d != nil {
		items = append(items, fmt.Sprintf("executions_30d=%d", *p.Executions30d))
	}
	if p.AlertsAllRules != nil {
		items = append(items, fmt.Sprintf("alerts_all_rules=%d", *p.AlertsAllRules))
	}
	if p.Rules != nil {
		items = append(items, fmt.Sprintf("rules=%d", *p.Rules))
	}
	if p.Hosts != nil {
		items = append(items, fmt.Sprintf("hosts=%d", *p.Hosts))
	}
	if p.FirstSeen30d != nil {
		items = append(items, "first_seen_30d="+*p.FirstSeen30d)
	}
	if p.FirstSeen != nil {
		items = append(items, "first_seen="+*p.FirstSeen)
	}
	if len(items) == 0 {
		return "Not available."
	}
	return strings.Join(items, ", ")
}

func pythonIntDict(values ReferenceCounts) string {
	if len(values) == 0 {
		return "{}"
	}
	items := make([]string, 0, len(values))
	for _, item := range values {
		items = append(items, fmt.Sprintf("'%s': %d", strings.ReplaceAll(item.Key, "'", "\\'"), item.Count))
	}
	return "{" + strings.Join(items, ", ") + "}"
}

func observableKeys(values map[string][]string) []string {
	// Python's _collect_observables returns a dict built from sorted items.
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slicesSort(keys)
	return keys
}

func slicesSort(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

func truncateRunes(value string, limit int, suffix string) string {
	if utf8.RuneCountInString(value) <= limit {
		return value
	}
	runes := []rune(value)
	return string(runes[:limit]) + suffix
}

func truthy(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case bool:
		return v
	case float64:
		return v != 0
	case string:
		return v != ""
	default:
		return true
	}
}
