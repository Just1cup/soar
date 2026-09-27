// Package elastic talks to Elastic Security through the Kibana detection
// engine API.
//
// This is the port of the Python ActionEngine that already ran against this
// laboratory. Two behaviours are preserved exactly, because both were learned
// the expensive way:
//
//   - the plan counts the affected alerts BEFORE the change, by querying
//     Elasticsearch, so the operator confirms a number and not a hope;
//   - an exception is scoped to the rule that fired, never installed globally.
package elastic

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/titas/soar/backend/internal/integration"
)

const alertsIndex = ".alerts-security.alerts-*"

type Adapter struct {
	client *http.Client
}

func New() *Adapter {
	return &Adapter{
		client: &http.Client{
			Timeout: 120 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 4,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

func (a *Adapter) Slug() string { return "elastic-siem" }

// scopeQuery builds the Elasticsearch filter that defines "these alerts".
//
// Rule AND host AND entity, all three when present. Scoping by rule alone
// would close a noisy rule's alerts on every host, which is how a tuning
// action becomes an outage of visibility.
func scopeQuery(in map[string]any) map[string]any {
	must := []map[string]any{
		{"term": map[string]any{"kibana.alert.rule.name": str(in["rule_name"])}},
	}
	if h := str(in["host"]); h != "" && h != "-" {
		must = append(must, map[string]any{"term": map[string]any{"host.name": h}})
	}
	if e := str(in["entity"]); e != "" && e != "-" {
		must = append(must, map[string]any{
			"bool": map[string]any{"should": []map[string]any{
				{"term": map[string]any{"process.executable": e}},
				{"term": map[string]any{"user.name": e}},
				{"term": map[string]any{"source.ip": e}},
				{"term": map[string]any{"destination.ip": e}},
			}, "minimum_should_match": 1},
		})
	}
	// Só o que ainda está aberto: refazer o plano depois de aplicar deve dar
	// zero, e não a mesma contagem de novo.
	must = append(must, map[string]any{
		"terms": map[string]any{"kibana.alert.workflow_status": []string{"open", "acknowledged"}},
	})
	return map[string]any{"bool": map[string]any{"filter": must}}
}

func (a *Adapter) Plan(ctx context.Context, call integration.ActionCall) (*integration.Plan, error) {
	switch call.Action {
	case "close_alerts":
		return a.planCloseAlerts(ctx, call)
	case "create_exception":
		return a.planCreateException(ctx, call)
	default:
		return nil, fmt.Errorf("ação %q não gera plano", call.Action)
	}
}

func (a *Adapter) planCloseAlerts(ctx context.Context, call integration.ActionCall) (*integration.Plan, error) {
	query := scopeQuery(call.Input)
	status := str(call.Input["status"])
	if status == "" {
		status = "closed"
	}

	plan := &integration.Plan{
		Reversible: "reabrir os alertas alterando o status de volta para 'open'",
		Request: map[string]any{
			"method": "POST",
			"url":    strings.TrimRight(call.Asset.Endpoint, "/") + "/api/detection_engine/signals/status",
			"body":   map[string]any{"query": query, "status": status},
		},
		Ready: true,
	}

	count, err := a.countAlerts(ctx, call.Asset, query)
	if err != nil {
		// O plano ainda é mostrado, com a razão: "por que não consigo fazer
		// isto" é a pergunta que está sendo feita.
		plan.Ready = false
		plan.Summary = "Não foi possível contar os alertas afetados"
		plan.Details = append(plan.Details, err.Error())
		return plan, nil
	}
	plan.Affected = &count
	plan.Summary = fmt.Sprintf("Marcar %d alerta(s) como %q", count, status)
	plan.Details = []string{
		"Regra: " + str(call.Input["rule_name"]),
	}
	if h := str(call.Input["host"]); h != "" && h != "-" {
		plan.Details = append(plan.Details, "Host: "+h)
	}
	if e := str(call.Input["entity"]); e != "" && e != "-" {
		plan.Details = append(plan.Details, "Entidade: "+e)
	}
	switch {
	case count == 0:
		plan.Ready = false
		plan.Warnings = append(plan.Warnings,
			"Nenhum alerta aberto corresponde a este escopo; nada a fazer.")
	case count > 1000:
		// Não bloqueia: informa. Fechar 19.344 alertas de uma vez foi uma
		// operação legítima neste ambiente — mas o operador precisa ver o
		// número antes, não depois.
		plan.Warnings = append(plan.Warnings, fmt.Sprintf(
			"Escopo grande: %d alertas. Confira a regra e o host antes de aplicar.", count))
	}
	if status == "closed" {
		plan.Warnings = append(plan.Warnings,
			"Fechar não impede a regra de disparar de novo. O remédio durável é exceção de regra.")
	}
	return plan, nil
}

func (a *Adapter) planCreateException(ctx context.Context, call integration.ActionCall) (*integration.Plan, error) {
	ruleName := str(call.Input["rule_name"])
	field, value := str(call.Input["field"]), str(call.Input["value"])

	plan := &integration.Plan{
		Reversible: "remover o item da lista de exceções da regra",
		Ready:      true,
		Details: []string{
			"Regra: " + ruleName,
			fmt.Sprintf("Condição: %s é %s", field, value),
			"Comentário: " + str(call.Input["comment"]),
		},
	}

	ruleID, err := a.findRuleID(ctx, call.Asset, ruleName)
	if err != nil || ruleID == "" {
		plan.Ready = false
		plan.Summary = "Regra não localizada no Kibana"
		if err != nil {
			plan.Details = append(plan.Details, err.Error())
		} else {
			plan.Details = append(plan.Details, "Nenhuma regra com este nome exato.")
		}
		return plan, nil
	}

	item := map[string]any{
		"description":    str(call.Input["comment"]),
		"name":           fmt.Sprintf("SOAR: %s é %s", field, value),
		"type":           "simple",
		"list_id":        "",
		"namespace_type": "single",
		"entries": []map[string]any{{
			"field": field, "operator": "included", "type": "match", "value": value,
		}},
	}
	plan.Summary = fmt.Sprintf("Criar exceção na regra %q para %s = %s", ruleName, field, value)
	plan.Request = map[string]any{
		"method": "POST",
		"url": strings.TrimRight(call.Asset.Endpoint, "/") +
			"/api/detection_engine/rules/" + ruleID + "/exceptions",
		"body": map[string]any{"items": []any{item}},
	}
	plan.Warnings = append(plan.Warnings,
		"A exceção vale só para esta regra. Alertas já existentes não são fechados por ela.")
	return plan, nil
}

func (a *Adapter) Execute(ctx context.Context, call integration.ActionCall) (*integration.Result, error) {
	switch call.Action {
	case "find_rule":
		id, err := a.findRuleID(ctx, call.Asset, str(call.Input["rule_name"]))
		if err != nil {
			return nil, err
		}
		return &integration.Result{
			Output:  map[string]any{"rule_id": id},
			Summary: "Regra localizada",
		}, nil

	case "close_alerts", "create_exception":
		// O executor já recomputou o plano e conferiu o fingerprint; aqui só
		// se envia a requisição que ele aprovou, literalmente.
		req, _ := call.Input["__request"].(map[string]any)
		if req == nil {
			return nil, fmt.Errorf("execução sem requisição planejada")
		}
		return a.send(ctx, call.Asset, req)

	case "isolate_host":
		return nil, fmt.Errorf("isolate_host não tem adapter neste deploy")
	default:
		return nil, fmt.Errorf("ação desconhecida: %q", call.Action)
	}
}

func (a *Adapter) send(ctx context.Context, asset integration.Asset, req map[string]any) (*integration.Result, error) {
	body, err := json.Marshal(req["body"])
	if err != nil {
		return nil, fmt.Errorf("serializar corpo: %w", err)
	}
	resp, err := a.do(ctx, asset, str(req["method"]), str(req["url"]), body)
	if err != nil {
		return nil, err
	}
	var parsed map[string]any
	_ = json.Unmarshal(resp, &parsed)

	out := &integration.Result{Output: parsed}
	if total, ok := parsed["updated"].(float64); ok {
		n := int(total)
		out.Affected = &n
		out.Summary = fmt.Sprintf("%d alerta(s) alterado(s)", n)
	} else {
		out.Summary = "Requisição aceita pelo Kibana"
	}
	return out, nil
}

func (a *Adapter) Health(ctx context.Context, asset integration.Asset) error {
	_, err := a.do(ctx, asset, http.MethodGet,
		strings.TrimRight(asset.Endpoint, "/")+"/api/detection_engine/rules/_find?per_page=1", nil)
	return err
}

func (a *Adapter) findRuleID(ctx context.Context, asset integration.Asset, name string) (string, error) {
	url := fmt.Sprintf("%s/api/detection_engine/rules/_find?per_page=200&filter=%s",
		strings.TrimRight(asset.Endpoint, "/"),
		urlEscape(`alert.attributes.name:"`+name+`"`))
	raw, err := a.do(ctx, asset, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	var found struct {
		Data []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &found); err != nil {
		return "", fmt.Errorf("resposta inesperada do Kibana: %w", err)
	}
	// Igualdade exata: o filtro do Kibana é fuzzy e "DNS Request" casaria com
	// "Uncommon DNS Request". Instalar a exceção na regra errada é pior que
	// não instalar.
	for _, r := range found.Data {
		if r.Name == name {
			return r.ID, nil
		}
	}
	return "", nil
}

func (a *Adapter) countAlerts(ctx context.Context, asset integration.Asset, query map[string]any) (int, error) {
	elasticURL := str(asset.Config["elastic_url"])
	if elasticURL == "" {
		return 0, fmt.Errorf("asset sem elastic_url: não é possível contar o escopo")
	}
	body, _ := json.Marshal(map[string]any{"query": query})
	raw, err := a.do(ctx, asset, http.MethodPost,
		strings.TrimRight(elasticURL, "/")+"/"+alertsIndex+"/_count", body)
	if err != nil {
		return 0, err
	}
	var counted struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal(raw, &counted); err != nil {
		return 0, fmt.Errorf("contagem inesperada: %w", err)
	}
	return counted.Count, nil
}

func (a *Adapter) do(ctx context.Context, asset integration.Asset, method, url string, body []byte) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, fmt.Errorf("montar requisição: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// O Kibana recusa mutação sem este header; é a proteção de CSRF dele.
	req.Header.Set("kbn-xsrf", "soar")
	if asset.Credential != "" {
		req.Header.Set("Authorization", "Basic "+
			base64.StdEncoding.EncodeToString([]byte(asset.Credential)))
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Elastic/Kibana inalcançável em %s: %w", asset.Endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Limite de leitura: uma resposta de erro do Elasticsearch pode vir com
	// megabytes de stack trace, e nada disso cabe num plano.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("ler resposta: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("Kibana respondeu %d: %s", resp.StatusCode, truncate(string(raw), 300))
	}
	return raw, nil
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func urlEscape(s string) string {
	r := strings.NewReplacer(" ", "%20", `"`, "%22", ":", "%3A", "&", "%26", "+", "%2B")
	return r.Replace(s)
}
