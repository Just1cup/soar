package postgres

import (
	"encoding/json"
	"testing"
)

func TestJSONBRedactsSecretsRecursively(t *testing.T) {
	got, err := jsonb(map[string]any{
		"Password": "one",
		"nested":   map[string]any{"api-key": "two", "safe": "visible"},
		"items":    []any{map[string]any{"refresh_token": "three"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(got.(string)), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["Password"] != "[redigido]" {
		t.Fatalf("password não redigido: %#v", decoded)
	}
	nested := decoded["nested"].(map[string]any)
	if nested["api-key"] != "[redigido]" || nested["safe"] != "visible" {
		t.Fatalf("mapa aninhado incorreto: %#v", nested)
	}
	item := decoded["items"].([]any)[0].(map[string]any)
	if item["refresh_token"] != "[redigido]" {
		t.Fatalf("segredo em array não redigido: %#v", item)
	}
}

func TestJSONBNilStaysSQLNull(t *testing.T) {
	got, err := jsonb(nil)
	if err != nil || got != nil {
		t.Fatalf("jsonb(nil) = %#v, %v", got, err)
	}
}
