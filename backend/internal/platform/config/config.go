// Package config reads the environment once, at startup, and fails loudly.
//
// Fail fast is the rule: a platform that boots with a missing database URL and
// only discovers it on the first request has turned a config error into an
// incident.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Env          string
	Profile      string // edge | standard | scale  (docs/soar/08 §5)
	HTTPAddr     string
	DatabaseURL  string
	DBMaxConns   int32
	CursorSecret string
	LogLevel     string
	ShutdownWait time.Duration
	// ContentPacks é lido do DISCO, não embarcado: conteúdo (integrações,
	// regras, playbooks) precisa poder ser atualizado sem recompilar o core
	// (docs/soar/08 §12).
	ContentPacks string
	// ApprovalTTL limita por quanto tempo um plano confirmado continua
	// confirmável. Um plano aprovado ontem descreve o mundo de ontem.
	ApprovalTTL time.Duration
	// IngestEnabled desliga o laço de ingestão sem desligar a API: útil para
	// rodar um migrate ou investigar o banco sem o conector escrevendo junto.
	IngestEnabled  bool
	IngestInterval time.Duration
	// DedupeWindow é o padrão quando o tipo de incidente não define o seu.
	DedupeWindow time.Duration
	// AssessmentEnabled liga o consumidor incident.created. A leitura e a
	// promoção de artefatos existentes continuam disponíveis quando desligado.
	AssessmentEnabled bool
	OllamaURL         string
	OllamaModel       string
	OllamaNumCtx      int
	OllamaTimeout     time.Duration
	// ElasticURL é opcional: sem ele a avaliação explicita que correlação e
	// prevalência não puderam ser consultadas, em vez de fingir ausência.
	AssessmentElasticURL string
}

func Load() (Config, error) {
	c := Config{
		Env:                  env("SOAR_ENV", "development"),
		Profile:              env("SOAR_PROFILE", "edge"),
		HTTPAddr:             env("SOAR_HTTP_ADDR", "127.0.0.1:8080"),
		DatabaseURL:          os.Getenv("SOAR_DATABASE_URL"),
		DBMaxConns:           int32(envInt("SOAR_DB_MAX_CONNS", 10)),
		CursorSecret:         os.Getenv("SOAR_CURSOR_SECRET"),
		LogLevel:             env("SOAR_LOG_LEVEL", "info"),
		ShutdownWait:         time.Duration(envInt("SOAR_SHUTDOWN_WAIT_SECONDS", 15)) * time.Second,
		ContentPacks:         env("SOAR_CONTENT_PACKS", "./content-packs"),
		ApprovalTTL:          time.Duration(envInt("SOAR_APPROVAL_TTL_MINUTES", 30)) * time.Minute,
		IngestEnabled:        envBool("SOAR_INGEST_ENABLED", true),
		IngestInterval:       time.Duration(envInt("SOAR_INGEST_INTERVAL_SECONDS", 60)) * time.Second,
		DedupeWindow:         time.Duration(envInt("SOAR_DEDUPE_WINDOW_HOURS", 24)) * time.Hour,
		AssessmentEnabled:    envBool("SOAR_ASSESSMENT_ENABLED", false),
		OllamaURL:            env("SOAR_OLLAMA_URL", "http://127.0.0.1:11434"),
		OllamaModel:          env("SOAR_OLLAMA_MODEL", "qwen3:8b"),
		OllamaNumCtx:         envInt("SOAR_OLLAMA_NUM_CTX", 8192),
		OllamaTimeout:        time.Duration(envInt("SOAR_OLLAMA_TIMEOUT_SECONDS", 240)) * time.Second,
		AssessmentElasticURL: os.Getenv("SOAR_ASSESSMENT_ELASTIC_URL"),
	}
	if c.DatabaseURL == "" {
		return c, fmt.Errorf("SOAR_DATABASE_URL é obrigatório")
	}
	if c.CursorSecret == "" {
		if c.Env != "development" {
			return c, fmt.Errorf("SOAR_CURSOR_SECRET é obrigatório fora de development")
		}
		// Só em desenvolvimento: um cursor assinado com segredo conhecido ainda
		// impede erro de digitação, mas não é controle de segurança.
		c.CursorSecret = "dev-insecure-cursor-secret"
	}
	switch c.Profile {
	case "edge", "standard", "scale":
	default:
		return c, fmt.Errorf("SOAR_PROFILE inválido: %q (edge|standard|scale)", c.Profile)
	}
	if c.AssessmentEnabled {
		if c.OllamaURL == "" || c.OllamaModel == "" {
			return c, fmt.Errorf("SOAR_OLLAMA_URL e SOAR_OLLAMA_MODEL são obrigatórios com assessment ligado")
		}
		if c.OllamaNumCtx < 4096 {
			return c, fmt.Errorf("SOAR_OLLAMA_NUM_CTX deve ser pelo menos 4096")
		}
	}
	return c, nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envBool(k string, def bool) bool {
	if v := os.Getenv(k); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}
