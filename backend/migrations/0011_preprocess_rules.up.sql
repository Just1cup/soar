-- Fase 2, F-04: pre-process rules. A decisão mais barata é a que evita criar
-- o caso (docs/soar/00 §2). É a resposta direta ao fechamento manual de
-- 19.344 alertas em 2026-09-20.

CREATE SCHEMA IF NOT EXISTS automation;

CREATE TABLE automation.rules (
    id          UUID PRIMARY KEY DEFAULT uuidv7(),
    tenant_id   UUID NOT NULL REFERENCES core.tenants(id),
    slug        TEXT NOT NULL,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('preprocess','automation')),
    trigger     TEXT NOT NULL,
    run_order   INT NOT NULL DEFAULT 100,
    -- Condições e ações, como vieram do YAML do content pack.
    definition  JSONB NOT NULL,
    -- Nasce DESLIGADA. Ligar exige um dry-run bem-sucedido, porque uma regra
    -- de supressão errada descarta um ataque real — e silenciosamente.
    enabled     BOOLEAN NOT NULL DEFAULT false,
    dry_run_at  TIMESTAMPTZ,
    dry_run_matched INT,
    expires_at  TIMESTAMPTZ,
    pack_id     TEXT,
    version     INT NOT NULL DEFAULT 1,
    created_by  UUID REFERENCES iam.users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, slug),

    -- Uma regra que descarta ou fecha NÃO pode existir sem data de validade.
    -- Uma detecção silenciada para sempre por esquecimento é a falha mais cara
    -- que um SOAR pode introduzir, e não deve depender da disciplina de
    -- ninguém (docs/soar/07 §6.8).
    CONSTRAINT suppression_must_expire CHECK (
        expires_at IS NOT NULL
        OR NOT (definition -> 'actions' @> '[{"type":"drop"}]'
             OR definition -> 'actions' @> '[{"type":"close_incident"}]')
    ),
    -- E não pode ser ligada sem ter passado por um dry-run.
    CONSTRAINT enabled_needs_dry_run CHECK (NOT enabled OR dry_run_at IS NOT NULL)
);
CREATE INDEX rules_active ON automation.rules (tenant_id, trigger, run_order)
    WHERE enabled;

CREATE TABLE automation.rule_runs (
    id          UUID PRIMARY KEY DEFAULT uuidv7(),
    tenant_id   UUID NOT NULL,
    rule_id     UUID NOT NULL REFERENCES automation.rules(id) ON DELETE CASCADE,
    alert_id    UUID,
    incident_id UUID REFERENCES incident.incidents(id) ON DELETE CASCADE,
    matched     BOOLEAN NOT NULL,
    dry_run     BOOLEAN NOT NULL DEFAULT false,
    outcome     TEXT NOT NULL,
    detail      JSONB NOT NULL DEFAULT '{}',
    error       TEXT,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX rule_runs_by_rule ON automation.rule_runs (rule_id, occurred_at DESC);

-- O que foi suprimido na semana, consultável. Uma supressão que ninguém
-- revisa é uma detecção desligada sem que ninguém saiba.
CREATE VIEW automation.suppression_report AS
SELECT r.slug            AS rule_slug,
       r.name            AS rule_name,
       r.expires_at,
       count(a.id)       AS alerts_suppressed,
       min(a.ingested_at) AS first_suppression,
       max(a.ingested_at) AS last_suppression
  FROM automation.rules r
  LEFT JOIN incident.alerts a ON a.suppressed_by = r.id
 WHERE r.kind = 'preprocess'
 GROUP BY r.id, r.slug, r.name, r.expires_at;
