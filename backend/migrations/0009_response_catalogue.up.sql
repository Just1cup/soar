-- Fase 2, F-05: catálogo de ações, política de autonomia, aprovação e
-- execução. O modelo app/asset/action vem do Splunk SOAR (docs/soar/00 §3):
-- a integração declara o que sabe fazer, o asset diz contra qual instância e
-- com qual credencial, e o playbook só orquestra.

CREATE SCHEMA IF NOT EXISTS response;

CREATE TABLE response.integrations (
    id         UUID PRIMARY KEY DEFAULT uuidv7(),
    tenant_id  UUID NOT NULL REFERENCES core.tenants(id),
    slug       TEXT NOT NULL,
    name       TEXT NOT NULL,
    pack_id    TEXT NOT NULL,
    -- O manifesto inteiro, como veio do content pack: as ações, seus schemas
    -- de entrada e saída, autonomia e reversibilidade. Fica em JSONB porque é
    -- lido inteiro pelo registry e nunca consultado por campo.
    manifest   JSONB NOT NULL,
    manifest_sha BYTEA NOT NULL,
    enabled    BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, slug)
);

CREATE TABLE response.integration_assets (
    id             UUID PRIMARY KEY DEFAULT uuidv7(),
    tenant_id      UUID NOT NULL REFERENCES core.tenants(id),
    integration_id UUID NOT NULL REFERENCES response.integrations(id) ON DELETE CASCADE,
    name           TEXT NOT NULL,
    endpoint       TEXT,
    -- PONTEIRO, nunca o segredo: env://VAR, k8s://secret/chave, vault://path.
    -- Nenhuma coluna deste banco guarda credencial de integração.
    credential_ref TEXT NOT NULL,
    config         JSONB NOT NULL DEFAULT '{}',
    health_status  TEXT NOT NULL DEFAULT 'unknown'
                   CHECK (health_status IN ('unknown','healthy','degraded','down')),
    health_checked_at TIMESTAMPTZ,
    health_detail  TEXT,
    circuit_state  TEXT NOT NULL DEFAULT 'closed'
                   CHECK (circuit_state IN ('closed','open','half_open')),
    circuit_until  TIMESTAMPTZ,
    enabled        BOOLEAN NOT NULL DEFAULT true,
    version        INT NOT NULL DEFAULT 1,
    UNIQUE (tenant_id, integration_id, name),
    CONSTRAINT credential_is_a_pointer CHECK (credential_ref ~ '^(env|k8s|vault|none)://')
);

CREATE TABLE response.approvals (
    id             UUID PRIMARY KEY DEFAULT uuidv7(),
    tenant_id      UUID NOT NULL REFERENCES core.tenants(id),
    incident_id    UUID REFERENCES incident.incidents(id) ON DELETE CASCADE,
    asset_id       UUID NOT NULL REFERENCES response.integration_assets(id),
    action         TEXT NOT NULL,
    permission     TEXT NOT NULL REFERENCES iam.permissions(name),

    -- O plano renderizado: resumo, detalhes, quantos objetos mudam, como
    -- reverter, e a requisição literal — que o operador pode executar à mão
    -- em vez de confiar, e que é o que ele faz nas primeiras vezes.
    plan             JSONB NOT NULL,
    plan_fingerprint BYTEA NOT NULL,
    affected_count   INT,

    status         TEXT NOT NULL DEFAULT 'requested' CHECK (status IN
                   ('requested','approved','rejected','expired','superseded','consumed')),
    requested_by   TEXT NOT NULL,
    requested_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ NOT NULL,
    decided_by     UUID REFERENCES iam.users(id),
    decided_at     TIMESTAMPTZ,
    decision_note  TEXT,
    version        INT NOT NULL DEFAULT 1,

    CONSTRAINT decided_has_actor CHECK (
        status NOT IN ('approved','rejected') OR (decided_by IS NOT NULL AND decided_at IS NOT NULL)
    )
);
CREATE INDEX approvals_pending ON response.approvals (tenant_id, requested_at)
    WHERE status = 'requested';
CREATE INDEX approvals_by_incident ON response.approvals (tenant_id, incident_id, requested_at DESC);

CREATE TABLE response.action_runs (
    id               UUID PRIMARY KEY DEFAULT uuidv7(),
    tenant_id        UUID NOT NULL REFERENCES core.tenants(id),
    incident_id      UUID REFERENCES incident.incidents(id) ON DELETE CASCADE,
    execution_id     UUID,
    asset_id         UUID NOT NULL REFERENCES response.integration_assets(id),
    integration_slug TEXT NOT NULL,
    action           TEXT NOT NULL,
    approval_id      UUID REFERENCES response.approvals(id),

    -- Repetir a mesma chave devolve o resultado gravado. Sem isto, um timeout
    -- do cliente vira uma segunda execução em produção.
    idempotency_key  TEXT NOT NULL,
    plan_fingerprint BYTEA,
    autonomy         TEXT NOT NULL CHECK (autonomy IN ('auto','approval_required','manual')),

    status           TEXT NOT NULL DEFAULT 'pending' CHECK (status IN
                     ('pending','running','succeeded','failed','skipped')),
    -- Entrada e saída passam pelo redator antes de chegar aqui.
    input            JSONB NOT NULL DEFAULT '{}',
    output           JSONB,
    error            TEXT,
    affected_count   INT,

    actor_kind       TEXT NOT NULL,
    actor_id         TEXT NOT NULL,
    requested_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at       TIMESTAMPTZ,
    finished_at      TIMESTAMPTZ,
    latency_ms       INT,
    attempt          SMALLINT NOT NULL DEFAULT 1,

    UNIQUE (tenant_id, idempotency_key),

    -- O invariante 3 do doc 03, no banco: ação sensível não executa sem
    -- aprovação. Um CHECK vale mais que um teste, porque não depende de o
    -- caminho do código estar correto.
    CONSTRAINT approval_required_has_approval CHECK (
        autonomy <> 'approval_required' OR approval_id IS NOT NULL
    )
);
CREATE INDEX action_runs_by_incident ON response.action_runs (tenant_id, incident_id, requested_at DESC);
CREATE INDEX action_runs_inflight ON response.action_runs (started_at)
    WHERE status IN ('pending','running');
CREATE INDEX action_runs_by_action ON response.action_runs (tenant_id, integration_slug, action, requested_at DESC);

CREATE TABLE platform.idempotency_keys (
    tenant_id     UUID NOT NULL REFERENCES core.tenants(id),
    key           TEXT NOT NULL,
    route         TEXT NOT NULL,
    -- Reusar a mesma chave com corpo diferente é erro do cliente, não um
    -- pedido de replay: devolver silenciosamente o resultado de outra
    -- requisição é pior que reexecutar.
    request_hash  BYTEA NOT NULL,
    status_code   SMALLINT,
    response_body JSONB,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, key)
);
CREATE INDEX idempotency_gc ON platform.idempotency_keys (expires_at);
