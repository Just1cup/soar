-- Fase 0: o mínimo coerente. Tabelas completas segundo docs/soar/07, mas só os
-- domínios que a fatia vertical atravessa.

CREATE SCHEMA IF NOT EXISTS core;
CREATE SCHEMA IF NOT EXISTS iam;
CREATE SCHEMA IF NOT EXISTS incident;

CREATE TABLE core.tenants (
    id         UUID PRIMARY KEY DEFAULT uuidv7(),
    slug       TEXT NOT NULL UNIQUE,
    name       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE iam.users (
    id            UUID PRIMARY KEY DEFAULT uuidv7(),
    tenant_id     UUID NOT NULL REFERENCES core.tenants(id),
    email         TEXT NOT NULL,
    display_name  TEXT NOT NULL,
    password_hash TEXT,
    external_sub  TEXT,
    status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    version       INT NOT NULL DEFAULT 1,
    UNIQUE (tenant_id, email)
);

CREATE TABLE incident.incident_types (
    id            UUID PRIMARY KEY DEFAULT uuidv7(),
    tenant_id     UUID NOT NULL REFERENCES core.tenants(id),
    slug          TEXT NOT NULL,
    name          TEXT NOT NULL,
    dedupe_window INTERVAL NOT NULL DEFAULT '24 hours',
    reopen_policy TEXT NOT NULL DEFAULT 'new_incident'
                  CHECK (reopen_policy IN ('new_incident','reopen','append')),
    UNIQUE (tenant_id, slug)
);

CREATE TABLE incident.incidents (
    id            UUID PRIMARY KEY DEFAULT uuidv7(),
    tenant_id     UUID NOT NULL REFERENCES core.tenants(id),
    key           TEXT NOT NULL,
    type_id       UUID NOT NULL REFERENCES incident.incident_types(id),

    title         TEXT NOT NULL,
    description   TEXT,
    status        TEXT NOT NULL DEFAULT 'new'
                  CHECK (status IN ('new','triage','investigating','pending_action','resolved','closed')),
    severity      TEXT NOT NULL
                  CHECK (severity IN ('critical','high','medium','low','info')),
    priority      SMALLINT NOT NULL DEFAULT 3 CHECK (priority BETWEEN 1 AND 5),

    owner_id      UUID REFERENCES iam.users(id),
    assigned_at   TIMESTAMPTZ,

    source_rule   TEXT,
    fingerprint   BYTEA NOT NULL,
    dedupe_until  TIMESTAMPTZ,

    alert_count   INT NOT NULL DEFAULT 0,
    first_seen    TIMESTAMPTZ NOT NULL,
    last_seen     TIMESTAMPTZ NOT NULL,

    resolution    TEXT CHECK (resolution IN
                  ('true_positive','benign_true_positive','false_positive','inconclusive')),
    closed_reason TEXT,
    closed_at     TIMESTAMPTZ,
    closed_by     UUID REFERENCES iam.users(id),
    first_ack_at  TIMESTAMPTZ,

    attack_tactics    TEXT[] NOT NULL DEFAULT '{}',
    attack_techniques TEXT[] NOT NULL DEFAULT '{}',
    tags              TEXT[] NOT NULL DEFAULT '{}',

    open_mandatory_tasks INT NOT NULL DEFAULT 0,

    version       INT NOT NULL DEFAULT 1,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (tenant_id, key),

    -- Um incidente fechado precisa dizer em que deu e por quê. Sem isto, a
    -- métrica de falso positivo por regra é ficção.
    CONSTRAINT closed_needs_reason CHECK (
        status <> 'closed' OR (resolution IS NOT NULL AND closed_reason IS NOT NULL)
    )
) WITH (fillfactor = 85);

-- O invariante que faz uma regra quebrada gerar UM incidente, e não cinquenta
-- mil: um único incidente aberto por fingerprint.
CREATE UNIQUE INDEX incidents_open_fingerprint
    ON incident.incidents (tenant_id, fingerprint)
    WHERE status <> 'closed';

-- A consulta mais frequente da plataforma: a fila do analista.
CREATE INDEX incidents_queue
    ON incident.incidents (tenant_id, last_seen DESC, id DESC)
    WHERE status <> 'closed';

CREATE INDEX incidents_owner
    ON incident.incidents (tenant_id, owner_id, last_seen DESC)
    WHERE status <> 'closed';

CREATE INDEX incidents_closed
    ON incident.incidents (tenant_id, closed_at DESC)
    WHERE status = 'closed';
