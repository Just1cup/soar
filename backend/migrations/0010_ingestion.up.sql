-- Fase 2, F-04 + F-23: ingestão. Seis modos atrás de um pipeline só
-- (docs/soar/08 §2), com a durabilidade sendo propriedade do modo.

CREATE TABLE incident.alert_sources (
    id         UUID PRIMARY KEY DEFAULT uuidv7(),
    tenant_id  UUID NOT NULL REFERENCES core.tenants(id),
    slug       TEXT NOT NULL,
    name       TEXT NOT NULL,
    kind       TEXT NOT NULL CHECK (kind IN
               ('elastic-siem','surface-monitor','generic-webhook','generic-json-pull',
                'file-batch','manual')),
    mode       TEXT NOT NULL CHECK (mode IN ('pull','push','stream','batch','agent','manual')),
    config     JSONB NOT NULL DEFAULT '{}',
    classifier TEXT,
    mapper     TEXT,
    default_incident_type TEXT NOT NULL DEFAULT 'generic',
    enabled    BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, slug)
);

-- O cursor mora no banco, não na memória do pod, e só avança DEPOIS do aceite
-- durável. É isso que torna o pull at-least-once em vez de melhor esforço:
-- se o sink falhar, o cursor não anda e o ciclo seguinte repete — e a
-- duplicata morre no dedupe.
CREATE TABLE incident.source_cursors (
    source_id   UUID PRIMARY KEY REFERENCES incident.alert_sources(id) ON DELETE CASCADE,
    tenant_id   UUID NOT NULL,
    -- Modelo lastRun do XSOAR: last_fetch_time + seen_ids + next_token.
    -- Resolve o caso documentado de itens com timestamp idêntico atravessando
    -- ciclos, que com `>` perde e com `>=` duplica.
    cursor      JSONB NOT NULL DEFAULT '{}',
    advanced_at TIMESTAMPTZ,
    version     INT NOT NULL DEFAULT 1
);

-- O bruto é guardado SEMPRE. Todo mapper nasce errado em algum campo, e sem o
-- bruto o conserto é retroativo só no papel.
CREATE TABLE platform.raw_intake (
    id             UUID NOT NULL DEFAULT uuidv7(),
    tenant_id      UUID NOT NULL,
    source_id      UUID NOT NULL,
    receipt_id     UUID NOT NULL,
    mode           TEXT NOT NULL,
    content_type   TEXT NOT NULL DEFAULT 'application/json',
    payload        JSONB,
    payload_sha256 BYTEA NOT NULL,
    size_bytes     INT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'accepted' CHECK (status IN
                   ('accepted','mapped','duplicate','quarantined','failed')),
    quarantine_reason TEXT,
    attempts       SMALLINT NOT NULL DEFAULT 0,
    ingested_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    processed_at   TIMESTAMPTZ,
    PRIMARY KEY (ingested_at, id)
) PARTITION BY RANGE (ingested_at);

CREATE INDEX raw_intake_pending ON platform.raw_intake (ingested_at)
    WHERE status = 'accepted';
CREATE INDEX raw_intake_quarantine ON platform.raw_intake (tenant_id, ingested_at DESC)
    WHERE status = 'quarantined';
CREATE INDEX raw_intake_brin ON platform.raw_intake USING BRIN (ingested_at);

CREATE TABLE incident.alerts (
    id                UUID PRIMARY KEY DEFAULT uuidv7(),
    tenant_id         UUID NOT NULL REFERENCES core.tenants(id),
    source_id         UUID NOT NULL REFERENCES incident.alert_sources(id),
    external_alert_id TEXT NOT NULL,
    incident_id       UUID REFERENCES incident.incidents(id) ON DELETE SET NULL,
    raw_intake_id     UUID,

    fingerprint       BYTEA NOT NULL,
    title             TEXT NOT NULL,
    rule_id           TEXT,
    rule_name         TEXT NOT NULL,
    severity          TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
    status            TEXT NOT NULL DEFAULT 'new' CHECK (status IN
                      ('new','grouped','suppressed','closed')),
    -- `drop` NUNCA apaga: marca o alerta com a regra que o suprimiu, e ele
    -- continua consultável. Uma supressão invisível é indistinguível de uma
    -- perda (docs/soar/04, F-04).
    suppressed_by     UUID,
    suppressed_reason TEXT,

    host              TEXT,
    entity            TEXT,
    entity_kind       TEXT,

    event_time        TIMESTAMPTZ NOT NULL,
    ingested_at       TIMESTAMPTZ NOT NULL DEFAULT now(),

    normalized_data   JSONB NOT NULL DEFAULT '{}',
    -- Ponteiro para o documento no SIEM, não cópia: o Postgres guarda o que
    -- aconteceu e qual é o estado, não 30 milhões de eventos brutos.
    source_ref        JSONB NOT NULL DEFAULT '{}',

    -- O coração da idempotência de ingestão. Entrega at-least-once do Elastic
    -- mais ON CONFLICT DO NOTHING é muito mais barato e confiável do que
    -- perseguir exactly-once através de seis fornecedores.
    CONSTRAINT alerts_external_unique UNIQUE (tenant_id, source_id, external_alert_id)
);
CREATE INDEX alerts_by_incident ON incident.alerts (tenant_id, incident_id, event_time);
CREATE INDEX alerts_by_fingerprint ON incident.alerts (tenant_id, fingerprint, event_time DESC);
CREATE INDEX alerts_suppressed ON incident.alerts (tenant_id, suppressed_by, ingested_at DESC)
    WHERE status = 'suppressed';

-- "O conector do QRadar parou de trazer alertas às 03:12" vira consulta, e
-- não suspeita. É a falha mais comum e mais silenciosa de qualquer SOAR.
CREATE TABLE platform.connector_runs (
    id            UUID PRIMARY KEY DEFAULT uuidv7(),
    tenant_id     UUID NOT NULL,
    source_id     UUID NOT NULL REFERENCES incident.alert_sources(id) ON DELETE CASCADE,
    started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at   TIMESTAMPTZ,
    fetched       INT NOT NULL DEFAULT 0,
    accepted      INT NOT NULL DEFAULT 0,
    duplicates    INT NOT NULL DEFAULT 0,
    quarantined   INT NOT NULL DEFAULT 0,
    incidents_created INT NOT NULL DEFAULT 0,
    incidents_updated INT NOT NULL DEFAULT 0,
    cursor_before JSONB,
    cursor_after  JSONB,
    status        TEXT NOT NULL CHECK (status IN ('running','succeeded','partial','failed')),
    error         TEXT,
    duration_ms   INT
);
CREATE INDEX connector_runs_recent ON platform.connector_runs (source_id, started_at DESC);

-- Partições do raw_intake, com o mesmo padrão da auditoria.
CREATE OR REPLACE FUNCTION platform.ensure_intake_partitions(months_ahead INT DEFAULT 3)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE m INT; start_at DATE; end_at DATE; part TEXT;
BEGIN
    FOR m IN -1..months_ahead LOOP
        start_at := date_trunc('month', now())::date + (m || ' months')::interval;
        end_at   := start_at + interval '1 month';
        part     := format('raw_intake_%s', to_char(start_at, 'YYYY_MM'));
        IF NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                        WHERE n.nspname = 'platform' AND c.relname = part) THEN
            EXECUTE format(
                'CREATE TABLE platform.%I PARTITION OF platform.raw_intake FOR VALUES FROM (%L) TO (%L)',
                part, start_at, end_at);
        END IF;
    END LOOP;
END;
$$;
SELECT platform.ensure_intake_partitions(3);
CREATE TABLE platform.raw_intake_default PARTITION OF platform.raw_intake DEFAULT;
