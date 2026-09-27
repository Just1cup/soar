CREATE SCHEMA IF NOT EXISTS audit;
CREATE SCHEMA IF NOT EXISTS platform;

-- ---------------------------------------------------------------- auditoria
-- Quem mandou, o que mudou, quando, e sob qual requisição. Particionada por
-- mês: DETACH + arquivo em vez de DELETE em centenas de milhões de linhas.
CREATE TABLE audit.audit_events (
    id            UUID NOT NULL DEFAULT uuidv7(),
    tenant_id     UUID NOT NULL,
    occurred_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    actor_kind    TEXT NOT NULL CHECK (actor_kind IN ('user','automation','workflow','integration','system')),
    actor_id      TEXT NOT NULL,
    on_behalf_of  TEXT,

    action        TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id   TEXT NOT NULL,
    incident_id   UUID,

    result        TEXT NOT NULL CHECK (result IN ('succeeded','failed','denied')),
    reason        TEXT,
    before_state  JSONB,
    after_state   JSONB,

    request_id    TEXT,
    trace_id      TEXT,
    execution_id  UUID,
    source_ip     INET,
    metadata      JSONB NOT NULL DEFAULT '{}',

    PRIMARY KEY (occurred_at, id)
) PARTITION BY RANGE (occurred_at);

CREATE INDEX audit_by_incident ON audit.audit_events (tenant_id, incident_id, occurred_at DESC);
CREATE INDEX audit_by_actor    ON audit.audit_events (tenant_id, actor_id, occurred_at DESC);
CREATE INDEX audit_by_action   ON audit.audit_events (tenant_id, action, occurred_at DESC);
CREATE INDEX audit_brin        ON audit.audit_events USING BRIN (occurred_at) WITH (pages_per_range = 64);

-- ----------------------------------------------------------------- timeline
-- O War Room. Sobrepõe-se à auditoria mas não é a mesma coisa: ACL, retenção
-- e volume diferentes (docs/soar/07 §6.10). Um único escritor grava nas duas.
CREATE TABLE audit.timeline_events (
    id            UUID NOT NULL DEFAULT uuidv7(),
    tenant_id     UUID NOT NULL,
    incident_id   UUID NOT NULL,
    occurred_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    event_type    TEXT NOT NULL,
    actor_kind    TEXT NOT NULL,
    actor_id      TEXT NOT NULL,
    actor_label   TEXT NOT NULL DEFAULT '',
    title         TEXT NOT NULL,
    detail        TEXT,
    payload       JSONB NOT NULL DEFAULT '{}',
    audit_id      UUID,

    PRIMARY KEY (occurred_at, id)
) PARTITION BY RANGE (occurred_at);

CREATE INDEX timeline_by_incident ON audit.timeline_events (tenant_id, incident_id, occurred_at);
CREATE INDEX timeline_brin        ON audit.timeline_events USING BRIN (occurred_at) WITH (pages_per_range = 64);

-- ------------------------------------------------------ append-only de fato
-- Regras (CREATE RULE) não são suportadas em tabela particionada, então a
-- imutabilidade vem de um trigger BEFORE que levanta exceção. Vale para todo
-- mundo, inclusive o dono do banco — e é a única garantia que se sustenta num
-- ambiente onde a aplicação conecta como owner.
--
-- Em produção, soma-se a isto o REVOKE UPDATE, DELETE para o papel da
-- aplicação (ver 0006), que é defesa em profundidade e não substituto.
CREATE OR REPLACE FUNCTION audit.reject_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'a trilha de auditoria é append-only: % em %.% recusado',
        TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER audit_events_immutable
    BEFORE UPDATE OR DELETE ON audit.audit_events
    FOR EACH ROW EXECUTE FUNCTION audit.reject_mutation();

CREATE TRIGGER timeline_events_immutable
    BEFORE UPDATE OR DELETE ON audit.timeline_events
    FOR EACH ROW EXECUTE FUNCTION audit.reject_mutation();

-- ---------------------------------------------------------------- partições
-- Cria as partições de um intervalo de meses. Um job mensal chama isto para
-- os próximos 3 meses: criar partição no caminho de escrita é como descobrir
-- que falta disco durante um incidente.
CREATE OR REPLACE FUNCTION audit.ensure_partitions(months_ahead INT DEFAULT 3)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    tbl TEXT;
    m   INT;
    start_at DATE;
    end_at   DATE;
    part     TEXT;
BEGIN
    FOREACH tbl IN ARRAY ARRAY['audit_events','timeline_events'] LOOP
        FOR m IN -1..months_ahead LOOP
            start_at := date_trunc('month', now())::date + (m || ' months')::interval;
            end_at   := start_at + interval '1 month';
            part     := format('%s_%s', tbl, to_char(start_at, 'YYYY_MM'));
            IF NOT EXISTS (
                SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                 WHERE n.nspname = 'audit' AND c.relname = part
            ) THEN
                EXECUTE format(
                    'CREATE TABLE audit.%I PARTITION OF audit.%I FOR VALUES FROM (%L) TO (%L)',
                    part, tbl, start_at, end_at);
            END IF;
        END LOOP;
    END LOOP;
END;
$$;

SELECT audit.ensure_partitions(3);

-- Rede de segurança: se o job mensal atrasar, a escrita não falha. O custo é
-- que anexar uma partição nova exige varrer a default — aceitável enquanto ela
-- estiver vazia, que é o estado esperado.
CREATE TABLE audit.audit_events_default    PARTITION OF audit.audit_events    DEFAULT;
CREATE TABLE audit.timeline_events_default PARTITION OF audit.timeline_events DEFAULT;

-- ------------------------------------------------------------------- outbox
-- A mudança de negócio e a publicação do evento na MESMA transação. Elimina
-- "commit no banco, publish falhou" sem introduzir broker (docs/soar/07, AD-04R).
CREATE TABLE platform.outbox_events (
    id             BIGSERIAL PRIMARY KEY,
    tenant_id      UUID NOT NULL,
    event_id       UUID NOT NULL DEFAULT uuidv7(),
    topic          TEXT NOT NULL,
    schema_version SMALLINT NOT NULL DEFAULT 1,
    aggregate_id   UUID,
    actor_kind     TEXT NOT NULL,
    actor_id       TEXT NOT NULL,
    payload        JSONB NOT NULL DEFAULT '{}',
    trace_id       TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at   TIMESTAMPTZ,
    attempts       SMALLINT NOT NULL DEFAULT 0,
    last_error     TEXT
);
CREATE INDEX outbox_pending ON platform.outbox_events (id) WHERE published_at IS NULL;

-- Consumidor idempotente: entrega é at-least-once em todo o produto.
CREATE TABLE platform.processed_events (
    consumer   TEXT NOT NULL,
    event_id   UUID NOT NULL,
    handled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (consumer, event_id)
);
