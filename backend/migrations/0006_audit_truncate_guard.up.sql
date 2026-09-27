-- TRUNCATE não dispara trigger de linha. Sem isto, `TRUNCATE
-- audit.audit_events_2026_09` apagava um mês inteiro da trilha sem erro —
-- descoberto testando, depois de a migration anterior afirmar "append-only".
--
-- O caminho legítimo de arquivamento continua existindo e é deliberadamente
-- diferente: DETACH PARTITION (DDL, exige dono) e depois DROP. Apagar conteúdo
-- por DML é que não pode.

CREATE OR REPLACE FUNCTION audit.reject_truncate() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'a trilha de auditoria é append-only: TRUNCATE em %.% recusado (arquive com DETACH PARTITION)',
        TG_TABLE_SCHEMA, TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

-- Aplica os três guardas a uma tabela: UPDATE/DELETE por linha, TRUNCATE por
-- statement. Idempotente, para poder ser chamada em toda partição nova.
CREATE OR REPLACE FUNCTION audit.guard_table(schema_name TEXT, table_name TEXT)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                   WHERE n.nspname = schema_name AND c.relname = table_name
                     AND t.tgname = table_name || '_no_truncate') THEN
        EXECUTE format(
            'CREATE TRIGGER %I BEFORE TRUNCATE ON %I.%I
               FOR EACH STATEMENT EXECUTE FUNCTION audit.reject_truncate()',
            table_name || '_no_truncate', schema_name, table_name);
    END IF;
END;
$$;

-- Pais e todas as partições que já existem.
DO $$
DECLARE r RECORD;
BEGIN
    FOR r IN SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname = 'audit' AND c.relkind IN ('r','p')
                AND (c.relname LIKE 'audit_events%' OR c.relname LIKE 'timeline_events%')
    LOOP
        PERFORM audit.guard_table('audit', r.relname);
    END LOOP;
END;
$$;

-- E toda partição criada daqui em diante nasce guardada.
CREATE OR REPLACE FUNCTION audit.ensure_partitions(months_ahead INT DEFAULT 3)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    tbl TEXT; m INT; start_at DATE; end_at DATE; part TEXT;
BEGIN
    FOREACH tbl IN ARRAY ARRAY['audit_events','timeline_events'] LOOP
        FOR m IN -1..months_ahead LOOP
            start_at := date_trunc('month', now())::date + (m || ' months')::interval;
            end_at   := start_at + interval '1 month';
            part     := format('%s_%s', tbl, to_char(start_at, 'YYYY_MM'));
            IF NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                            WHERE n.nspname = 'audit' AND c.relname = part) THEN
                EXECUTE format(
                    'CREATE TABLE audit.%I PARTITION OF audit.%I FOR VALUES FROM (%L) TO (%L)',
                    part, tbl, start_at, end_at);
            END IF;
            PERFORM audit.guard_table('audit', part);
        END LOOP;
    END LOOP;
END;
$$;

SELECT audit.ensure_partitions(3);
