DO $$
DECLARE r RECORD;
BEGIN
    FOR r IN SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname='audit' AND c.relkind IN ('r','p')
                AND (c.relname LIKE 'audit_events%' OR c.relname LIKE 'timeline_events%')
    LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS %I ON audit.%I', r.relname || '_no_truncate', r.relname);
    END LOOP;
END;
$$;
DROP FUNCTION IF EXISTS audit.guard_table(TEXT, TEXT);
DROP FUNCTION IF EXISTS audit.reject_truncate();

-- Restaura exatamente a implementação introduzida por 0005. Sem isto, fazer
-- downgrade de 0006 deixaria ensure_partitions referenciando guard_table(),
-- que acabou de ser removida, e a próxima manutenção mensal falharia.
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
