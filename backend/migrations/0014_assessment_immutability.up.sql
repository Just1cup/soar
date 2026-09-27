-- A primeira versão do trigger protegia o raciocínio e o veredito, mas ainda
-- deixava metadados como modelo, título e notas Admiralty editáveis. O
-- artefato inteiro é histórico: somente a primeira promoção pode alterá-lo.
CREATE OR REPLACE FUNCTION assessment.reject_body_edit() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF (to_jsonb(NEW) - 'promoted_at' - 'promoted_by') IS DISTINCT FROM
       (to_jsonb(OLD) - 'promoted_at' - 'promoted_by') THEN
        RAISE EXCEPTION 'uma avaliação é imutável: crie outra com supersedes'
            USING ERRCODE = 'insufficient_privilege';
    END IF;

    IF OLD.promoted_at IS NOT NULL AND
       (NEW.promoted_at IS DISTINCT FROM OLD.promoted_at OR
        NEW.promoted_by IS DISTINCT FROM OLD.promoted_by) THEN
        RAISE EXCEPTION 'uma promoção já registrada é imutável'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END;
$$;
