CREATE OR REPLACE FUNCTION assessment.reject_body_edit() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.body IS DISTINCT FROM OLD.body
       OR NEW.verdict IS DISTINCT FROM OLD.verdict
       OR NEW.summary IS DISTINCT FROM OLD.summary
       OR NEW.case_context IS DISTINCT FROM OLD.case_context THEN
        RAISE EXCEPTION 'uma avaliação é imutável: crie outra com supersedes'
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NEW;
END;
$$;
