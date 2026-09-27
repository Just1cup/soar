-- O analista de LLM local. Nenhuma das cinco plataformas pesquisadas tem
-- isto: elas automatizam AÇÕES, nenhuma mede se a ANÁLISE que justificou a
-- ação estava certa.

CREATE SCHEMA IF NOT EXISTS assessment;

CREATE TABLE assessment.assessments (
    id                 UUID PRIMARY KEY DEFAULT uuidv7(),
    tenant_id          UUID NOT NULL REFERENCES core.tenants(id),
    incident_id        UUID NOT NULL REFERENCES incident.incidents(id) ON DELETE CASCADE,
    -- Correção gera registro NOVO. Nada edita o que se pensou na época.
    supersedes         UUID REFERENCES assessment.assessments(id),

    author_kind        TEXT NOT NULL CHECK (author_kind IN ('model','human')),
    model              TEXT,
    schema_version     SMALLINT NOT NULL DEFAULT 2,

    verdict            TEXT NOT NULL CHECK (verdict IN
                       ('true_positive','benign_true_positive','false_positive','inconclusive')),
    confidence         TEXT NOT NULL CHECK (confidence IN ('low','medium','high')),
    -- Admiralty: a fonte e a informação são graduadas SEPARADAMENTE. "A1" e
    -- "A4" são afirmações muito diferentes, e colapsá-las em um único campo
    -- de confiança perde exatamente a distinção que o analista precisa.
    source_reliability CHAR(1) NOT NULL CHECK (source_reliability IN ('A','B','C','D','E','F')),
    info_credibility   CHAR(1) NOT NULL CHECK (info_credibility IN ('1','2','3','4','5','6')),

    title              TEXT NOT NULL,
    summary            TEXT NOT NULL,
    body               JSONB NOT NULL,
    -- Construído por CÓDIGO a partir da telemetria, nunca pelo modelo.
    -- Guardado junto para que um leitor posterior possa julgar se a conclusão
    -- era razoável DADO O QUE ESTAVA DISPONÍVEL.
    case_context       JSONB NOT NULL DEFAULT '{}',

    attack_tactics     TEXT[] NOT NULL DEFAULT '{}',
    attack_techniques  TEXT[] NOT NULL DEFAULT '{}',

    -- Promover a veredito é ato de um humano ou de uma regra explícita, e
    -- vira linha na trilha de auditoria com o autor certo.
    promoted_at        TIMESTAMPTZ,
    promoted_by        UUID REFERENCES iam.users(id),

    generated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    latency_ms         INT,
    prompt_tokens      INT,

    CONSTRAINT promoted_has_actor CHECK (
        (promoted_at IS NULL AND promoted_by IS NULL) OR
        (promoted_at IS NOT NULL AND promoted_by IS NOT NULL)
    )
);

CREATE INDEX assessments_by_incident
    ON assessment.assessments (tenant_id, incident_id, generated_at DESC);
CREATE INDEX assessments_promoted
    ON assessment.assessments (tenant_id, promoted_at DESC) WHERE promoted_at IS NOT NULL;

-- Imutável na prática: a aplicação só pode inserir e promover. Editar o que
-- foi pensado na época falsificaria a própria medição que justifica existir.
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

CREATE TRIGGER assessments_immutable
    BEFORE UPDATE ON assessment.assessments
    FOR EACH ROW EXECUTE FUNCTION assessment.reject_body_edit();
