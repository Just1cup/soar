-- Tarefas são materializadas por incidente: a regra de origem escolhe um
-- roteiro, mas mudanças futuras no roteiro não reescrevem trabalho já feito.
CREATE TABLE incident.task_templates (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    category TEXT NOT NULL,
    phase TEXT NOT NULL,
    title TEXT NOT NULL,
    instruction TEXT NOT NULL,
    position INT NOT NULL,
    mandatory BOOLEAN NOT NULL DEFAULT true,
    UNIQUE (category, position)
);

INSERT INTO incident.task_templates (category, phase, title, instruction, position) VALUES
('general','Apropriação','Apropriar a demanda','Identifique a regra, o escopo e o responsável pela análise.',10),
('general','Detecção e análise','Confirmar o incidente e definir a severidade','Revise os alertas e registre a decisão nas notas.',20),
('general','Resposta','Definir contenção ou tuning','Escolha uma resposta proporcional e registre o resultado.',30),
('authentication','Apropriação','Validar identidade e origem','Confirme conta, IP de origem e janela do acesso.',10),
('authentication','Detecção e análise','Correlacionar logins e sessões','Verifique falhas, MFA, geolocalização e sessões próximas.',20),
('authentication','Resposta','Conter acesso indevido','Decida sobre bloqueio, revogação de sessão e reset de credenciais.',30),
('malware','Apropriação','Identificar host e processo','Confirme host, usuário, processo pai e linha de comando.',10),
('malware','Detecção e análise','Validar cadeia de execução e IOCs','Revise hashes, arquivos, rede e comportamento do processo.',20),
('malware','Resposta','Conter e erradicar','Avalie isolamento, remoção e busca por outros hosts afetados.',30),
('network','Apropriação','Delimitar origem e destino','Confirme IPs, domínios, portas e janela de atividade.',10),
('network','Detecção e análise','Correlacionar tráfego e DNS','Revise resolução, conexões, prevalência e IOCs.',20),
('network','Resposta','Decidir bloqueio ou exceção','Registre a justificativa e o escopo antes de agir.',30),
('web','Apropriação','Identificar serviço e requisição','Confirme aplicação, rota, origem e regra disparada.',10),
('web','Detecção e análise','Revisar requisições relacionadas','Verifique payload, resposta e impacto observado.',20),
('web','Resposta','Definir mitigação','Avalie bloqueio, correção ou exceção específica.',30);

INSERT INTO incident.task_templates (category, phase, title, instruction, position) VALUES
('availability','Apropriação','Confirmar serviço afetado','Identifique serviço, host e janela da indisponibilidade.',10),
('availability','Detecção e análise','Verificar impacto e causa','Correlacione erros, métricas e alterações recentes.',20),
('availability','Resposta','Restaurar e validar serviço','Registre a ação de recuperação e confirme a estabilidade.',30);

-- Padrões mais específicos têm prioridade menor. Uma regra exata pode ganhar
-- seu próprio category/template sem alterar código ou tarefas já materializadas.
CREATE TABLE incident.task_rules (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    pattern TEXT NOT NULL,
    category TEXT NOT NULL,
    priority INT NOT NULL,
    UNIQUE (pattern, category)
);
INSERT INTO incident.task_rules (pattern, category, priority) VALUES
('service disruption|indisponibilidade|outage', 'availability', 10),
('login|logon|auth|session|credential|brute|ssh|mfa|cloudtrail', 'authentication', 20),
('malware|process|execution|ransom|fileless|hash|edr', 'malware', 30),
('dns|network|traffic|domain|ip |connection|beacon|snort', 'network', 40),
('web|http|waf|url|sql injection|xss', 'web', 50);

CREATE TABLE incident.tasks (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    tenant_id UUID NOT NULL REFERENCES core.tenants(id),
    incident_id UUID NOT NULL REFERENCES incident.incidents(id) ON DELETE CASCADE,
    template_id UUID NOT NULL REFERENCES incident.task_templates(id),
    phase TEXT NOT NULL,
    title TEXT NOT NULL,
    instruction TEXT NOT NULL,
    position INT NOT NULL,
    mandatory BOOLEAN NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','done')),
    completed_at TIMESTAMPTZ,
    completed_by UUID REFERENCES iam.users(id),
    version INT NOT NULL DEFAULT 1,
    UNIQUE (incident_id, template_id)
);
CREATE INDEX tasks_by_incident ON incident.tasks (tenant_id, incident_id, position);

CREATE TABLE incident.task_notes (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    tenant_id UUID NOT NULL REFERENCES core.tenants(id),
    incident_id UUID NOT NULL REFERENCES incident.incidents(id) ON DELETE CASCADE,
    task_id UUID NOT NULL REFERENCES incident.tasks(id) ON DELETE CASCADE,
    author_id UUID REFERENCES iam.users(id),
    author_label TEXT NOT NULL,
    body TEXT NOT NULL CHECK (length(trim(body)) BETWEEN 1 AND 4000),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX task_notes_by_task ON incident.task_notes (tenant_id, task_id, created_at, id);
CREATE TRIGGER task_notes_immutable BEFORE UPDATE OR DELETE ON incident.task_notes
FOR EACH ROW EXECUTE FUNCTION audit.reject_mutation();

CREATE FUNCTION incident.task_category(rule_name TEXT, title TEXT) RETURNS TEXT
LANGUAGE sql STABLE AS $$
    SELECT COALESCE((SELECT r.category FROM incident.task_rules r
      WHERE coalesce(rule_name,'') ~* r.pattern OR coalesce(title,'') ~* r.pattern
      ORDER BY r.priority, r.id LIMIT 1), 'general')
$$;

CREATE FUNCTION incident.create_default_tasks() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status <> 'closed' THEN
        INSERT INTO incident.tasks (tenant_id, incident_id, template_id, phase, title, instruction, position, mandatory)
        SELECT NEW.tenant_id, NEW.id, t.id, t.phase, t.title, t.instruction, t.position, t.mandatory
        FROM incident.task_templates t
        WHERE t.category = incident.task_category(NEW.source_rule, NEW.title)
        ON CONFLICT (incident_id, template_id) DO NOTHING;
        UPDATE incident.incidents SET open_mandatory_tasks = (
            SELECT count(*) FROM incident.tasks
            WHERE incident_id = NEW.id AND mandatory AND status = 'pending'
        ) WHERE id = NEW.id;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER incident_default_tasks AFTER INSERT ON incident.incidents
FOR EACH ROW EXECUTE FUNCTION incident.create_default_tasks();

-- Incidentes anteriores à migration também ganham um roteiro, sem reabrir fechados.
INSERT INTO incident.tasks (tenant_id, incident_id, template_id, phase, title, instruction, position, mandatory)
SELECT i.tenant_id, i.id, t.id, t.phase, t.title, t.instruction, t.position, t.mandatory
FROM incident.incidents i JOIN incident.task_templates t
  ON t.category = incident.task_category(i.source_rule, i.title)
WHERE i.status <> 'closed'
ON CONFLICT (incident_id, template_id) DO NOTHING;
UPDATE incident.incidents i SET open_mandatory_tasks = x.n
FROM (SELECT incident_id, count(*)::int AS n FROM incident.tasks WHERE mandatory AND status = 'pending' GROUP BY incident_id) x
WHERE i.id = x.incident_id;
