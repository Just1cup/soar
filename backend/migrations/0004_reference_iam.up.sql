INSERT INTO iam.permissions (name, descr) VALUES
  ('incident.read',            'Ver incidentes'),
  ('incident.assign',          'Atribuir dono'),
  ('incident.close',           'Fechar incidente'),
  ('incident.reopen',          'Reabrir incidente fechado'),
  ('incident.change_severity', 'Alterar severidade'),
  ('case.task.complete',       'Concluir tarefa'),
  ('case.skip_mandatory_task', 'Pular tarefa obrigatória'),
  ('case.comment',             'Comentar no caso'),
  ('assessment.promote',       'Promover avaliação a veredito'),
  ('approval.decide',          'Aprovar ou recusar ação de resposta'),
  ('playbook.read',            'Ver playbooks'),
  ('playbook.execute',         'Executar playbook'),
  ('playbook.edit',            'Editar playbook'),
  ('rule.read',                'Ver regras de automação'),
  ('rule.edit',                'Editar regras de automação'),
  ('integration.read',         'Ver integrações'),
  ('integration.configure',    'Configurar integrações'),
  ('response.close_alerts',    'Fechar alertas no SIEM'),
  ('response.create_exception','Criar exceção de regra no SIEM'),
  -- Existem no modelo e NÃO têm adapter compilado neste deploy (AD-08):
  -- isolar o droplet já deixou a máquina inalcançável por SSH e pelo túnel.
  ('response.block_ip',        'Bloquear IP no perímetro (sem implementação)'),
  ('response.isolate_endpoint','Isolar endpoint (sem implementação)'),
  ('response.disable_user',    'Desabilitar usuário (sem implementação)'),
  ('audit.read',               'Ler a trilha de auditoria')
ON CONFLICT (name) DO NOTHING;

INSERT INTO iam.roles (tenant_id, name, descr, is_system)
SELECT t.id, v.name, v.descr, v.sys
  FROM core.tenants t,
       (VALUES
          ('analyst_l1',       'Triagem e leitura',                 false),
          ('analyst_l2',       'Investigação e resposta',           false),
          ('manager',          'Gestão do SOC',                     false),
          ('auditor',          'Somente leitura, inclui auditoria', false),
          ('admin',            'Administração',                     false),
          ('system:automation','Motor de regras',                   true),
          ('system:workflow',  'Motor de playbooks',                true),
          ('system:assessment','Analista de LLM local',             true)
       ) AS v(name, descr, sys)
 WHERE t.slug = 'default'
ON CONFLICT (tenant_id, name) DO NOTHING;

-- analyst_l1: triagem, sem fechar.
INSERT INTO iam.role_permissions (role_id, permission)
SELECT r.id, p FROM iam.roles r,
     unnest(ARRAY['incident.read','incident.assign','case.task.complete','case.comment']) p
 WHERE r.name = 'analyst_l1' ON CONFLICT DO NOTHING;

-- analyst_l2: investiga, fecha e executa resposta reversível.
INSERT INTO iam.role_permissions (role_id, permission)
SELECT r.id, p FROM iam.roles r,
     unnest(ARRAY['incident.read','incident.assign','incident.close','incident.change_severity',
                  'case.task.complete','case.comment','assessment.promote','approval.decide',
                  'playbook.read','playbook.execute','rule.read','integration.read',
                  'response.close_alerts','response.create_exception']) p
 WHERE r.name = 'analyst_l2' ON CONFLICT DO NOTHING;

INSERT INTO iam.role_permissions (role_id, permission)
SELECT r.id, p FROM iam.roles r,
     unnest(ARRAY['incident.read','incident.assign','incident.close','incident.reopen',
                  'incident.change_severity','case.task.complete','case.skip_mandatory_task',
                  'case.comment','assessment.promote','approval.decide','playbook.read',
                  'playbook.execute','playbook.edit','rule.read','rule.edit',
                  'integration.read','audit.read']) p
 WHERE r.name = 'manager' ON CONFLICT DO NOTHING;

-- auditor: lê tudo, não escreve nada. É o papel que torna a trilha
-- consultável sem dar poder de mudar produção.
INSERT INTO iam.role_permissions (role_id, permission)
SELECT r.id, p FROM iam.roles r,
     unnest(ARRAY['incident.read','playbook.read','rule.read','integration.read','audit.read']) p
 WHERE r.name = 'auditor' ON CONFLICT DO NOTHING;

INSERT INTO iam.role_permissions (role_id, permission)
SELECT r.id, p.name FROM iam.roles r, iam.permissions p
 WHERE r.name = 'admin' ON CONFLICT DO NOTHING;

-- O motor de regras pode etiquetar, atribuir, comentar e fechar como benigno.
-- NÃO pode reabrir, nem aprovar ação, nem mexer em regra ou integração.
INSERT INTO iam.role_permissions (role_id, permission)
SELECT r.id, p FROM iam.roles r,
     unnest(ARRAY['incident.read','incident.assign','incident.close',
                  'incident.change_severity','case.comment','playbook.execute']) p
 WHERE r.name = 'system:automation' ON CONFLICT DO NOTHING;

-- O modelo, por construção, não pode fechar nada: ele produz um artefato, e
-- promovê-lo a veredito é ato de um humano ou de uma regra explícita.
INSERT INTO iam.role_permissions (role_id, permission)
SELECT r.id, p FROM iam.roles r, unnest(ARRAY['incident.read','case.comment']) p
 WHERE r.name = 'system:assessment' ON CONFLICT DO NOTHING;

INSERT INTO iam.role_permissions (role_id, permission)
SELECT r.id, p FROM iam.roles r,
     unnest(ARRAY['incident.read','case.comment','playbook.execute',
                  'response.close_alerts','response.create_exception']) p
 WHERE r.name = 'system:workflow' ON CONFLICT DO NOTHING;
