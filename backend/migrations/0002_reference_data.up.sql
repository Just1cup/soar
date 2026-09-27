-- Dado de referência, não dado de demonstração: o tenant padrão e os tipos de
-- incidente que a ingestão precisa para classificar qualquer coisa.
INSERT INTO core.tenants (id, slug, name)
VALUES ('00000000-0000-7000-8000-000000000001', 'default', 'Default')
ON CONFLICT (slug) DO NOTHING;

INSERT INTO incident.incident_types (tenant_id, slug, name, dedupe_window, reopen_policy)
SELECT t.id, v.slug, v.name, v.win::interval, v.policy
FROM core.tenants t,
     (VALUES
        ('generic',           'Genérico',                  '24 hours', 'new_incident'),
        ('infra-noise',       'Ruído de infraestrutura',   '7 days',   'append'),
        ('web-attack',        'Ataque a aplicação web',    '6 hours',  'new_incident'),
        ('auth-anomaly',      'Anomalia de autenticação',  '12 hours', 'new_incident'),
        ('external-exposure', 'Exposição externa',         '30 days',  'append')
     ) AS v(slug, name, win, policy)
WHERE t.slug = 'default'
ON CONFLICT (tenant_id, slug) DO NOTHING;
