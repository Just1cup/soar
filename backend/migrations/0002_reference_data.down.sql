DELETE FROM incident.incident_types
 WHERE slug IN ('generic','infra-noise','web-attack','auth-anomaly','external-exposure');
DELETE FROM core.tenants WHERE slug = 'default';
