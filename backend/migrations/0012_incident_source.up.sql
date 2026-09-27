-- O incidente passa a saber de qual fonte veio. Sem isto não dá para
-- responder "o conector do QRadar criou quantos incidentes ontem?", nem para
-- desabilitar uma fonte e entender o que ela trouxe.
ALTER TABLE incident.incidents
    ADD COLUMN IF NOT EXISTS source_id UUID REFERENCES incident.alert_sources(id);

CREATE INDEX IF NOT EXISTS incidents_by_source
    ON incident.incidents (tenant_id, source_id, created_at DESC);
