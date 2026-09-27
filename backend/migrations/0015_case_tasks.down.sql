DROP TRIGGER IF EXISTS incident_default_tasks ON incident.incidents;
DROP FUNCTION IF EXISTS incident.create_default_tasks();
DROP FUNCTION IF EXISTS incident.task_category(TEXT, TEXT);
DROP TABLE IF EXISTS incident.task_notes;
DROP TABLE IF EXISTS incident.tasks;
DROP TABLE IF EXISTS incident.task_rules;
DROP TABLE IF EXISTS incident.task_templates;
UPDATE incident.incidents SET open_mandatory_tasks = 0;
