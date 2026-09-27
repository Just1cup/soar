DROP TRIGGER IF EXISTS assessments_immutable ON assessment.assessments;
DROP FUNCTION IF EXISTS assessment.reject_body_edit();
DROP TABLE IF EXISTS assessment.assessments;
DROP SCHEMA IF EXISTS assessment;
