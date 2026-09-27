-- Vincula o token de duplo envio à sessão. Sessões criadas antes desta
-- migration recebem um hash impossível de produzir a partir de um cookie e,
-- portanto, precisam autenticar novamente.
ALTER TABLE iam.sessions ADD COLUMN csrf_hash BYTEA;
UPDATE iam.sessions
   SET csrf_hash = decode(repeat('00', 32), 'hex')
 WHERE csrf_hash IS NULL;
ALTER TABLE iam.sessions ALTER COLUMN csrf_hash SET NOT NULL;
