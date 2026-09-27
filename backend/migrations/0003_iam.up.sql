-- Autenticação e autorização. O RBAC é verificado no backend, no use case —
-- nunca no handler e nunca no frontend (docs/soar/03 §12.2).

CREATE TABLE iam.roles (
    id         UUID PRIMARY KEY DEFAULT uuidv7(),
    tenant_id  UUID NOT NULL REFERENCES core.tenants(id),
    name       TEXT NOT NULL,
    descr      TEXT NOT NULL DEFAULT '',
    -- Papéis de sistema (system:automation, system:workflow) existem porque
    -- limitar o que uma regra automática pode fazer É controle de segurança:
    -- é o que impede uma regra mal escrita de fechar incidente crítico.
    is_system  BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE iam.permissions (
    name  TEXT PRIMARY KEY,
    descr TEXT NOT NULL
);

CREATE TABLE iam.role_permissions (
    role_id    UUID NOT NULL REFERENCES iam.roles(id) ON DELETE CASCADE,
    permission TEXT NOT NULL REFERENCES iam.permissions(name) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission)
);

CREATE TABLE iam.user_roles (
    user_id    UUID NOT NULL REFERENCES iam.users(id) ON DELETE CASCADE,
    role_id    UUID NOT NULL REFERENCES iam.roles(id) ON DELETE CASCADE,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    granted_by UUID REFERENCES iam.users(id),
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE iam.sessions (
    id         UUID PRIMARY KEY DEFAULT uuidv7(),
    tenant_id  UUID NOT NULL REFERENCES core.tenants(id),
    user_id    UUID NOT NULL REFERENCES iam.users(id) ON DELETE CASCADE,
    -- Nunca o token em claro: quem lê o banco não pode se passar por ninguém.
    token_hash BYTEA NOT NULL UNIQUE,
    issued_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    source_ip  INET,
    user_agent TEXT
);
CREATE INDEX sessions_live ON iam.sessions (expires_at) WHERE revoked_at IS NULL;
CREATE INDEX sessions_user ON iam.sessions (user_id) WHERE revoked_at IS NULL;
