CREATE TABLE IF NOT EXISTS tenants (
    tenant_id UUID PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS projects (
    project_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    slug TEXT NOT NULL,
    environment TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, slug, environment)
);

CREATE TABLE IF NOT EXISTS applications (
    tenant_id UUID NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    client_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    redirect_uris JSONB NOT NULL DEFAULT '[]'::jsonb,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, client_id)
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    user_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    last_authenticated_at TIMESTAMPTZ NOT NULL,
    authentication_methods JSONB NOT NULL DEFAULT '[]'::jsonb,
    step_up_required BOOLEAN NOT NULL DEFAULT FALSE,
    device_id UUID NULL,
    status TEXT NOT NULL,
    UNIQUE (tenant_id, session_id)
);

CREATE INDEX IF NOT EXISTS idx_sessions_tenant_user
    ON sessions (tenant_id, user_id);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_id UUID PRIMARY KEY,
    family_id UUID NOT NULL,
    tenant_id UUID NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    subject_type TEXT NOT NULL,
    subject_id UUID NOT NULL,
    token_hash TEXT NOT NULL,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL,
    replaced_by UUID NULL,
    UNIQUE (tenant_id, token_id),
    UNIQUE (tenant_id, token_hash)
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family
    ON refresh_tokens (tenant_id, family_id);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_lookup
    ON refresh_tokens (tenant_id, token_hash);

CREATE TABLE IF NOT EXISTS authorization_codes (
    code_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    client_id TEXT NOT NULL,
    user_id UUID NOT NULL,
    redirect_uri TEXT NOT NULL,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    code_hash TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NULL,
    status TEXT NOT NULL,
    UNIQUE (tenant_id, code_hash)
);

CREATE INDEX IF NOT EXISTS idx_authorization_codes_lookup
    ON authorization_codes (tenant_id, code_hash);
