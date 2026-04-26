use std::str::FromStr;

use async_trait::async_trait;
use localzet_config::DatabaseConfig;
use localzet_domain::{
    AuthorizationCode, AuthorizationCodeRepository, AuthorizationCodeStatus,
    Application, ApplicationKind, ApplicationRepository, AuthenticationContext,
    AuthenticationMethod, PkceChallengeMethod, RefreshTokenRecord,
    RefreshTokenRepository, RefreshTokenStatus, RepositoryError, Session,
    SessionRepository, SessionStatus, TenantId, TenantScopedRepository,
    TokenFamilyId, TokenSubject, UserId,
};
use serde_json::Value;
use sqlx::{postgres::PgPoolOptions, Executor, PgPool, Row};
use uuid::Uuid;

#[derive(Clone)]
pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    pub async fn connect(config: &DatabaseConfig) -> Result<Self, RepositoryError> {
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .connect(&config.url)
            .await
            .map_err(storage_error)?;

        if config.run_migrations {
            sqlx::migrate!("../../db/migrations")
                .run(&pool)
                .await
                .map_err(storage_error)?;
        }

        Ok(Self { pool })
    }

    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[async_trait]
impl TenantScopedRepository for PostgresStore {
    async fn assert_tenant_scope(&self, tenant_id: TenantId) -> Result<(), RepositoryError> {
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM tenants WHERE tenant_id = $1)",
        )
        .bind(tenant_id.0)
        .fetch_one(&self.pool)
        .await
        .map_err(storage_error)?;

        if exists {
            Ok(())
        } else {
            Err(RepositoryError::TenantScopeViolation)
        }
    }
}

pub type PostgresApplicationRepository = PostgresStore;
pub type PostgresAuthorizationCodeRepository = PostgresStore;
pub type PostgresSessionRepository = PostgresStore;
pub type PostgresRefreshTokenRepository = PostgresStore;

#[async_trait]
impl ApplicationRepository for PostgresStore {
    async fn get_by_client_id(
        &self,
        tenant_id: TenantId,
        client_id: &str,
    ) -> Result<Option<Application>, RepositoryError> {
        self.assert_tenant_scope(tenant_id).await?;

        let row = sqlx::query(
            r#"
            SELECT client_id, kind, redirect_uris, scopes
            FROM applications
            WHERE tenant_id = $1 AND client_id = $2
            "#,
        )
        .bind(tenant_id.0)
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        row.map(map_application_row).transpose()
    }
}

#[async_trait]
impl SessionRepository for PostgresStore {
    async fn save_session(&self, session: &Session) -> Result<(), RepositoryError> {
        self.assert_tenant_scope(session.tenant_id).await?;

        let methods: Vec<&str> = session
            .authentication_context
            .methods
            .iter()
            .map(AuthenticationMethod::as_str)
            .collect();

        sqlx::query(
            r#"
            INSERT INTO sessions (
                session_id,
                tenant_id,
                user_id,
                created_at,
                expires_at,
                last_authenticated_at,
                authentication_methods,
                step_up_required,
                device_id,
                status
            ) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10)
            ON CONFLICT (session_id) DO UPDATE SET
                expires_at = EXCLUDED.expires_at,
                last_authenticated_at = EXCLUDED.last_authenticated_at,
                authentication_methods = EXCLUDED.authentication_methods,
                step_up_required = EXCLUDED.step_up_required,
                device_id = EXCLUDED.device_id,
                status = EXCLUDED.status
            WHERE sessions.tenant_id = EXCLUDED.tenant_id
            "#,
        )
        .bind(session.session_id)
        .bind(session.tenant_id.0)
        .bind(session.user_id.0)
        .bind(session.created_at)
        .bind(session.expires_at)
        .bind(session.last_authenticated_at)
        .bind(serde_json::to_value(methods).map_err(serialization_error)?)
        .bind(session.authentication_context.step_up_required)
        .bind(session.authentication_context.device_id)
        .bind(session.status.as_str())
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    async fn get_session(
        &self,
        tenant_id: TenantId,
        session_id: Uuid,
    ) -> Result<Option<Session>, RepositoryError> {
        self.assert_tenant_scope(tenant_id).await?;

        let row = sqlx::query(
            r#"
            SELECT
                session_id,
                tenant_id,
                user_id,
                created_at,
                expires_at,
                last_authenticated_at,
                authentication_methods,
                step_up_required,
                device_id,
                status
            FROM sessions
            WHERE tenant_id = $1 AND session_id = $2
            "#,
        )
        .bind(tenant_id.0)
        .bind(session_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        row.map(map_session_row).transpose()
    }
}

#[async_trait]
impl RefreshTokenRepository for PostgresStore {
    async fn save_refresh_token(&self, record: &RefreshTokenRecord) -> Result<(), RepositoryError> {
        self.assert_tenant_scope(record.tenant_id).await?;

        sqlx::query(
            r#"
            INSERT INTO refresh_tokens (
                token_id,
                family_id,
                tenant_id,
                subject_type,
                subject_id,
                token_hash,
                issued_at,
                expires_at,
                status,
                replaced_by
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (token_id) DO UPDATE SET
                status = EXCLUDED.status,
                replaced_by = EXCLUDED.replaced_by,
                expires_at = EXCLUDED.expires_at
            WHERE refresh_tokens.tenant_id = EXCLUDED.tenant_id
            "#,
        )
        .bind(record.token_id)
        .bind(record.family_id.0)
        .bind(record.tenant_id.0)
        .bind(record.subject.subject_type())
        .bind(record.subject.subject_id())
        .bind(&record.token_hash)
        .bind(record.issued_at)
        .bind(record.expires_at)
        .bind(record.status.as_str())
        .bind(record.replaced_by)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    async fn find_refresh_token_by_hash(
        &self,
        tenant_id: TenantId,
        token_hash: &str,
    ) -> Result<Option<RefreshTokenRecord>, RepositoryError> {
        self.assert_tenant_scope(tenant_id).await?;

        let row = sqlx::query(
            r#"
            SELECT
                token_id,
                family_id,
                tenant_id,
                subject_type,
                subject_id,
                token_hash,
                issued_at,
                expires_at,
                status,
                replaced_by
            FROM refresh_tokens
            WHERE tenant_id = $1 AND token_hash = $2
            "#,
        )
        .bind(tenant_id.0)
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        row.map(map_refresh_token_row).transpose()
    }

    async fn revoke_family(
        &self,
        tenant_id: TenantId,
        family_id: TokenFamilyId,
    ) -> Result<(), RepositoryError> {
        self.assert_tenant_scope(tenant_id).await?;

        sqlx::query(
            r#"
            UPDATE refresh_tokens
            SET status = 'revoked'
            WHERE tenant_id = $1 AND family_id = $2 AND status IN ('active', 'rotated')
            "#,
        )
        .bind(tenant_id.0)
        .bind(family_id.0)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }
}

#[async_trait]
impl AuthorizationCodeRepository for PostgresStore {
    async fn save_authorization_code(&self, code: &AuthorizationCode) -> Result<(), RepositoryError> {
        self.assert_tenant_scope(code.tenant_id).await?;

        sqlx::query(
            r#"
            INSERT INTO authorization_codes (
                code_id,
                tenant_id,
                client_id,
                user_id,
                redirect_uri,
                scopes,
                code_hash,
                code_challenge,
                code_challenge_method,
                expires_at,
                consumed_at,
                status
            ) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9, $10, $11, $12)
            ON CONFLICT (code_id) DO UPDATE SET
                consumed_at = EXCLUDED.consumed_at,
                status = EXCLUDED.status
            WHERE authorization_codes.tenant_id = EXCLUDED.tenant_id
            "#,
        )
        .bind(code.code_id)
        .bind(code.tenant_id.0)
        .bind(&code.client_id)
        .bind(code.user_id.0)
        .bind(code.redirect_uri.as_str())
        .bind(serde_json::to_value(&code.scopes).map_err(serialization_error)?)
        .bind(&code.code_hash)
        .bind(&code.code_challenge)
        .bind(code.code_challenge_method.as_str())
        .bind(code.expires_at)
        .bind(code.consumed_at)
        .bind(code.status.as_str())
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        Ok(())
    }

    async fn find_authorization_code_by_hash(
        &self,
        tenant_id: TenantId,
        code_hash: &str,
    ) -> Result<Option<AuthorizationCode>, RepositoryError> {
        self.assert_tenant_scope(tenant_id).await?;

        let row = sqlx::query(
            r#"
            SELECT
                code_id,
                tenant_id,
                client_id,
                user_id,
                redirect_uri,
                scopes,
                code_hash,
                code_challenge,
                code_challenge_method,
                expires_at,
                consumed_at,
                status
            FROM authorization_codes
            WHERE tenant_id = $1 AND code_hash = $2
            "#,
        )
        .bind(tenant_id.0)
        .bind(code_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(storage_error)?;

        row.map(map_authorization_code_row).transpose()
    }

    async fn consume_authorization_code(
        &self,
        tenant_id: TenantId,
        code_id: Uuid,
        consumed_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), RepositoryError> {
        self.assert_tenant_scope(tenant_id).await?;

        let result = sqlx::query(
            r#"
            UPDATE authorization_codes
            SET consumed_at = $3, status = 'consumed'
            WHERE tenant_id = $1 AND code_id = $2 AND status = 'active'
            "#,
        )
        .bind(tenant_id.0)
        .bind(code_id)
        .bind(consumed_at)
        .execute(&self.pool)
        .await
        .map_err(storage_error)?;

        if result.rows_affected() == 0 {
            return Err(RepositoryError::NotFound);
        }

        Ok(())
    }
}

fn map_application_row(row: sqlx::postgres::PgRow) -> Result<Application, RepositoryError> {
    let redirect_uris: Value = row.try_get("redirect_uris").map_err(storage_error)?;
    let scopes: Value = row.try_get("scopes").map_err(storage_error)?;
    let redirect_uris: Vec<String> = serde_json::from_value(redirect_uris).map_err(serialization_error)?;
    let scopes: Vec<String> = serde_json::from_value(scopes).map_err(serialization_error)?;

    Ok(Application {
        client_id: row.try_get("client_id").map_err(storage_error)?,
        kind: ApplicationKind::from_str(&row.try_get::<String, _>("kind").map_err(storage_error)?)
            .map_err(domain_error)?,
        redirect_uris: redirect_uris
            .into_iter()
            .map(|uri| uri.parse())
            .collect::<Result<_, _>>()
            .map_err(|error| RepositoryError::Serialization {
                message: error.to_string(),
            })?,
        scopes,
    })
}

fn map_session_row(row: sqlx::postgres::PgRow) -> Result<Session, RepositoryError> {
    let methods: Value = row.try_get("authentication_methods").map_err(storage_error)?;
    let methods: Vec<String> = serde_json::from_value(methods).map_err(serialization_error)?;
    let methods = methods
        .into_iter()
        .map(|value| AuthenticationMethod::from_str(&value).map_err(domain_error))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Session {
        session_id: row.try_get("session_id").map_err(storage_error)?,
        tenant_id: TenantId(row.try_get("tenant_id").map_err(storage_error)?),
        user_id: UserId(row.try_get("user_id").map_err(storage_error)?),
        created_at: row.try_get("created_at").map_err(storage_error)?,
        expires_at: row.try_get("expires_at").map_err(storage_error)?,
        last_authenticated_at: row.try_get("last_authenticated_at").map_err(storage_error)?,
        authentication_context: AuthenticationContext {
            methods,
            step_up_required: row.try_get("step_up_required").map_err(storage_error)?,
            device_id: row.try_get("device_id").map_err(storage_error)?,
        },
        status: SessionStatus::from_str(&row.try_get::<String, _>("status").map_err(storage_error)?)
            .map_err(domain_error)?,
    })
}

fn map_refresh_token_row(row: sqlx::postgres::PgRow) -> Result<RefreshTokenRecord, RepositoryError> {
    let subject_type: String = row.try_get("subject_type").map_err(storage_error)?;
    let subject_id: Uuid = row.try_get("subject_id").map_err(storage_error)?;

    Ok(RefreshTokenRecord {
        token_id: row.try_get("token_id").map_err(storage_error)?,
        family_id: TokenFamilyId(row.try_get("family_id").map_err(storage_error)?),
        tenant_id: TenantId(row.try_get("tenant_id").map_err(storage_error)?),
        subject: TokenSubject::from_parts(&subject_type, subject_id).map_err(domain_error)?,
        token_hash: row.try_get("token_hash").map_err(storage_error)?,
        issued_at: row.try_get("issued_at").map_err(storage_error)?,
        expires_at: row.try_get("expires_at").map_err(storage_error)?,
        status: RefreshTokenStatus::from_str(&row.try_get::<String, _>("status").map_err(storage_error)?)
            .map_err(domain_error)?,
        replaced_by: row.try_get("replaced_by").map_err(storage_error)?,
    })
}

fn map_authorization_code_row(row: sqlx::postgres::PgRow) -> Result<AuthorizationCode, RepositoryError> {
    let scopes: Value = row.try_get("scopes").map_err(storage_error)?;
    let scopes: Vec<String> = serde_json::from_value(scopes).map_err(serialization_error)?;

    Ok(AuthorizationCode {
        code_id: row.try_get("code_id").map_err(storage_error)?,
        tenant_id: TenantId(row.try_get("tenant_id").map_err(storage_error)?),
        client_id: row.try_get("client_id").map_err(storage_error)?,
        user_id: UserId(row.try_get("user_id").map_err(storage_error)?),
        redirect_uri: row
            .try_get::<String, _>("redirect_uri")
            .map_err(storage_error)?
            .parse()
            .map_err(serialization_error)?,
        scopes,
        code_hash: row.try_get("code_hash").map_err(storage_error)?,
        code_challenge: row.try_get("code_challenge").map_err(storage_error)?,
        code_challenge_method: PkceChallengeMethod::from_str(
            &row.try_get::<String, _>("code_challenge_method").map_err(storage_error)?,
        )
        .map_err(domain_error)?,
        expires_at: row.try_get("expires_at").map_err(storage_error)?,
        consumed_at: row.try_get("consumed_at").map_err(storage_error)?,
        status: AuthorizationCodeStatus::from_str(
            &row.try_get::<String, _>("status").map_err(storage_error)?,
        )
        .map_err(domain_error)?,
    })
}

fn storage_error(error: impl std::fmt::Display) -> RepositoryError {
    RepositoryError::Storage {
        message: error.to_string(),
    }
}

fn serialization_error(error: impl std::fmt::Display) -> RepositoryError {
    RepositoryError::Serialization {
        message: error.to_string(),
    }
}

fn domain_error(error: impl std::fmt::Display) -> RepositoryError {
    RepositoryError::Serialization {
        message: error.to_string(),
    }
}

pub async fn healthcheck<'a, E>(executor: E) -> Result<(), RepositoryError>
where
    E: Executor<'a, Database = sqlx::Postgres>,
{
    sqlx::query("SELECT 1")
        .execute(executor)
        .await
        .map_err(storage_error)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use localzet_domain::{AuthenticationMethod, RefreshTokenStatus, SessionStatus};

    #[test]
    fn string_enums_roundtrip() {
        assert_eq!(AuthenticationMethod::from_str("passkey").unwrap().as_str(), "passkey");
        assert_eq!(SessionStatus::from_str("active").unwrap().as_str(), "active");
        assert_eq!(RefreshTokenStatus::from_str("revoked").unwrap().as_str(), "revoked");
    }
}
