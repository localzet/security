use async_trait::async_trait;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    identity::Application,
    oauth::AuthorizationCode,
    session::{Session, TokenFamilyId},
    token::RefreshTokenRecord,
    TenantId,
};

#[async_trait]
pub trait TenantScopedRepository {
    async fn assert_tenant_scope(&self, tenant_id: TenantId) -> Result<(), RepositoryError>;
}

#[async_trait]
pub trait ApplicationRepository: TenantScopedRepository {
    async fn get_by_client_id(
        &self,
        tenant_id: TenantId,
        client_id: &str,
    ) -> Result<Option<Application>, RepositoryError>;
}

#[async_trait]
pub trait SessionRepository: TenantScopedRepository {
    async fn save_session(&self, session: &Session) -> Result<(), RepositoryError>;
    async fn get_session(
        &self,
        tenant_id: TenantId,
        session_id: Uuid,
    ) -> Result<Option<Session>, RepositoryError>;
}

#[async_trait]
pub trait RefreshTokenRepository: TenantScopedRepository {
    async fn save_refresh_token(&self, record: &RefreshTokenRecord) -> Result<(), RepositoryError>;
    async fn find_refresh_token_by_hash(
        &self,
        tenant_id: TenantId,
        token_hash: &str,
    ) -> Result<Option<RefreshTokenRecord>, RepositoryError>;
    async fn revoke_family(
        &self,
        tenant_id: TenantId,
        family_id: TokenFamilyId,
    ) -> Result<(), RepositoryError>;
}

#[async_trait]
pub trait AuthorizationCodeRepository: TenantScopedRepository {
    async fn save_authorization_code(
        &self,
        code: &AuthorizationCode,
    ) -> Result<(), RepositoryError>;
    async fn find_authorization_code_by_hash(
        &self,
        tenant_id: TenantId,
        code_hash: &str,
    ) -> Result<Option<AuthorizationCode>, RepositoryError>;
    async fn consume_authorization_code(
        &self,
        tenant_id: TenantId,
        code_id: Uuid,
        consumed_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), RepositoryError>;
}

#[derive(Debug, Error)]
pub enum RepositoryError {
    #[error("tenant scope violation")]
    TenantScopeViolation,
    #[error("conflict")]
    Conflict,
    #[error("not found")]
    NotFound,
    #[error("serialization failure: {message}")]
    Serialization { message: String },
    #[error("storage failure: {message}")]
    Storage { message: String },
}
