use chrono::{Duration, Utc};
use localzet_crypto::OpaqueTokenService;
use localzet_domain::{
    ApplicationRepository, AuthorizationCode, AuthorizationCodeRepository, AuthorizationCodeStatus,
    PkceChallengeMethod, RefreshTokenRecord, RefreshTokenRepository, RefreshTokenStatus,
    RepositoryError, TenantId, TokenFamilyId, TokenSubject, UserId,
};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AuthorizationCodeService {
    tokens: OpaqueTokenService,
    code_ttl: Duration,
}

impl Default for AuthorizationCodeService {
    fn default() -> Self {
        Self {
            tokens: OpaqueTokenService,
            code_ttl: Duration::minutes(10),
        }
    }
}

impl AuthorizationCodeService {
    pub fn new(tokens: OpaqueTokenService, code_ttl: Duration) -> Self {
        Self { tokens, code_ttl }
    }

    pub async fn issue_code<R>(
        &self,
        applications: &R,
        codes: &R,
        tenant_id: TenantId,
        client_id: &str,
        user_id: UserId,
        redirect_uri: Url,
        scopes: Vec<String>,
        code_challenge: &str,
        code_challenge_method: PkceChallengeMethod,
    ) -> Result<IssuedAuthorizationCode, AuthServiceError>
    where
        R: ApplicationRepository + AuthorizationCodeRepository + Sync,
    {
        let application = applications
            .get_by_client_id(tenant_id, client_id)
            .await?
            .ok_or(AuthServiceError::UnknownClient)?;

        if !application
            .redirect_uris
            .iter()
            .any(|registered| registered == &redirect_uri)
        {
            return Err(AuthServiceError::InvalidRedirectUri);
        }

        let code = self.tokens.generate(32);
        let record = AuthorizationCode {
            code_id: Uuid::new_v4(),
            tenant_id,
            client_id: client_id.to_owned(),
            user_id,
            redirect_uri,
            scopes,
            code_hash: self.tokens.sha256(&code),
            code_challenge: code_challenge.to_owned(),
            code_challenge_method,
            expires_at: Utc::now() + self.code_ttl,
            consumed_at: None,
            status: AuthorizationCodeStatus::Active,
        };

        codes.save_authorization_code(&record).await?;

        Ok(IssuedAuthorizationCode {
            code,
            expires_at: record.expires_at,
        })
    }

    pub async fn consume_code<R>(
        &self,
        repository: &R,
        tenant_id: TenantId,
        code: &str,
        code_verifier: &str,
    ) -> Result<AuthorizationCode, AuthServiceError>
    where
        R: AuthorizationCodeRepository + Sync,
    {
        let code_hash = self.tokens.sha256(code);
        let record = repository
            .find_authorization_code_by_hash(tenant_id, &code_hash)
            .await?
            .ok_or(AuthServiceError::AuthorizationCodeNotFound)?;

        if !matches!(record.status, AuthorizationCodeStatus::Active) {
            return Err(AuthServiceError::AuthorizationCodeNotActive);
        }

        if record.expires_at <= Utc::now() {
            return Err(AuthServiceError::AuthorizationCodeExpired);
        }

        let verifier_hash = self.tokens.sha256(code_verifier);
        if record.code_challenge != verifier_hash {
            return Err(AuthServiceError::InvalidPkceVerifier);
        }

        repository
            .consume_authorization_code(tenant_id, record.code_id, Utc::now())
            .await?;

        Ok(record)
    }
}

#[derive(Debug, Clone)]
pub struct RefreshTokenService {
    tokens: OpaqueTokenService,
    token_ttl: Duration,
}

impl Default for RefreshTokenService {
    fn default() -> Self {
        Self {
            tokens: OpaqueTokenService,
            token_ttl: Duration::days(30),
        }
    }
}

impl RefreshTokenService {
    pub fn new(tokens: OpaqueTokenService, token_ttl: Duration) -> Self {
        Self { tokens, token_ttl }
    }

    pub async fn issue_initial_token<R>(
        &self,
        repository: &R,
        tenant_id: TenantId,
        subject: TokenSubject,
    ) -> Result<IssuedRefreshToken, AuthServiceError>
    where
        R: RefreshTokenRepository + Sync,
    {
        let family_id = TokenFamilyId(Uuid::new_v4());
        self.persist_new_refresh_token(repository, tenant_id, family_id, subject)
            .await
    }

    pub async fn rotate_refresh_token<R>(
        &self,
        repository: &R,
        tenant_id: TenantId,
        refresh_token: &str,
    ) -> Result<IssuedRefreshToken, AuthServiceError>
    where
        R: RefreshTokenRepository + Sync,
    {
        let token_hash = self.tokens.sha256(refresh_token);
        let existing = repository
            .find_refresh_token_by_hash(tenant_id, &token_hash)
            .await?
            .ok_or(AuthServiceError::RefreshTokenNotFound)?;

        if !matches!(existing.status, RefreshTokenStatus::Active) {
            repository
                .revoke_family(tenant_id, existing.family_id)
                .await?;
            return Err(AuthServiceError::RefreshTokenReuseDetected);
        }

        if existing.expires_at <= Utc::now() {
            return Err(AuthServiceError::RefreshTokenExpired);
        }

        let rotated = RefreshTokenRecord {
            status: RefreshTokenStatus::Rotated,
            replaced_by: Some(Uuid::new_v4()),
            ..existing.clone()
        };
        repository.save_refresh_token(&rotated).await?;

        self.persist_new_refresh_token(repository, tenant_id, existing.family_id, existing.subject)
            .await
    }

    async fn persist_new_refresh_token<R>(
        &self,
        repository: &R,
        tenant_id: TenantId,
        family_id: TokenFamilyId,
        subject: TokenSubject,
    ) -> Result<IssuedRefreshToken, AuthServiceError>
    where
        R: RefreshTokenRepository + Sync,
    {
        let raw = self.tokens.generate(32);
        let token_id = Uuid::new_v4();
        let now = Utc::now();
        let record = RefreshTokenRecord {
            token_id,
            family_id,
            tenant_id,
            subject,
            token_hash: self.tokens.sha256(&raw),
            issued_at: now,
            expires_at: now + self.token_ttl,
            status: RefreshTokenStatus::Active,
            replaced_by: None,
        };
        repository.save_refresh_token(&record).await?;

        Ok(IssuedRefreshToken {
            token_id,
            refresh_token: raw,
            family_id,
            subject: record.subject,
            expires_at: record.expires_at,
        })
    }
}

#[derive(Debug, Clone)]
pub struct IssuedAuthorizationCode {
    pub code: String,
    pub expires_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct IssuedRefreshToken {
    pub token_id: Uuid,
    pub refresh_token: String,
    pub family_id: TokenFamilyId,
    pub subject: TokenSubject,
    pub expires_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Error)]
pub enum AuthServiceError {
    #[error("unknown client")]
    UnknownClient,
    #[error("invalid redirect uri")]
    InvalidRedirectUri,
    #[error("authorization code not found")]
    AuthorizationCodeNotFound,
    #[error("authorization code is not active")]
    AuthorizationCodeNotActive,
    #[error("authorization code expired")]
    AuthorizationCodeExpired,
    #[error("invalid pkce verifier")]
    InvalidPkceVerifier,
    #[error("refresh token not found")]
    RefreshTokenNotFound,
    #[error("refresh token expired")]
    RefreshTokenExpired,
    #[error("refresh token reuse detected")]
    RefreshTokenReuseDetected,
    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    use async_trait::async_trait;
    use localzet_crypto::OpaqueTokenService;
    use localzet_domain::{
        Application, ApplicationKind, ApplicationRepository, AuthorizationCode,
        AuthorizationCodeRepository, RefreshTokenRecord, RefreshTokenRepository, RepositoryError,
        TenantScopedRepository,
    };

    use super::*;

    #[derive(Clone, Default)]
    struct InMemoryRepo {
        tenants: Arc<Mutex<Vec<TenantId>>>,
        applications: Arc<Mutex<HashMap<(TenantId, String), Application>>>,
        codes: Arc<Mutex<HashMap<(TenantId, String), AuthorizationCode>>>,
        tokens: Arc<Mutex<HashMap<(TenantId, String), RefreshTokenRecord>>>,
    }

    #[async_trait]
    impl TenantScopedRepository for InMemoryRepo {
        async fn assert_tenant_scope(&self, tenant_id: TenantId) -> Result<(), RepositoryError> {
            if self.tenants.lock().expect("tenants").contains(&tenant_id) {
                Ok(())
            } else {
                Err(RepositoryError::TenantScopeViolation)
            }
        }
    }

    #[async_trait]
    impl ApplicationRepository for InMemoryRepo {
        async fn get_by_client_id(
            &self,
            tenant_id: TenantId,
            client_id: &str,
        ) -> Result<Option<Application>, RepositoryError> {
            self.assert_tenant_scope(tenant_id).await?;
            Ok(self
                .applications
                .lock()
                .expect("applications")
                .get(&(tenant_id, client_id.to_owned()))
                .cloned())
        }
    }

    #[async_trait]
    impl AuthorizationCodeRepository for InMemoryRepo {
        async fn save_authorization_code(
            &self,
            code: &AuthorizationCode,
        ) -> Result<(), RepositoryError> {
            self.assert_tenant_scope(code.tenant_id).await?;
            self.codes
                .lock()
                .expect("codes")
                .insert((code.tenant_id, code.code_hash.clone()), code.clone());
            Ok(())
        }

        async fn find_authorization_code_by_hash(
            &self,
            tenant_id: TenantId,
            code_hash: &str,
        ) -> Result<Option<AuthorizationCode>, RepositoryError> {
            self.assert_tenant_scope(tenant_id).await?;
            Ok(self
                .codes
                .lock()
                .expect("codes")
                .get(&(tenant_id, code_hash.to_owned()))
                .cloned())
        }

        async fn consume_authorization_code(
            &self,
            tenant_id: TenantId,
            code_id: Uuid,
            consumed_at: chrono::DateTime<Utc>,
        ) -> Result<(), RepositoryError> {
            self.assert_tenant_scope(tenant_id).await?;
            let mut codes = self.codes.lock().expect("codes");
            let record = codes
                .values_mut()
                .find(|entry| entry.tenant_id == tenant_id && entry.code_id == code_id)
                .ok_or(RepositoryError::NotFound)?;
            record.consumed_at = Some(consumed_at);
            record.status = AuthorizationCodeStatus::Consumed;
            Ok(())
        }
    }

    #[async_trait]
    impl RefreshTokenRepository for InMemoryRepo {
        async fn save_refresh_token(
            &self,
            record: &RefreshTokenRecord,
        ) -> Result<(), RepositoryError> {
            self.assert_tenant_scope(record.tenant_id).await?;
            self.tokens.lock().expect("tokens").insert(
                (record.tenant_id, record.token_hash.clone()),
                record.clone(),
            );
            Ok(())
        }

        async fn find_refresh_token_by_hash(
            &self,
            tenant_id: TenantId,
            token_hash: &str,
        ) -> Result<Option<RefreshTokenRecord>, RepositoryError> {
            self.assert_tenant_scope(tenant_id).await?;
            Ok(self
                .tokens
                .lock()
                .expect("tokens")
                .get(&(tenant_id, token_hash.to_owned()))
                .cloned())
        }

        async fn revoke_family(
            &self,
            tenant_id: TenantId,
            family_id: TokenFamilyId,
        ) -> Result<(), RepositoryError> {
            self.assert_tenant_scope(tenant_id).await?;
            let mut tokens = self.tokens.lock().expect("tokens");
            for record in tokens.values_mut() {
                if record.tenant_id == tenant_id && record.family_id == family_id {
                    record.status = RefreshTokenStatus::Revoked;
                }
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn authorization_code_roundtrip_succeeds() {
        let tenant_id = TenantId(Uuid::new_v4());
        let repo = seeded_repo(tenant_id);
        let verifier = "verifier-123";
        let code_service = AuthorizationCodeService::default();
        let hasher = OpaqueTokenService;

        let issued = code_service
            .issue_code(
                &repo,
                &repo,
                tenant_id,
                "web-client",
                UserId(Uuid::new_v4()),
                "https://example.local/callback".parse().expect("redirect"),
                vec!["openid".to_owned(), "profile".to_owned()],
                &hasher.sha256(verifier),
                PkceChallengeMethod::S256,
            )
            .await
            .expect("issue code");

        let consumed = code_service
            .consume_code(&repo, tenant_id, &issued.code, verifier)
            .await
            .expect("consume code");

        assert_eq!(consumed.client_id, "web-client");
    }

    #[tokio::test]
    async fn refresh_token_reuse_is_detected() {
        let tenant_id = TenantId(Uuid::new_v4());
        let repo = seeded_repo(tenant_id);
        let service = RefreshTokenService::default();

        let first = service
            .issue_initial_token(&repo, tenant_id, TokenSubject::User(UserId(Uuid::new_v4())))
            .await
            .expect("issue initial token");

        let second = service
            .rotate_refresh_token(&repo, tenant_id, &first.refresh_token)
            .await
            .expect("rotate refresh token");

        assert_ne!(first.token_id, second.token_id);

        let error = service
            .rotate_refresh_token(&repo, tenant_id, &first.refresh_token)
            .await
            .expect_err("reuse should fail");

        assert!(matches!(error, AuthServiceError::RefreshTokenReuseDetected));
    }

    fn seeded_repo(tenant_id: TenantId) -> InMemoryRepo {
        let repo = InMemoryRepo::default();
        repo.tenants.lock().expect("tenants").push(tenant_id);
        repo.applications.lock().expect("applications").insert(
            (tenant_id, "web-client".to_owned()),
            Application {
                client_id: "web-client".to_owned(),
                kind: ApplicationKind::Web,
                redirect_uris: vec!["https://example.local/callback".parse().expect("redirect")],
                scopes: vec!["openid".to_owned(), "profile".to_owned()],
            },
        );
        repo
    }
}
