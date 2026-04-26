use std::{collections::HashSet, net::SocketAddr};

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
    routing::{get, post},
    Form, Json, Router,
};
use localzet_auth_core::{
    AuthServiceError, AuthorizationCodeService, DiscoveryService, JwtIssuer, RefreshTokenService,
};
use localzet_config::{BootstrapConfig, DatabaseConfig, HttpConfig, SigningConfig};
use localzet_domain::{PkceChallengeMethod, TenantId, TokenSubject, UserId};
use localzet_storage::PostgresStore;
use serde::{Deserialize, Serialize};
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use url::Url;
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    discovery: DiscoveryService,
    store: Option<PostgresStore>,
    issuer: Option<JwtIssuer>,
    authorization_codes: AuthorizationCodeService,
    refresh_tokens: RefreshTokenService,
}

#[tokio::main]
async fn main() {
    init_tracing();

    let config = HttpConfig::from_env().expect("valid config");
    let bind_addr: SocketAddr = config.bind_addr.parse().expect("valid bind address");
    let store = init_store().await;
    let app_state = AppState {
        discovery: DiscoveryService::new(&config),
        store,
        issuer: init_issuer(&config),
        authorization_codes: AuthorizationCodeService::default(),
        refresh_tokens: RefreshTokenService::default(),
    };

    let app = Router::new()
        .route("/health/live", get(liveness))
        .route("/health/ready", get(readiness))
        .route("/oauth/authorize", get(authorize))
        .route("/oauth/token", post(token))
        .route("/oauth/introspect", post(introspect))
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/.well-known/jwks.json", get(jwks))
        .with_state(app_state)
        .layer(TraceLayer::new_for_http());

    info!(%bind_addr, "starting authd");

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .expect("listener bind");

    axum::serve(listener, app).await.expect("server failure");
}

async fn init_store() -> Option<PostgresStore> {
    match DatabaseConfig::from_env_optional() {
        Ok(Some(config)) => match PostgresStore::connect(&config).await {
            Ok(store) => {
                if let Err(error) = bootstrap_store(&store).await {
                    warn!(%error, "bootstrap initialization failed");
                }
                Some(store)
            }
            Err(error) => {
                warn!(%error, "database initialization failed; readiness will report degraded status");
                None
            }
        },
        Ok(None) => None,
        Err(error) => {
            warn!(%error, "database configuration is invalid; readiness will report degraded status");
            None
        }
    }
}

fn init_issuer(http: &HttpConfig) -> Option<JwtIssuer> {
    match SigningConfig::from_env_optional() {
        Ok(Some(config)) => match JwtIssuer::new(http, &config) {
            Ok(issuer) => Some(issuer),
            Err(error) => {
                warn!(%error, "signing configuration is invalid; token endpoint will be degraded");
                None
            }
        },
        Ok(None) => None,
        Err(error) => {
            warn!(%error, "signing configuration is invalid; token endpoint will be degraded");
            None
        }
    }
}

async fn bootstrap_store(store: &PostgresStore) -> Result<(), String> {
    let Some(config) = BootstrapConfig::from_env_optional().map_err(|error| error.to_string())?
    else {
        return Ok(());
    };

    sqlx::query(
        r#"
        INSERT INTO tenants (tenant_id, slug, display_name)
        VALUES ($1, $2, $3)
        ON CONFLICT (tenant_id) DO UPDATE SET
            slug = EXCLUDED.slug,
            display_name = EXCLUDED.display_name
        "#,
    )
    .bind(config.tenant_id.0)
    .bind(&config.tenant_slug)
    .bind(&config.tenant_display_name)
    .execute(store.pool())
    .await
    .map_err(|error| error.to_string())?;

    let redirect_uris = serde_json::json!([config.redirect_uri.as_str()]);
    let scopes = serde_json::json!(["openid", "profile", "offline_access"]);

    sqlx::query(
        r#"
        INSERT INTO applications (tenant_id, client_id, kind, redirect_uris, scopes)
        VALUES ($1, $2, 'web', $3::jsonb, $4::jsonb)
        ON CONFLICT (tenant_id, client_id) DO UPDATE SET
            redirect_uris = EXCLUDED.redirect_uris,
            scopes = EXCLUDED.scopes
        "#,
    )
    .bind(config.tenant_id.0)
    .bind(&config.client_id)
    .bind(redirect_uris)
    .bind(scopes)
    .execute(store.pool())
    .await
    .map_err(|error| error.to_string())?;

    Ok(())
}

fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,tower_http=info".to_owned()),
        )
        .with_target(false)
        .compact()
        .init();
}

async fn liveness() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn readiness(State(state): State<AppState>) -> impl IntoResponse {
    if let Some(store) = &state.store {
        if localzet_storage::postgres::healthcheck(store.pool())
            .await
            .is_err()
        {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "status": "degraded",
                    "reason": "database_unavailable"
                })),
            );
        }
    }

    (
        StatusCode::OK,
        Json(serde_json::to_value(state.discovery.readiness()).expect("serializable readiness")),
    )
}

async fn discovery(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.discovery.document())
}

async fn jwks(State(state): State<AppState>) -> impl IntoResponse {
    let keys = state
        .issuer
        .as_ref()
        .map(|issuer| vec![issuer.jwk()])
        .unwrap_or_default();
    (
        StatusCode::OK,
        Json(localzet_auth_core::JwksDocument { keys }),
    )
}

async fn authorize(
    State(state): State<AppState>,
    Query(query): Query<AuthorizationRequest>,
) -> Result<Redirect, OAuthErrorResponse> {
    let store = state
        .store
        .as_ref()
        .ok_or_else(|| OAuthErrorResponse::server_error("storage unavailable"))?;
    let tenant_id = parse_tenant_id(&query.tenant_id)?;
    let user_id = parse_user_id(&query.user_id)?;

    if query.response_type != "code" {
        return Err(OAuthErrorResponse::invalid_request(
            "unsupported response_type",
        ));
    }

    if query.code_challenge_method.as_deref() != Some("S256") {
        return Err(OAuthErrorResponse::invalid_request(
            "code_challenge_method must be S256",
        ));
    }

    let redirect_uri = query
        .redirect_uri
        .parse::<Url>()
        .map_err(|_| OAuthErrorResponse::invalid_request("invalid redirect_uri"))?;
    let scopes = split_scopes(&query.scope);

    let issued = state
        .authorization_codes
        .issue_code(
            store,
            store,
            tenant_id,
            &query.client_id,
            user_id,
            redirect_uri.clone(),
            scopes,
            query
                .code_challenge
                .as_deref()
                .ok_or_else(|| OAuthErrorResponse::invalid_request("code_challenge is required"))?,
            PkceChallengeMethod::S256,
        )
        .await
        .map_err(map_auth_error)?;

    let mut callback = redirect_uri;
    {
        let mut pairs = callback.query_pairs_mut();
        pairs.append_pair("code", &issued.code);
        if let Some(state) = &query.state {
            pairs.append_pair("state", state);
        }
    }

    Ok(Redirect::to(callback.as_str()))
}

async fn token(
    State(state): State<AppState>,
    Form(form): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, OAuthErrorResponse> {
    let store = state
        .store
        .as_ref()
        .ok_or_else(|| OAuthErrorResponse::server_error("storage unavailable"))?;
    let tenant_id = parse_tenant_id(&form.tenant_id)?;
    let issuer = state
        .issuer
        .as_ref()
        .ok_or_else(|| OAuthErrorResponse::server_error("signing unavailable"))?;

    match form.grant_type.as_str() {
        "authorization_code" => {
            let client_id = form
                .client_id
                .as_deref()
                .ok_or_else(|| OAuthErrorResponse::invalid_request("client_id is required"))?;
            let redirect_uri = form
                .redirect_uri
                .as_deref()
                .ok_or_else(|| OAuthErrorResponse::invalid_request("redirect_uri is required"))?
                .parse::<Url>()
                .map_err(|_| OAuthErrorResponse::invalid_request("invalid redirect_uri"))?;

            let code = form
                .code
                .as_deref()
                .ok_or_else(|| OAuthErrorResponse::invalid_request("code is required"))?;
            let code_verifier = form
                .code_verifier
                .as_deref()
                .ok_or_else(|| OAuthErrorResponse::invalid_request("code_verifier is required"))?;

            let authorization = state
                .authorization_codes
                .consume_code(store, tenant_id, code, code_verifier)
                .await
                .map_err(map_auth_error)?;

            if authorization.client_id != client_id {
                return Err(OAuthErrorResponse::invalid_client());
            }

            if authorization.redirect_uri != redirect_uri {
                return Err(OAuthErrorResponse::invalid_grant("redirect_uri mismatch"));
            }

            let refresh = state
                .refresh_tokens
                .issue_initial_token(store, tenant_id, TokenSubject::User(authorization.user_id))
                .await
                .map_err(map_auth_error)?;

            let access_token = issuer
                .issue_access_token(
                    tenant_id,
                    authorization.user_id,
                    client_id,
                    &authorization.scopes,
                )
                .map_err(|_| OAuthErrorResponse::server_error("token signing failed"))?;
            let id_token = if authorization.scopes.iter().any(|scope| scope == "openid") {
                Some(
                    issuer
                        .issue_id_token(tenant_id, authorization.user_id, client_id)
                        .map_err(|_| OAuthErrorResponse::server_error("token signing failed"))?,
                )
            } else {
                None
            };

            Ok(Json(TokenResponse::from_authorization_code(
                access_token,
                authorization.scopes,
                refresh,
                id_token,
            )))
        }
        "refresh_token" => {
            let client_id = form
                .client_id
                .as_deref()
                .ok_or_else(|| OAuthErrorResponse::invalid_request("client_id is required"))?;
            let refresh_token = form
                .refresh_token
                .as_deref()
                .ok_or_else(|| OAuthErrorResponse::invalid_request("refresh_token is required"))?;

            let rotated = state
                .refresh_tokens
                .rotate_refresh_token(store, tenant_id, refresh_token)
                .await
                .map_err(map_auth_error)?;

            let access_token = issuer
                .issue_access_token(
                    tenant_id,
                    parse_subject_user_id(&rotated.subject)?,
                    client_id,
                    &["openid".to_owned(), "offline_access".to_owned()],
                )
                .map_err(|_| OAuthErrorResponse::server_error("token signing failed"))?;

            Ok(Json(TokenResponse::from_refresh_rotation(
                access_token,
                rotated,
            )))
        }
        _ => Err(OAuthErrorResponse::unsupported_grant_type()),
    }
}

async fn introspect(
    State(state): State<AppState>,
    Form(form): Form<IntrospectionRequest>,
) -> Result<Json<localzet_auth_core::IntrospectionResponse>, OAuthErrorResponse> {
    let issuer = state
        .issuer
        .as_ref()
        .ok_or_else(|| OAuthErrorResponse::server_error("signing unavailable"))?;
    let client_id = form
        .client_id
        .as_deref()
        .ok_or_else(|| OAuthErrorResponse::invalid_request("client_id is required"))?;
    let token = form
        .token
        .as_deref()
        .ok_or_else(|| OAuthErrorResponse::invalid_request("token is required"))?;

    Ok(Json(
        issuer
            .introspect_access_token(token, client_id)
            .unwrap_or_else(|_| localzet_auth_core::IntrospectionResponse::inactive()),
    ))
}

fn parse_tenant_id(value: &str) -> Result<TenantId, OAuthErrorResponse> {
    value
        .parse::<Uuid>()
        .map(TenantId)
        .map_err(|_| OAuthErrorResponse::invalid_request("invalid tenant_id"))
}

fn parse_user_id(value: &Option<String>) -> Result<UserId, OAuthErrorResponse> {
    let value = value
        .as_deref()
        .ok_or_else(|| OAuthErrorResponse::invalid_request("user_id is required"))?;

    value
        .parse::<Uuid>()
        .map(UserId)
        .map_err(|_| OAuthErrorResponse::invalid_request("invalid user_id"))
}

fn split_scopes(scope: &Option<String>) -> Vec<String> {
    scope
        .as_deref()
        .map(|value| {
            value
                .split(' ')
                .filter(|part| !part.is_empty())
                .map(ToOwned::to_owned)
                .collect::<HashSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn parse_subject_user_id(subject: &TokenSubject) -> Result<UserId, OAuthErrorResponse> {
    match subject {
        TokenSubject::User(user_id) => Ok(*user_id),
        TokenSubject::ServiceAccount(_) => Err(OAuthErrorResponse::invalid_grant(
            "service account refresh token is not supported by this endpoint",
        )),
    }
}

fn map_auth_error(error: AuthServiceError) -> OAuthErrorResponse {
    match error {
        AuthServiceError::UnknownClient => OAuthErrorResponse::invalid_client(),
        AuthServiceError::InvalidRedirectUri => {
            OAuthErrorResponse::invalid_request("invalid redirect uri")
        }
        AuthServiceError::AuthorizationCodeNotFound
        | AuthServiceError::AuthorizationCodeNotActive
        | AuthServiceError::AuthorizationCodeExpired
        | AuthServiceError::InvalidPkceVerifier
        | AuthServiceError::RefreshTokenNotFound
        | AuthServiceError::RefreshTokenExpired
        | AuthServiceError::RefreshTokenReuseDetected => {
            OAuthErrorResponse::invalid_grant(&error.to_string())
        }
        AuthServiceError::Repository(_) => OAuthErrorResponse::server_error("repository failure"),
    }
}

#[derive(Debug, Deserialize)]
struct AuthorizationRequest {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    state: Option<String>,
    tenant_id: String,
    user_id: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenRequest {
    grant_type: String,
    tenant_id: String,
    client_id: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IntrospectionRequest {
    client_id: Option<String>,
    token: Option<String>,
}

#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    scope: String,
    refresh_token: Option<String>,
    id_token: Option<String>,
}

impl TokenResponse {
    fn from_authorization_code(
        access_token: String,
        scopes: Vec<String>,
        refresh: localzet_auth_core::IssuedRefreshToken,
        id_token: Option<String>,
    ) -> Self {
        Self {
            access_token,
            token_type: "Bearer",
            expires_in: 300,
            scope: scopes.join(" "),
            refresh_token: Some(refresh.refresh_token),
            id_token,
        }
    }

    fn from_refresh_rotation(
        access_token: String,
        refresh: localzet_auth_core::IssuedRefreshToken,
    ) -> Self {
        Self {
            access_token,
            token_type: "Bearer",
            expires_in: 300,
            scope: "openid offline_access".to_owned(),
            refresh_token: Some(refresh.refresh_token),
            id_token: None,
        }
    }
}

#[derive(Debug, Serialize)]
struct OAuthErrorBody {
    error: &'static str,
    error_description: String,
}

struct OAuthErrorResponse {
    status: StatusCode,
    body: OAuthErrorBody,
}

impl OAuthErrorResponse {
    fn invalid_request(description: &str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            body: OAuthErrorBody {
                error: "invalid_request",
                error_description: description.to_owned(),
            },
        }
    }

    fn invalid_client() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            body: OAuthErrorBody {
                error: "invalid_client",
                error_description: "unknown client".to_owned(),
            },
        }
    }

    fn invalid_grant(description: &str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            body: OAuthErrorBody {
                error: "invalid_grant",
                error_description: description.to_owned(),
            },
        }
    }

    fn unsupported_grant_type() -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            body: OAuthErrorBody {
                error: "unsupported_grant_type",
                error_description: "unsupported grant_type".to_owned(),
            },
        }
    }

    fn server_error(description: &str) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            body: OAuthErrorBody {
                error: "server_error",
                error_description: description.to_owned(),
            },
        }
    }
}

impl IntoResponse for OAuthErrorResponse {
    fn into_response(self) -> axum::response::Response {
        (self.status, Json(self.body)).into_response()
    }
}
