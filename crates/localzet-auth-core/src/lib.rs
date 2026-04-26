pub mod service;
pub mod token;

use chrono::{Duration, Utc};
use localzet_config::HttpConfig;
use serde::Serialize;
use url::Url;

pub use service::{
    AuthServiceError, AuthorizationCodeService, IssuedAuthorizationCode,
    IssuedRefreshToken, RefreshTokenService,
};
pub use token::{
    IntrospectionResponse, JwtIssuer, TokenIssuerError, VerifiedAccessToken,
};

#[derive(Debug, Clone)]
pub struct DiscoveryService {
    issuer: Url,
}

impl DiscoveryService {
    pub fn new(config: &HttpConfig) -> Self {
        Self {
            issuer: config.issuer.clone(),
        }
    }

    pub fn document(&self) -> DiscoveryDocument {
        DiscoveryDocument {
            issuer: self.issuer.clone(),
            authorization_endpoint: self.issuer.join("/oauth/authorize").expect("valid issuer path"),
            token_endpoint: self.issuer.join("/oauth/token").expect("valid issuer path"),
            jwks_uri: self.issuer.join("/.well-known/jwks.json").expect("valid issuer path"),
            revocation_endpoint: self.issuer.join("/oauth/revoke").expect("valid issuer path"),
            introspection_endpoint: self.issuer.join("/oauth/introspect").expect("valid issuer path"),
            device_authorization_endpoint: self
                .issuer
                .join("/oauth/device_authorization")
                .expect("valid issuer path"),
            response_types_supported: vec!["code"],
            subject_types_supported: vec!["public"],
            id_token_signing_alg_values_supported: vec!["RS256"],
            scopes_supported: vec!["openid", "profile", "email", "offline_access"],
            token_endpoint_auth_methods_supported: vec!["client_secret_basic", "client_secret_post", "private_key_jwt"],
            grant_types_supported: vec![
                "authorization_code",
                "refresh_token",
                "client_credentials",
                "urn:ietf:params:oauth:grant-type:device_code",
            ],
            code_challenge_methods_supported: vec!["S256"],
            claims_supported: vec!["sub", "iss", "aud", "exp", "iat"],
        }
    }

    pub fn jwks(&self) -> JwksDocument {
        JwksDocument { keys: Vec::new() }
    }

    pub fn readiness(&self) -> Readiness {
        Readiness {
            status: "ok",
            timestamp: Utc::now(),
            cache_ttl_seconds: Duration::seconds(5).num_seconds(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveryDocument {
    pub issuer: Url,
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    pub jwks_uri: Url,
    pub revocation_endpoint: Url,
    pub introspection_endpoint: Url,
    pub device_authorization_endpoint: Url,
    pub response_types_supported: Vec<&'static str>,
    pub subject_types_supported: Vec<&'static str>,
    pub id_token_signing_alg_values_supported: Vec<&'static str>,
    pub scopes_supported: Vec<&'static str>,
    pub token_endpoint_auth_methods_supported: Vec<&'static str>,
    pub grant_types_supported: Vec<&'static str>,
    pub code_challenge_methods_supported: Vec<&'static str>,
    pub claims_supported: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct JwksDocument {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Jwk {
    pub kid: String,
    pub kty: String,
    pub alg: String,
    pub r#use: String,
    pub n: String,
    pub e: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Readiness {
    pub status: &'static str,
    pub timestamp: chrono::DateTime<Utc>,
    pub cache_ttl_seconds: i64,
}

#[cfg(test)]
mod tests {
    use localzet_config::HttpConfig;

    use super::DiscoveryService;

    #[test]
    fn discovery_uses_expected_security_defaults() {
        let config = HttpConfig {
            bind_addr: "127.0.0.1:8080".to_owned(),
            issuer: "https://auth.localzet.test".parse().expect("issuer"),
        };

        let document = DiscoveryService::new(&config).document();

        assert!(document.scopes_supported.contains(&"openid"));
        assert!(document.code_challenge_methods_supported.contains(&"S256"));
        assert!(document
            .grant_types_supported
            .contains(&"urn:ietf:params:oauth:grant-type:device_code"));
    }
}
