use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use localzet_config::{HttpConfig, SigningConfig};
use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts, RsaPublicKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::Jwk;
use localzet_domain::{TenantId, UserId};

#[derive(Debug, Clone)]
pub struct JwtIssuer {
    issuer: String,
    key_id: String,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    jwk: Jwk,
    access_token_ttl: Duration,
    id_token_ttl: Duration,
}

impl JwtIssuer {
    pub fn new(http: &HttpConfig, signing: &SigningConfig) -> Result<Self, TokenIssuerError> {
        let public_key = RsaPublicKey::from_public_key_pem(&signing.public_key_pem)?;
        let jwk = Jwk {
            kid: signing.key_id.clone(),
            kty: "RSA".to_owned(),
            alg: "RS256".to_owned(),
            r#use: "sig".to_owned(),
            n: Base64UrlUnpadded::encode_string(&public_key.n().to_bytes_be()),
            e: Base64UrlUnpadded::encode_string(&public_key.e().to_bytes_be()),
        };

        Ok(Self {
            issuer: http.issuer.to_string(),
            key_id: signing.key_id.clone(),
            encoding_key: EncodingKey::from_rsa_pem(signing.private_key_pem.as_bytes())?,
            decoding_key: DecodingKey::from_rsa_pem(signing.public_key_pem.as_bytes())?,
            jwk,
            access_token_ttl: Duration::minutes(5),
            id_token_ttl: Duration::minutes(5),
        })
    }

    pub fn jwk(&self) -> Jwk {
        self.jwk.clone()
    }

    pub fn issue_access_token(
        &self,
        tenant_id: TenantId,
        subject: UserId,
        audience: &str,
        scopes: &[String],
    ) -> Result<String, TokenIssuerError> {
        let now = Utc::now();
        let claims = AccessTokenClaims {
            iss: self.issuer.clone(),
            sub: subject.0.to_string(),
            aud: audience.to_owned(),
            exp: (now + self.access_token_ttl).timestamp(),
            iat: now.timestamp(),
            jti: Uuid::new_v4().to_string(),
            tid: tenant_id.0.to_string(),
            scope: scopes.join(" "),
            token_use: "access".to_owned(),
        };

        self.encode(&claims)
    }

    pub fn issue_id_token(
        &self,
        tenant_id: TenantId,
        subject: UserId,
        audience: &str,
    ) -> Result<String, TokenIssuerError> {
        let now = Utc::now();
        let claims = IdTokenClaims {
            iss: self.issuer.clone(),
            sub: subject.0.to_string(),
            aud: audience.to_owned(),
            exp: (now + self.id_token_ttl).timestamp(),
            iat: now.timestamp(),
            jti: Uuid::new_v4().to_string(),
            tid: tenant_id.0.to_string(),
            auth_time: now.timestamp(),
        };

        self.encode(&claims)
    }

    pub fn introspect_access_token(
        &self,
        token: &str,
        audience: &str,
    ) -> Result<IntrospectionResponse, TokenIssuerError> {
        let claims = self.verify_access_token(token, audience)?;
        let claims = claims.0;
        Ok(IntrospectionResponse {
            active: true,
            scope: claims.scope.clone(),
            client_id: claims.aud.clone(),
            username: claims.sub.clone(),
            token_type: Some("Bearer".to_owned()),
            exp: Some(claims.exp),
            iat: Some(claims.iat),
            sub: Some(claims.sub),
            iss: Some(claims.iss),
            jti: Some(claims.jti),
            tid: Some(claims.tid),
        })
    }

    pub fn verify_access_token(
        &self,
        token: &str,
        audience: &str,
    ) -> Result<VerifiedAccessToken, TokenIssuerError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[audience]);
        validation.set_issuer(&[self.issuer.as_str()]);

        let verified = decode::<AccessTokenClaims>(token, &self.decoding_key, &validation)?;
        Ok(VerifiedAccessToken(verified.claims))
    }

    fn encode<T: Serialize>(&self, claims: &T) -> Result<String, TokenIssuerError> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.key_id.clone());

        Ok(jsonwebtoken::encode(&header, claims, &self.encoding_key)?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    jti: String,
    tid: String,
    scope: String,
    token_use: String,
}

#[derive(Debug, Serialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    jti: String,
    tid: String,
    auth_time: i64,
}

#[derive(Debug, Clone)]
pub struct VerifiedAccessToken(pub AccessTokenClaims);

#[derive(Debug, Serialize)]
pub struct IntrospectionResponse {
    pub active: bool,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub username: Option<String>,
    pub token_type: Option<String>,
    pub exp: Option<i64>,
    pub iat: Option<i64>,
    pub sub: Option<String>,
    pub iss: Option<String>,
    pub jti: Option<String>,
    pub tid: Option<String>,
}

impl IntrospectionResponse {
    pub fn inactive() -> Self {
        Self {
            active: false,
            scope: None,
            client_id: None,
            username: None,
            token_type: None,
            exp: None,
            iat: None,
            sub: None,
            iss: None,
            jti: None,
            tid: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum TokenIssuerError {
    #[error("invalid rsa private key")]
    InvalidPrivateKey(#[from] jsonwebtoken::errors::Error),
    #[error("invalid rsa public key")]
    InvalidPublicKey(#[from] rsa::pkcs8::spki::Error),
}
