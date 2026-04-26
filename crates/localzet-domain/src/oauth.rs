use std::{fmt, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use crate::{TenantId, UserId};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    pub code_id: Uuid,
    pub tenant_id: TenantId,
    pub client_id: String,
    pub user_id: UserId,
    pub redirect_uri: Url,
    pub scopes: Vec<String>,
    pub code_hash: String,
    pub code_challenge: String,
    pub code_challenge_method: PkceChallengeMethod,
    pub expires_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub status: AuthorizationCodeStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PkceChallengeMethod {
    S256,
}

impl PkceChallengeMethod {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::S256 => "S256",
        }
    }
}

impl fmt::Display for PkceChallengeMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PkceChallengeMethod {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "S256" => Ok(Self::S256),
            _ => Err("unknown pkce challenge method"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizationCodeStatus {
    Active,
    Consumed,
    Expired,
    Revoked,
}

impl AuthorizationCodeStatus {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
        }
    }
}

impl fmt::Display for AuthorizationCodeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AuthorizationCodeStatus {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "active" => Ok(Self::Active),
            "consumed" => Ok(Self::Consumed),
            "expired" => Ok(Self::Expired),
            "revoked" => Ok(Self::Revoked),
            _ => Err("unknown authorization code status"),
        }
    }
}
