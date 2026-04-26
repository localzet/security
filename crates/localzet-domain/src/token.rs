use std::{fmt, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{session::TokenFamilyId, TenantId, UserId};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenRecord {
    pub token_id: Uuid,
    pub family_id: TokenFamilyId,
    pub tenant_id: TenantId,
    pub subject: TokenSubject,
    pub token_hash: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub status: RefreshTokenStatus,
    pub replaced_by: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenSubject {
    User(UserId),
    ServiceAccount(Uuid),
}

impl TokenSubject {
    pub const fn subject_type(&self) -> &'static str {
        match self {
            Self::User(_) => "user",
            Self::ServiceAccount(_) => "service_account",
        }
    }

    pub const fn subject_id(&self) -> Uuid {
        match self {
            Self::User(user_id) => user_id.0,
            Self::ServiceAccount(account_id) => *account_id,
        }
    }

    pub fn from_parts(subject_type: &str, subject_id: Uuid) -> Result<Self, &'static str> {
        match subject_type {
            "user" => Ok(Self::User(UserId(subject_id))),
            "service_account" => Ok(Self::ServiceAccount(subject_id)),
            _ => Err("unknown token subject type"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshTokenStatus {
    Active,
    Rotated,
    Reused,
    Revoked,
    Expired,
}

impl RefreshTokenStatus {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Rotated => "rotated",
            Self::Reused => "reused",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

impl fmt::Display for RefreshTokenStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RefreshTokenStatus {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "active" => Ok(Self::Active),
            "rotated" => Ok(Self::Rotated),
            "reused" => Ok(Self::Reused),
            "revoked" => Ok(Self::Revoked),
            "expired" => Ok(Self::Expired),
            _ => Err("unknown refresh token status"),
        }
    }
}
