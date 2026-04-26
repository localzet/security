use std::{fmt, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{TenantId, UserId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TokenFamilyId(pub Uuid);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: Uuid,
    pub tenant_id: TenantId,
    pub user_id: UserId,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_authenticated_at: DateTime<Utc>,
    pub authentication_context: AuthenticationContext,
    pub status: SessionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationContext {
    pub methods: Vec<AuthenticationMethod>,
    pub step_up_required: bool,
    pub device_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationMethod {
    Password,
    Totp,
    Passkey,
    DeviceFlow,
    ServiceCredential,
}

impl AuthenticationMethod {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Totp => "totp",
            Self::Passkey => "passkey",
            Self::DeviceFlow => "device_flow",
            Self::ServiceCredential => "service_credential",
        }
    }
}

impl fmt::Display for AuthenticationMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AuthenticationMethod {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "password" => Ok(Self::Password),
            "totp" => Ok(Self::Totp),
            "passkey" => Ok(Self::Passkey),
            "device_flow" => Ok(Self::DeviceFlow),
            "service_credential" => Ok(Self::ServiceCredential),
            _ => Err("unknown authentication method"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Active,
    Revoked,
    Expired,
}

impl SessionStatus {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

impl fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SessionStatus {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "active" => Ok(Self::Active),
            "revoked" => Ok(Self::Revoked),
            "expired" => Ok(Self::Expired),
            _ => Err("unknown session status"),
        }
    }
}
