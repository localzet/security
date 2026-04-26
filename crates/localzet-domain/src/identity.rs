use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(pub Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdentityId(pub Uuid);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(pub Uuid);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationKind {
    Web,
    Spa,
    Mobile,
    Cli,
    Service,
    Admin,
}

impl ApplicationKind {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::Spa => "spa",
            Self::Mobile => "mobile",
            Self::Cli => "cli",
            Self::Service => "service",
            Self::Admin => "admin",
        }
    }
}

impl fmt::Display for ApplicationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ApplicationKind {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "web" => Ok(Self::Web),
            "spa" => Ok(Self::Spa),
            "mobile" => Ok(Self::Mobile),
            "cli" => Ok(Self::Cli),
            "service" => Ok(Self::Service),
            "admin" => Ok(Self::Admin),
            _ => Err("unknown application kind"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Application {
    pub client_id: String,
    pub kind: ApplicationKind,
    pub redirect_uris: Vec<Url>,
    pub scopes: Vec<String>,
}
