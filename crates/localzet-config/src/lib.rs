use std::{env, fs};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    pub bind_addr: String,
    pub issuer: Url,
}

impl HttpConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind_addr =
            env::var("LOCALZET_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_owned());
        let issuer = env::var("LOCALZET_ISSUER")
            .unwrap_or_else(|_| "http://127.0.0.1:8080".to_owned())
            .parse()?;

        Ok(Self { bind_addr, issuer })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub run_migrations: bool,
}

impl DatabaseConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let url = env::var("LOCALZET_DATABASE_URL").map_err(|_| ConfigError::MissingEnv {
            name: "LOCALZET_DATABASE_URL",
        })?;

        Ok(Self {
            url,
            max_connections: env_u32("LOCALZET_DATABASE_MAX_CONNECTIONS", 10),
            run_migrations: env_bool("LOCALZET_DATABASE_RUN_MIGRATIONS", true),
        })
    }

    pub fn from_env_optional() -> Result<Option<Self>, ConfigError> {
        match env::var("LOCALZET_DATABASE_URL") {
            Ok(_) => Self::from_env().map(Some),
            Err(env::VarError::NotPresent) => Ok(None),
            Err(_) => Err(ConfigError::MissingEnv {
                name: "LOCALZET_DATABASE_URL",
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapConfig {
    pub tenant_id: TenantIdConfig,
    pub tenant_slug: String,
    pub tenant_display_name: String,
    pub client_id: String,
    pub redirect_uri: Url,
}

impl BootstrapConfig {
    pub fn from_env_optional() -> Result<Option<Self>, ConfigError> {
        let tenant_id = match env::var("LOCALZET_BOOTSTRAP_TENANT_ID") {
            Ok(value) => value
                .parse::<Uuid>()
                .map_err(|_| ConfigError::InvalidUuid {
                    name: "LOCALZET_BOOTSTRAP_TENANT_ID",
                })?,
            Err(env::VarError::NotPresent) => return Ok(None),
            Err(_) => {
                return Err(ConfigError::MissingEnv {
                    name: "LOCALZET_BOOTSTRAP_TENANT_ID",
                });
            }
        };

        let redirect_uri = env::var("LOCALZET_BOOTSTRAP_REDIRECT_URI")
            .unwrap_or_else(|_| "http://127.0.0.1:3000/callback".to_owned())
            .parse()?;

        Ok(Some(Self {
            tenant_id: TenantIdConfig(tenant_id),
            tenant_slug: env::var("LOCALZET_BOOTSTRAP_TENANT_SLUG")
                .unwrap_or_else(|_| "local-dev".to_owned()),
            tenant_display_name: env::var("LOCALZET_BOOTSTRAP_TENANT_DISPLAY_NAME")
                .unwrap_or_else(|_| "Local Development".to_owned()),
            client_id: env::var("LOCALZET_BOOTSTRAP_CLIENT_ID")
                .unwrap_or_else(|_| "web-client".to_owned()),
            redirect_uri,
        }))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningConfig {
    pub key_id: String,
    pub private_key_pem: String,
    pub public_key_pem: String,
}

impl SigningConfig {
    pub fn from_env_optional() -> Result<Option<Self>, ConfigError> {
        let private_key_pem = match env::var("LOCALZET_SIGNING_PRIVATE_KEY_PATH") {
            Ok(path) => fs::read_to_string(&path).map_err(|_| ConfigError::ReadFile {
                name: "LOCALZET_SIGNING_PRIVATE_KEY_PATH",
            })?,
            Err(env::VarError::NotPresent) => match env::var("LOCALZET_SIGNING_PRIVATE_KEY_PEM") {
                Ok(value) => value,
                Err(env::VarError::NotPresent) => return Ok(None),
                Err(_) => {
                    return Err(ConfigError::MissingEnv {
                        name: "LOCALZET_SIGNING_PRIVATE_KEY_PEM",
                    });
                }
            },
            Err(_) => {
                return Err(ConfigError::MissingEnv {
                    name: "LOCALZET_SIGNING_PRIVATE_KEY_PATH",
                });
            }
        };

        let public_key_pem =
            match env::var("LOCALZET_SIGNING_PUBLIC_KEY_PATH") {
                Ok(path) => fs::read_to_string(&path).map_err(|_| ConfigError::ReadFile {
                    name: "LOCALZET_SIGNING_PUBLIC_KEY_PATH",
                })?,
                Err(env::VarError::NotPresent) => env::var("LOCALZET_SIGNING_PUBLIC_KEY_PEM")
                    .map_err(|_| ConfigError::MissingEnv {
                        name: "LOCALZET_SIGNING_PUBLIC_KEY_PEM",
                    })?,
                Err(_) => {
                    return Err(ConfigError::MissingEnv {
                        name: "LOCALZET_SIGNING_PUBLIC_KEY_PATH",
                    });
                }
            };

        Ok(Some(Self {
            key_id: env::var("LOCALZET_SIGNING_KEY_ID").unwrap_or_else(|_| "main-rs256".to_owned()),
            private_key_pem,
            public_key_pem,
        }))
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TenantIdConfig(pub Uuid);

fn env_u32(name: &'static str, default: u32) -> u32 {
    env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_bool(name: &'static str, default: bool) -> bool {
    env::var(name)
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "on"))
        .unwrap_or(default)
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing environment variable: {name}")]
    MissingEnv { name: &'static str },
    #[error("invalid url: {0}")]
    InvalidUrl(#[from] url::ParseError),
    #[error("invalid uuid in environment variable: {name}")]
    InvalidUuid { name: &'static str },
    #[error("failed to read file from environment variable: {name}")]
    ReadFile { name: &'static str },
}
