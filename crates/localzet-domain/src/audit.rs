use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{TenantId, UserId};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: Uuid,
    pub tenant_id: TenantId,
    pub actor: Option<UserId>,
    pub action: AuditAction,
    pub target: AuditTarget,
    pub occurred_at: DateTime<Utc>,
    pub reason: Option<String>,
    pub correlation_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    SessionCreated,
    SessionRevoked,
    LoginSucceeded,
    LoginFailed,
    AdminImpersonation,
    PolicyChanged,
    TenantConfigChanged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTarget {
    pub kind: String,
    pub id: String,
}
