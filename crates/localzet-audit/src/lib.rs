use async_trait::async_trait;
use localzet_domain::AuditEvent;
use thiserror::Error;

#[async_trait]
pub trait AuditSink: Send + Sync {
    async fn emit(&self, event: AuditEvent) -> Result<(), AuditError>;
}

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("audit sink failure: {message}")]
    Sink { message: String },
}

#[derive(Debug, Default)]
pub struct NoopAuditSink;

#[async_trait]
impl AuditSink for NoopAuditSink {
    async fn emit(&self, _event: AuditEvent) -> Result<(), AuditError> {
        Ok(())
    }
}
