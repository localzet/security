use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub reason: &'static str,
}

impl PolicyDecision {
    pub const fn allow(reason: &'static str) -> Self {
        Self {
            allowed: true,
            reason,
        }
    }

    pub const fn deny(reason: &'static str) -> Self {
        Self {
            allowed: false,
            reason,
        }
    }
}
