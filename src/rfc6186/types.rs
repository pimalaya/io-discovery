//! Types yielded by RFC 6186 SRV-based mail service discovery.

use alloc::string::String;

use serde::{Deserialize, Serialize};

/// Best-of-each-service summary produced by the combined RFC 6186
/// flow. Each slot carries the SRV record with the lowest priority
/// (and highest weight on ties), or `None` when that service did not
/// publish a record on the queried domain.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SrvReport {
    pub imap: Option<SrvService>,
    pub imaps: Option<SrvService>,
    pub submission: Option<SrvService>,
}

/// One SRV record stripped to the fields a mail client actually uses:
/// where to connect (`host`, `port`) and how the runtime picked it
/// among siblings (`priority`, `weight`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SrvService {
    pub host: String,
    pub port: u16,
    pub priority: u16,
    pub weight: u16,
}
