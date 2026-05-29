//! Types yielded by RFC 6764 SRV-based CalDAV/CardDAV discovery.

use serde::{Deserialize, Serialize};

use crate::rfc6186::types::SrvService;

/// Best-of-each-service summary produced by the combined RFC 6764
/// flow. Each slot carries the SRV record with the lowest priority
/// (and highest weight on ties), or `None` when that service did not
/// publish a record on the queried domain.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Rfc6764Report {
    pub caldav: Option<SrvService>,
    pub caldavs: Option<SrvService>,
    pub carddav: Option<SrvService>,
    pub carddavs: Option<SrvService>,
}
