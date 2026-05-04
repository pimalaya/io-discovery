//! # Shared coroutines and defaults
//!
//! Building blocks reused across the
//! [`autoconfig`](crate::autoconfig) and [`pacc`](crate::pacc)
//! discovery flows.
//!
//! - [`http_get`] — single HTTP/1.1 GET that yields the raw response
//!   body.
//! - [`dns_txt`] — single DNS TXT exchange over TCP that yields the
//!   answer records in resolver order.
//! - [`defaults`] — buffer sizes and CLI defaults shared by the rest
//!   of the crate.

pub mod defaults;
pub mod dns_txt;
pub mod http_get;
