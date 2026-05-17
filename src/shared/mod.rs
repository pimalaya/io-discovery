//! # Shared coroutines and runtime helpers
//!
//! Building blocks reused across the
//! [`autoconfig`](crate::autoconfig) and [`pacc`](crate::pacc)
//! discovery flows.
//!
//! - [`http`]: single HTTP/1.1 GET that yields the raw response
//!   body; also exposes the `http`/`https` factory bootstrap for the
//!   pool (gated by the `stream` feature).
//! - [`dns`]: single DNS TXT exchange over TCP that yields the
//!   answer records in resolver order.
//! - [`pool`]: std-blocking, URL-keyed cache of streams driven by
//!   user-supplied scheme factories (gated by the `client` feature).

pub mod dns;
pub mod http;
#[cfg(feature = "client")]
pub mod pool;
