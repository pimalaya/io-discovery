//! # Shared defaults
//!
//! Crate-wide constants: the DNS resolver used by every CLI
//! subcommand and the buffer size every DNS query coroutine builds
//! into.

/// Default DNS resolver (`host:port`) used by every CLI subcommand
/// when `--server` is not given.
#[cfg(feature = "cli")]
pub(crate) const DNS_SERVER: &str = "1.1.1.1:53";

/// Maximum query buffer (in bytes) every DNS coroutine reserves for
/// building the outgoing message, including the 2-byte TCP length
/// prefix (RFC 1035 §4.2.2).
pub(crate) const DNS_QUERY_BUF_SIZE: usize = 4 * 1024;
