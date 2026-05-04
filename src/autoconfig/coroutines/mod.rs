//! # I/O-free autoconfig coroutines
//!
//! One coroutine per discovery step:
//!
//! - [`isp`] — fetch and parse a single ISP autoconfig XML document.
//! - [`dns_mx`] — DNS MX lookup over TCP, sorted by preference.
//! - [`mailconf`] — DNS TXT lookup yielding a `mailconf=<URL>` value.
//! - [`dns_srv`] — DNS SRV lookup over TCP, sorted per RFC 2782.

pub mod dns_mx;
pub mod dns_srv;
pub mod isp;
pub mod mailconf;
