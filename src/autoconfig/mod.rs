//! # Mozilla Autoconfiguration discovery
//!
//! Implements the [Mozilla Thunderbird autoconfiguration] discovery
//! chain: tries the publisher's well-known ISP URLs, falls back to a
//! DNS MX-based retry of the same ISPs against the MX target's
//! parent, then a DNS TXT `mailconf=<URL>` redirect, then SRV records
//! assembled into an autoconfig as a last resort.
//!
//! - [`coroutines`] — I/O-free coroutines, one per discovery step.
//! - [`types`] — `serde` types for the autoconfig XML document.
//! - [`client`] — std-blocking helper that drives each coroutine
//!   against a caller-provided stream (gated on `feature =
//!   "client"`).
//! - [`cli`] — `clap` subcommand wiring (gated on `feature = "cli"`).
//!
//! [Mozilla Thunderbird autoconfiguration]: https://wiki.mozilla.org/Thunderbird:Autoconfiguration

#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "client")]
pub mod client;
pub mod coroutines;
pub mod types;
