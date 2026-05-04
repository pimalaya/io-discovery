//! # PACC discovery
//!
//! [draft-ietf-mailmaint-pacc-02] autoconfiguration: fetches a JSON
//! configuration document over HTTPS at the well-known URL
//! `https://ua-auto-config.<domain>/.well-known/user-agent-configuration.json`
//! and verifies it against a SHA-256 digest published in a DNS TXT
//! record under `_ua-auto-config.<domain>`.
//!
//! - [`coroutine`] — I/O-free state machine driving fetch + verify.
//! - [`types`] — `serde` types for the PACC configuration document.
//! - [`client`] — std-blocking client that drives the coroutine
//!   against caller-provided [`Read`]/[`Write`] streams (gated on
//!   `feature = "client"`).
//! - [`cli`] — `clap` subcommand wiring (gated on `feature = "cli"`).
//!
//! [draft-ietf-mailmaint-pacc-02]: https://datatracker.ietf.org/doc/html/draft-ietf-mailmaint-pacc-02
//! [`Read`]: std::io::Read
//! [`Write`]: std::io::Write

#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "client")]
pub mod client;
pub mod coroutine;
pub mod types;
