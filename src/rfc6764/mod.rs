//! RFC 6764 SRV-based CalDAV/CardDAV service discovery.

#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "client")]
pub mod client;
pub mod discover;
pub mod srv;
pub mod types;
