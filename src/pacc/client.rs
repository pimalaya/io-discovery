//! # Standard, blocking PACC discovery client
//!
//! Thin wrapper that drives [`DiscoveryPacc`] against caller-provided
//! [`Read`]/[`Write`] streams: one for the HTTPS digest fetch and one
//! for the DNS digest verification. The client itself is runtime-
//! agnostic — it does not depend on a particular stream
//! implementation.

use std::io::{Read, Write};

use thiserror::Error;

use crate::pacc::{coroutine::*, types::PaccConfig};

/// Errors returned by [`DiscoveryPaccClientStd::discover`].
#[derive(Debug, Error)]
pub enum DiscoveryPaccClientError {
    #[error(transparent)]
    Discovery(#[from] DiscoveryPaccError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Std-blocking client that wraps a [`DiscoveryPacc`] coroutine and
/// the two streams it drives — an HTTPS stream for the digest fetch
/// and a DNS stream for the digest verification.
pub struct DiscoveryPaccClientStd<Http: Read + Write, Dns: Read + Write> {
    http_stream: Http,
    dns_stream: Dns,
}

impl<Http: Read + Write, Dns: Read + Write> DiscoveryPaccClientStd<Http, Dns> {
    /// Builds a client owning the given HTTPS and DNS streams.
    pub fn new(http_stream: Http, dns_stream: Dns) -> Self {
        Self {
            http_stream,
            dns_stream,
        }
    }

    /// Releases ownership of the underlying streams to the caller, in
    /// the same order they were passed to [`Self::new`].
    pub fn into_inner(self) -> (Http, Dns) {
        (self.http_stream, self.dns_stream)
    }

    /// Runs the full PACC discovery for `domain`, alternating between
    /// the HTTPS and DNS streams owned by `self` as the coroutine
    /// requests it.
    pub fn discover(&mut self, domain: &str) -> Result<PaccConfig, DiscoveryPaccClientError> {
        let mut pacc = DiscoveryPacc::new(domain)?;

        let mut buf = [0u8; 8192];
        let mut arg: Option<&[u8]> = None;

        loop {
            match pacc.resume(arg.take()) {
                DiscoveryPaccResult::Ok(config) => return Ok(config),
                DiscoveryPaccResult::WantsHttpRead => {
                    let n = self.http_stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                DiscoveryPaccResult::WantsHttpWrite(ref bytes) => {
                    self.http_stream.write_all(bytes)?;
                }
                DiscoveryPaccResult::WantsDnsRead => {
                    let n = self.dns_stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                DiscoveryPaccResult::WantsDnsWrite(ref bytes) => {
                    self.dns_stream.write_all(bytes)?;
                }
                DiscoveryPaccResult::Err(err) => return Err(err.into()),
            }
        }
    }
}
