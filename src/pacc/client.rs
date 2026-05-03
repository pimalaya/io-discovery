//! # std-blocking PACC client.
//!
//! Thin wrapper that drives [`DiscoveryPacc`] against blocking
//! [`pimalaya_toolbox::stream::Stream`]s. Suits callers who want a
//! plain `discover(domain) -> PaccConfig` API without dealing with
//! the I/O-free coroutine themselves.

use std::{
    io::{Read, Write},
    net::TcpStream,
    string::{String, ToString},
};

use pimalaya_toolbox::stream::{Stream, http::HttpSession};
use thiserror::Error;

use crate::pacc::{coroutine::*, types::PaccConfig};

/// Errors returned by [`discover`].
#[derive(Debug, Error)]
pub enum DiscoveryPaccClientError {
    #[error(transparent)]
    Discovery(#[from] DiscoveryPaccError),
    #[error("HTTPS session setup failed: {0}")]
    Http(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Runs the full PACC discovery for `domain`. `dns_server` is the
/// `host:port` of the DNS resolver used for the digest TXT lookup;
/// pass [`None`] to fall back to `1.1.1.1:53`.
pub fn discover(domain: &str, dns_server: &str) -> Result<PaccConfig, DiscoveryPaccClientError> {
    let url = DiscoveryPacc::url(domain)?;
    let mut stream = HttpSession::new(&url, Default::default())
        .map_err(|err| DiscoveryPaccClientError::Http(err.to_string()))?
        .stream;
    let mut pacc = DiscoveryPacc::new(domain)?;

    let mut buf = [0u8; 8192];
    let mut arg: Option<&[u8]> = None;

    loop {
        match pacc.resume(arg.take()) {
            DiscoveryPaccResult::Ok(config) => return Ok(config),
            DiscoveryPaccResult::WantsDnsConnect => {
                stream = Stream::Tcp(TcpStream::connect(dns_server)?);
            }
            DiscoveryPaccResult::WantsWrite(ref bytes) => {
                stream.write_all(bytes)?;
            }
            DiscoveryPaccResult::WantsRead => {
                let n = stream.read(&mut buf)?;
                arg = Some(&buf[..n]);
            }
            DiscoveryPaccResult::Err(err) => return Err(err.into()),
        }
    }
}
