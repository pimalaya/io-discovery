//! # PACC configuration fetch.
//!
//! [`DiscoveryPaccFetch`] sends one HTTPS GET to the well-known PACC
//! URL and parses the response body as JSON into [`PaccConfig`]. The
//! raw response bytes are also returned so the caller can verify them
//! against the digest published in the corresponding DNS TXT record
//! (see [`crate::pacc::verify`]).
//!
//! Per [draft-ietf-mailmaint-pacc-02], the discovery URL is
//! `https://ua-auto-config.<domain>/.well-known/user-agent-configuration.json`.
//!
//! [draft-ietf-mailmaint-pacc-02]: https://datatracker.ietf.org/doc/html/draft-ietf-mailmaint-pacc-02

use alloc::{format, vec::Vec};

use thiserror::Error;
use url::{ParseError, Url};

use crate::{
    http_get::{HttpGet, HttpGetError, HttpGetResult},
    pacc::serde::PaccConfig,
};

/// Errors that can occur during a single PACC configuration fetch.
#[derive(Debug, Error)]
pub enum DiscoveryPaccFetchError {
    #[error("PACC fetch returned invalid UTF-8 body")]
    Utf8(#[source] core::str::Utf8Error),
    #[error("PACC fetch returned invalid JSON body")]
    Json(#[source] serde_json::Error),
    #[error(transparent)]
    Http(#[from] HttpGetError),
}

/// Output emitted when the coroutine progresses or terminates.
pub enum DiscoveryPaccFetchResult {
    /// The fetch successfully decoded a configuration document. `raw`
    /// is the exact response body bytes — keep them around for the
    /// digest verification step.
    Ok { config: PaccConfig, raw: Vec<u8> },
    /// The fetch wants more bytes to be read from the socket.
    WantsRead,
    /// The fetch wants the given bytes to be written to the socket.
    WantsWrite(Vec<u8>),
    /// The fetch failed.
    Err(DiscoveryPaccFetchError),
}

/// HTTPS+JSON fetch coroutine for the well-known PACC URL.
pub struct DiscoveryPaccFetch {
    get: HttpGet,
}

impl DiscoveryPaccFetch {
    /// Builds the well-known PACC URL for `domain`:
    /// `https://ua-auto-config.<domain>/.well-known/user-agent-configuration.json`.
    pub fn url(domain: impl AsRef<str>) -> Result<Url, ParseError> {
        let domain = domain.as_ref().trim_matches('.');
        let url =
            format!("https://ua-auto-config.{domain}/.well-known/user-agent-configuration.json");
        Url::parse(&url)
    }

    /// Builds a fetcher for `url`. Pair with an HTTP session opened on
    /// the same URL.
    pub fn new(url: Url) -> Self {
        Self {
            get: HttpGet::new(url),
        }
    }

    /// Drives the fetch coroutine for one resume cycle.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> DiscoveryPaccFetchResult {
        match self.get.resume(arg) {
            HttpGetResult::Ok(bytes) => {
                let body = match core::str::from_utf8(&bytes) {
                    Ok(body) => body,
                    Err(err) => {
                        return DiscoveryPaccFetchResult::Err(DiscoveryPaccFetchError::Utf8(err));
                    }
                };

                match serde_json::from_str::<PaccConfig>(body) {
                    Ok(config) => DiscoveryPaccFetchResult::Ok { config, raw: bytes },
                    Err(err) => DiscoveryPaccFetchResult::Err(DiscoveryPaccFetchError::Json(err)),
                }
            }

            HttpGetResult::WantsRead => DiscoveryPaccFetchResult::WantsRead,
            HttpGetResult::WantsWrite(bytes) => DiscoveryPaccFetchResult::WantsWrite(bytes),
            HttpGetResult::Err(err) => DiscoveryPaccFetchResult::Err(err.into()),
        }
    }
}
