//! # PACC discovery coroutine.
//!
//! [`DiscoveryPacc`] performs the full PACC exchange defined by
//! [draft-ietf-mailmaint-pacc-02] in three steps, in order:
//!
//! 1. HTTPS GET the well-known URL
//!    `https://ua-auto-config.<domain>/.well-known/user-agent-configuration.json`
//!    and keep the raw response bytes.
//! 2. DNS TXT lookup for `_ua-auto-config.<domain>`. Each record is
//!    parsed as a `v=UAAC1; a=sha256; d=<base64>` tag set; the first
//!    record whose decoded `d` digest constant-time matches a SHA-256
//!    of the raw HTTP body wins.
//! 3. Once a record matches, parse the raw bytes as JSON and yield
//!    the resulting [`PaccConfig`].
//!
//! Per RFC 1035 §3.3.14 a TXT record is a sequence of length-prefixed
//! character-strings. Long values get split across multiple
//! character-strings; the coroutine concatenates them (no separator,
//! per RFC 6376 §3.6.2.2 / RFC 7208 §3.3) before parsing.
//!
//! The runtime opens the initial HTTPS stream itself (the URL is
//! exposed via [`DiscoveryPacc::url`]). When the HTTP fetch is done,
//! the coroutine yields a single [`WantsDnsConnect`] event so the
//! runtime knows to drop the HTTPS stream and connect to a DNS
//! resolver of its choice.
//!
//! [`WantsDnsConnect`]: DiscoveryPaccResult::WantsDnsConnect
//! [draft-ietf-mailmaint-pacc-02]: https://datatracker.ietf.org/doc/html/draft-ietf-mailmaint-pacc-02

use core::mem;

use alloc::{
    format, str,
    string::{String, ToString},
    vec::Vec,
};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use log::trace;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use url::{ParseError, Url};

use crate::{
    dns_txt::{DiscoveryDnsTxt, DiscoveryDnsTxtError, DiscoveryDnsTxtResult},
    http_get::{HttpGet, HttpGetError, HttpGetResult},
    pacc::types::PaccConfig,
};

/// Errors that can occur during a single PACC discovery.
#[derive(Debug, Error)]
pub enum DiscoveryPaccError {
    #[error("PACC URL for domain `{1}` is not valid")]
    InvalidUrl(#[source] ParseError, String),
    #[error("no `_ua-auto-config` TXT record matched the configuration body")]
    NoValidTxtRecord,
    #[error("PACC body matched the published digest but is not valid JSON")]
    Json(#[source] serde_json::Error),

    #[error(transparent)]
    Http(#[from] HttpGetError),
    #[error(transparent)]
    Dns(#[from] DiscoveryDnsTxtError),
}

/// Output emitted when the coroutine progresses or terminates.
pub enum DiscoveryPaccResult {
    /// Discovery succeeded: the body matched the published digest and
    /// parses as a valid configuration document.
    Ok(PaccConfig),
    /// The coroutine wants more bytes from the active stream.
    WantsRead,
    /// The coroutine wants the given bytes written to the active stream.
    WantsWrite(Vec<u8>),
    /// HTTP fetch is complete. The runtime should drop the HTTPS
    /// stream, open a fresh TCP stream to a DNS resolver of its
    /// choice, and use it as the active stream for the rest of the
    /// run. Yielded exactly once per discovery.
    WantsDnsConnect,
    /// Discovery failed.
    Err(DiscoveryPaccError),
}

#[derive(Default)]
enum State {
    Get,
    Verify,
    #[default]
    Done,
}

/// I/O-free coroutine that performs the full PACC discovery
/// (fetch → digest verification → JSON parse) for a given domain.
pub struct DiscoveryPacc {
    state: State,
    fetch: HttpGet,
    verify: DiscoveryDnsTxt,
    raw_body: Vec<u8>,
}

impl DiscoveryPacc {
    /// Builds the well-known PACC URL for `domain`:
    /// `https://ua-auto-config.<domain>/.well-known/user-agent-configuration.json`.
    pub fn url(domain: impl AsRef<str>) -> Result<Url, DiscoveryPaccError> {
        let d = domain.as_ref().trim_matches('.');
        let url = format!("https://ua-auto-config.{d}/.well-known/user-agent-configuration.json");
        Url::parse(&url).map_err(|err| DiscoveryPaccError::InvalidUrl(err, d.to_string()))
    }

    /// Builds a discoverer for `domain`. The runtime should pair the
    /// returned coroutine with an HTTPS stream opened on
    /// [`DiscoveryPacc::url`]; on [`WantsDnsConnect`] the runtime
    /// replaces it with a TCP stream to its DNS resolver.
    ///
    /// [`WantsDnsConnect`]: DiscoveryPaccResult::WantsDnsConnect
    pub fn new(domain: impl AsRef<str>) -> Result<Self, DiscoveryPaccError> {
        let url = Self::url(domain.as_ref())?;
        let qname = format!("_ua-auto-config.{}", domain.as_ref().trim_matches('.'));

        Ok(Self {
            state: State::Get,
            fetch: HttpGet::new(url),
            verify: DiscoveryDnsTxt::new(qname),
            raw_body: Vec::new(),
        })
    }

    /// Drives the discovery coroutine for one resume cycle.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> DiscoveryPaccResult {
        match mem::take(&mut self.state) {
            State::Get => match self.fetch.resume(arg) {
                HttpGetResult::WantsRead => {
                    self.state = State::Get;
                    DiscoveryPaccResult::WantsRead
                }
                HttpGetResult::WantsWrite(bytes) => {
                    self.state = State::Get;
                    DiscoveryPaccResult::WantsWrite(bytes)
                }
                HttpGetResult::Ok(bytes) => {
                    self.raw_body = bytes;
                    self.state = State::Verify;
                    DiscoveryPaccResult::WantsDnsConnect
                }
                HttpGetResult::Err(err) => DiscoveryPaccResult::Err(err.into()),
            },
            State::Verify => match self.verify.resume(arg) {
                DiscoveryDnsTxtResult::WantsRead => {
                    self.state = State::Verify;
                    DiscoveryPaccResult::WantsRead
                }
                DiscoveryDnsTxtResult::WantsWrite(bytes) => {
                    self.state = State::Verify;
                    DiscoveryPaccResult::WantsWrite(bytes)
                }
                DiscoveryDnsTxtResult::Ok(records) => {
                    for record in records {
                        let mut config = Vec::new();

                        for data in record.rdata.iter() {
                            config.extend_from_slice(&data.octets);
                        }

                        let Ok(config) = str::from_utf8(&config) else {
                            trace!("invalid UTF-8 TXT record, skip");
                            continue;
                        };

                        let mut v = None;
                        let mut a = None;
                        let mut d = None;

                        for tag in config.split(';') {
                            let Some((name, val)) = tag.split_once('=') else {
                                continue;
                            };

                            match name.trim() {
                                n if n.eq_ignore_ascii_case("v") => v = Some(val.trim()),
                                n if n.eq_ignore_ascii_case("a") => a = Some(val.trim()),
                                n if n.eq_ignore_ascii_case("d") => d = Some(val.trim()),
                                _ => continue,
                            }
                        }

                        let (Some(v), Some(a), Some(d)) = (v, a, d) else {
                            trace!("missing v, a or d in TXT record, skip");
                            continue;
                        };

                        if !v.eq_ignore_ascii_case("UAAC1") {
                            trace!("invalid `v`: expect `UAAC1` got `{v}`, skip");
                            continue;
                        }

                        if !a.eq_ignore_ascii_case("sha256") {
                            trace!("invalid `a`: expect `sha256` got `{a}`, skip");
                            continue;
                        }

                        let expected_digest = match BASE64.decode(d) {
                            Ok(digest) => {
                                trace!("expected digest: {digest:x?}");
                                digest
                            }
                            Err(err) => {
                                trace!("invalid base64 digest `{d}`, skip: {err}");
                                continue;
                            }
                        };

                        let actual_digest = Sha256::digest(&self.raw_body);
                        trace!("actual digest: {actual_digest:x?}");

                        if !bool::from(expected_digest.ct_eq(&actual_digest)) {
                            trace!("digest mismatch, skip");
                            continue;
                        }

                        return match serde_json::from_slice(&self.raw_body) {
                            Ok(config) => DiscoveryPaccResult::Ok(config),
                            Err(err) => DiscoveryPaccResult::Err(DiscoveryPaccError::Json(err)),
                        };
                    }

                    DiscoveryPaccResult::Err(DiscoveryPaccError::NoValidTxtRecord)
                }
                DiscoveryDnsTxtResult::Err(err) => DiscoveryPaccResult::Err(err.into()),
            },

            State::Done => {
                panic!("DiscoveryPacc::resume called after completion");
            }
        }
    }
}
