//! # Per-URL ISP autoconfig HTTP+XML fetch.
//!
//! [`DiscoveryIsp`] is a single-URL fetch coroutine: it drives one
//! [`HttpGet`] cycle and parses the response body as a Mozilla
//! [Autoconfiguration] XML document. URL selection is the runtime's
//! responsibility — pair this coroutine with the static URL helpers
//! ([`isp_url`], [`isp_fallback_url`], [`ispdb_url`], [`all_urls`]).
//!
//! Typical driver shape:
//!
//! ```ignore
//! for url in DiscoveryIsp::all_urls(local, domain) {
//!     let Ok(mut http) = HttpSession::new(url.clone(), ...) else { continue };
//!     let mut isp = DiscoveryIsp::new(url);
//!     let mut arg = None;
//!     loop {
//!         match isp.resume(arg) {
//!             DiscoveryIspResult::Ok(c)         => return Ok(c),
//!             DiscoveryIspResult::WantsWrite(b) => { http.stream.write(&b)?; arg = None; }
//!             DiscoveryIspResult::WantsRead     => { let n = http.stream.read(&mut buf)?; arg = Some(&buf[..n]); }
//!             DiscoveryIspResult::Err(_)        => break,
//!         }
//!     }
//! }
//! ```
//!
//! [Autoconfiguration]: https://wiki.mozilla.org/Thunderbird:Autoconfiguration
//! [`isp_url`]: DiscoveryIsp::isp_url
//! [`isp_fallback_url`]: DiscoveryIsp::isp_fallback_url
//! [`ispdb_url`]: DiscoveryIsp::ispdb_url
//! [`all_urls`]: DiscoveryIsp::all_urls

use alloc::{
    format,
    string::{FromUtf8Error, String},
    vec::Vec,
};

use thiserror::Error;
use url::{ParseError, Url};

use crate::{
    autoconfig::serde::AutoConfig,
    http_get::{HttpGet, HttpGetError, HttpGetResult},
};

/// Errors that can occur during a single ISP autoconfig HTTP exchange.
#[derive(Debug, Error)]
pub enum DiscoveryIspError {
    #[error("ISP call returned invalid UTF-8 body")]
    Utf8(#[source] FromUtf8Error),
    #[error("ISP call returned invalid XML body")]
    Xml(#[source] serde_xml_rs::Error),
    #[error(transparent)]
    Http(#[from] HttpGetError),
}

/// Output emitted when the coroutine progresses or terminates.
pub enum DiscoveryIspResult {
    /// The fetch successfully decoded an autoconfig.
    Ok(AutoConfig),
    /// The fetch wants more bytes to be read from the socket.
    WantsRead,
    /// The fetch wants the given bytes to be written to the socket.
    WantsWrite(Vec<u8>),
    /// The fetch failed; the runtime should drop this URL and try the
    /// next one.
    Err(DiscoveryIspError),
}

/// HTTP+XML fetch coroutine for a single ISP autoconfig URL.
pub struct DiscoveryIsp {
    get: HttpGet,
}

impl DiscoveryIsp {
    /// Builds the URL for the main ISP location
    /// (`http[s]://autoconfig.<domain>/mail/config-v1.1.xml?...`).
    pub fn isp_url(
        local_part: impl AsRef<str>,
        domain: impl AsRef<str>,
        secure: bool,
    ) -> Result<Url, ParseError> {
        let domain = domain.as_ref().trim_matches('.');
        let email = format!("{}@{domain}", local_part.as_ref());
        let s = if secure { "s" } else { "" };
        let url =
            format!("http{s}://autoconfig.{domain}/mail/config-v1.1.xml?emailaddress={email}");
        Url::parse(&url)
    }

    /// Builds the URL for the alternative ISP location
    /// (`http[s]://<domain>/.well-known/autoconfig/mail/config-v1.1.xml`).
    pub fn isp_fallback_url(domain: impl AsRef<str>, secure: bool) -> Result<Url, ParseError> {
        let domain = domain.as_ref().trim_matches('.');
        let s = if secure { "s" } else { "" };
        let url = format!("http{s}://{domain}/.well-known/autoconfig/mail/config-v1.1.xml");
        Url::parse(&url)
    }

    /// Builds the URL for the Thunderbird ISPDB
    /// (`http[s]://autoconfig.thunderbird.net/v1.1/<domain>`).
    pub fn ispdb_url(domain: impl AsRef<str>, secure: bool) -> Result<Url, ParseError> {
        let domain = domain.as_ref().trim_matches('.');
        let s = if secure { "s" } else { "" };
        let url = format!("http{s}://autoconfig.thunderbird.net/v1.1/{domain}");
        Url::parse(&url)
    }

    pub fn all_urls(
        local_part: impl AsRef<str>,
        domain: impl AsRef<str>,
    ) -> Result<[Url; 5], ParseError> {
        let local_part = local_part.as_ref();
        let domain = domain.as_ref();

        Ok([
            Self::isp_url(local_part, domain, true)?,
            Self::isp_url(local_part, domain, false)?,
            Self::isp_fallback_url(domain, true)?,
            Self::isp_fallback_url(domain, false)?,
            Self::ispdb_url(domain, true)?,
        ])
    }

    /// Builds a fetcher for `url`. Pair with an HTTP session opened on
    /// the same URL.
    pub fn new(url: Url) -> Self {
        Self {
            get: HttpGet::new(url),
        }
    }

    /// Drives the fetch coroutine for one resume cycle.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> DiscoveryIspResult {
        match self.get.resume(arg) {
            HttpGetResult::Ok(bytes) => {
                let body = match String::from_utf8(bytes) {
                    Ok(body) => body,
                    Err(err) => return DiscoveryIspResult::Err(DiscoveryIspError::Utf8(err)),
                };

                match serde_xml_rs::from_str(&body) {
                    Ok(autoconfig) => DiscoveryIspResult::Ok(autoconfig),
                    Err(err) => DiscoveryIspResult::Err(DiscoveryIspError::Xml(err)),
                }
            }

            HttpGetResult::WantsRead => DiscoveryIspResult::WantsRead,
            HttpGetResult::WantsWrite(bytes) => DiscoveryIspResult::WantsWrite(bytes),
            HttpGetResult::Err(err) => DiscoveryIspResult::Err(err.into()),
        }
    }
}
