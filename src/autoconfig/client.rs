//! # Standard, blocking autoconfig discovery client
//!
//! [`DiscoveryAutoconfigClientStd`] exposes one method per Mozilla
//! autoconfig primitive ([`isp`], [`isp_fallback`], [`ispdb`],
//! [`mx`], [`mailconf`]); each runs exactly one coroutine end-to-end
//! through a local [`StreamPool`]. Composition (try several
//! candidates, fall back through MX-derived parents, race variants in
//! parallel, ...) is the caller's responsibility.
//!
//! Construction:
//!
//! - Light: [`new`] returns a client with only the default `tcp`
//!   factory registered. Plug `http` / `https` factories via
//!   [`with_factory`].
//! - Full: under the `stream` feature, chain [`with_tls`] after
//!   [`new`] to auto-register `http` / `https` factories backed by
//!   [`pimalaya_stream::std::stream::StreamStd`].
//!
//! [`new`]: DiscoveryAutoconfigClientStd::new
//! [`with_factory`]: DiscoveryAutoconfigClientStd::with_factory
//! [`with_tls`]: DiscoveryAutoconfigClientStd::with_tls
//! [`isp`]: DiscoveryAutoconfigClientStd::isp
//! [`isp_fallback`]: DiscoveryAutoconfigClientStd::isp_fallback
//! [`ispdb`]: DiscoveryAutoconfigClientStd::ispdb
//! [`mx`]: DiscoveryAutoconfigClientStd::mx
//! [`mailconf`]: DiscoveryAutoconfigClientStd::mailconf

use alloc::vec::Vec;

use domain::new::{
    base::{Record, name::RevNameBuf},
    rdata::Mx,
};
use thiserror::Error;
use url::Url;

use crate::{
    autoconfig::{
        isp::{DiscoveryIsp, DiscoveryIspError, DiscoveryIspResult},
        mailconf::{DiscoveryMailconf, DiscoveryMailconfError, DiscoveryMailconfResult},
        mx::{DiscoveryDnsMx, DiscoveryDnsMxError, DiscoveryDnsMxResult},
        types::Autoconfig,
    },
    shared::pool::{Stream, StreamPool},
};

const READ_BUFFER_SIZE: usize = 8 * 1024;

/// Errors returned by [`DiscoveryAutoconfigClientStd`].
#[derive(Debug, Error)]
pub enum DiscoveryAutoconfigClientStdError {
    /// A single ISP fetch (main / fallback / db URL) failed.
    #[error(transparent)]
    Isp(#[from] DiscoveryIspError),
    /// The DNS MX coroutine errored out.
    #[error(transparent)]
    DnsMx(#[from] DiscoveryDnsMxError),
    /// The mailconf TXT coroutine errored out.
    #[error(transparent)]
    Mailconf(#[from] DiscoveryMailconfError),
    /// `DiscoveryIsp::*_url` could not build the candidate URL from
    /// the caller's input.
    #[error(transparent)]
    UrlParse(#[from] url::ParseError),
    /// Read or write against an open stream failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// [`StreamPool::get`] failed (unknown scheme, factory error).
    #[error(transparent)]
    Pool(#[from] anyhow::Error),
}

/// Std-blocking Mozilla autoconfig discovery client.
pub struct DiscoveryAutoconfigClientStd {
    dns: Url,
    pool: StreamPool,
}

impl DiscoveryAutoconfigClientStd {
    /// Builds a client that resolves DNS lookups through `dns` (a
    /// `tcp://host:port` URL pointing at a DNS-over-TCP resolver).
    /// The underlying pool is pre-populated with the default `tcp`
    /// factory only; plug `http` / `https` factories via
    /// [`with_factory`] before calling any HTTPS-bound method, or
    /// chain [`with_tls`] under the `stream` feature.
    ///
    /// [`with_factory`]: Self::with_factory
    /// [`with_tls`]: Self::with_tls
    pub fn new(dns: Url) -> Self {
        Self {
            dns,
            pool: StreamPool::new(),
        }
    }

    /// Registers (or replaces) the pool factory for `scheme`.
    pub fn with_factory<F, S>(mut self, scheme: &'static str, factory: F) -> Self
    where
        F: FnMut(&Url) -> anyhow::Result<S> + 'static,
        S: Stream + 'static,
    {
        self.pool = self.pool.with_factory(scheme, factory);
        self
    }

    /// Bootstraps the pool with `http` / `https` factories backed by
    /// [`pimalaya_stream::std::stream::StreamStd`] using the given
    /// `tls` profile. Gated by the `stream` feature.
    #[cfg(feature = "stream")]
    pub fn with_tls(mut self, tls: pimalaya_stream::tls::Tls) -> Self {
        self.pool = self.pool.with_http_factories(tls);
        self
    }

    /// Fetches the ISP main URL
    /// (`http[s]://autoconfig.<domain>/mail/config-v1.1.xml?emailaddress=...`).
    pub fn isp(
        &mut self,
        local_part: &str,
        domain: &str,
        secure: bool,
    ) -> Result<Autoconfig, DiscoveryAutoconfigClientStdError> {
        let url = DiscoveryIsp::main_url(local_part, domain, secure)?;
        let mut coroutine = DiscoveryIsp::new(url.clone());
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(arg.take()) {
                DiscoveryIspResult::Ok(config) => return Ok(config),
                DiscoveryIspResult::Err(err) => return Err(err.into()),
                DiscoveryIspResult::WantsRead => {
                    let stream = self.pool.get(&url)?;
                    let n = stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                DiscoveryIspResult::WantsWrite(bytes) => {
                    let stream = self.pool.get(&url)?;
                    stream.write_all(&bytes)?;
                }
            }
        }
    }

    /// Fetches the ISP fallback URL
    /// (`http[s]://<domain>/.well-known/autoconfig/mail/config-v1.1.xml`).
    pub fn isp_fallback(
        &mut self,
        domain: &str,
        secure: bool,
    ) -> Result<Autoconfig, DiscoveryAutoconfigClientStdError> {
        let url = DiscoveryIsp::fallback_url(domain, secure)?;
        let mut coroutine = DiscoveryIsp::new(url.clone());
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(arg.take()) {
                DiscoveryIspResult::Ok(config) => return Ok(config),
                DiscoveryIspResult::Err(err) => return Err(err.into()),
                DiscoveryIspResult::WantsRead => {
                    let stream = self.pool.get(&url)?;
                    let n = stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                DiscoveryIspResult::WantsWrite(bytes) => {
                    let stream = self.pool.get(&url)?;
                    stream.write_all(&bytes)?;
                }
            }
        }
    }

    /// Fetches the Thunderbird ISPDB
    /// (`http[s]://autoconfig.thunderbird.net/v1.1/<domain>`).
    pub fn ispdb(
        &mut self,
        domain: &str,
        secure: bool,
    ) -> Result<Autoconfig, DiscoveryAutoconfigClientStdError> {
        let url = DiscoveryIsp::db_url(domain, secure)?;
        let mut coroutine = DiscoveryIsp::new(url.clone());
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(arg.take()) {
                DiscoveryIspResult::Ok(config) => return Ok(config),
                DiscoveryIspResult::Err(err) => return Err(err.into()),
                DiscoveryIspResult::WantsRead => {
                    let stream = self.pool.get(&url)?;
                    let n = stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                DiscoveryIspResult::WantsWrite(bytes) => {
                    let stream = self.pool.get(&url)?;
                    stream.write_all(&bytes)?;
                }
            }
        }
    }

    /// Returns the MX records for `domain`, sorted by ascending
    /// preference (best first). Empty when the response carries no
    /// MX answers.
    pub fn mx(
        &mut self,
        domain: &str,
    ) -> Result<
        Vec<Record<RevNameBuf, Mx<domain::new::base::name::NameBuf>>>,
        DiscoveryAutoconfigClientStdError,
    > {
        let mut coroutine = DiscoveryDnsMx::new(domain, self.dns.clone());
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(arg.take()) {
                DiscoveryDnsMxResult::Ok(records) => return Ok(records),
                DiscoveryDnsMxResult::Err(err) => return Err(err.into()),
                DiscoveryDnsMxResult::WantsRead { url } => {
                    let stream = self.pool.get(&url)?;
                    let n = stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                DiscoveryDnsMxResult::WantsWrite { url, bytes } => {
                    let stream = self.pool.get(&url)?;
                    stream.write_all(&bytes)?;
                }
            }
        }
    }

    /// Looks up the `mailconf=<URL>` TXT record on `domain` and
    /// returns the parsed redirect URL.
    pub fn mailconf(&mut self, domain: &str) -> Result<Url, DiscoveryAutoconfigClientStdError> {
        let mut coroutine = DiscoveryMailconf::new(domain, self.dns.clone());
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(arg.take()) {
                DiscoveryMailconfResult::Ok(url) => return Ok(url),
                DiscoveryMailconfResult::Err(err) => return Err(err.into()),
                DiscoveryMailconfResult::WantsRead { url } => {
                    let stream = self.pool.get(&url)?;
                    let n = stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                DiscoveryMailconfResult::WantsWrite { url, bytes } => {
                    let stream = self.pool.get(&url)?;
                    stream.write_all(&bytes)?;
                }
            }
        }
    }
}
