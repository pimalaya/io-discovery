//! # Standard, blocking PACC discovery client
//!
//! Builder-style wrapper around [`DiscoveryPacc`]. The pool comes
//! with default factories for `http`, `https`, and `tcp` already
//! registered — callers just construct with [`new`] and call
//! [`discover`]. HTTPS connections fail at runtime if no TLS
//! feature is enabled. BYO callers register their own scheme
//! factories through [`with_factory`].
//!
//! [`new`]: DiscoveryPaccClient::new
//! [`discover`]: DiscoveryPaccClient::discover
//! [`with_factory`]: DiscoveryPaccClient::with_factory

use pimalaya_stream::{
    std::pool::{Stream, StreamPool},
    tls::Tls,
};
use thiserror::Error;
use url::Url;

use crate::pacc::{coroutine::*, types::PaccConfig};

/// Errors returned by [`DiscoveryPaccClient::discover`].
#[derive(Debug, Error)]
pub enum DiscoveryPaccClientError {
    #[error(transparent)]
    Discovery(#[from] DiscoveryPaccError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Pool(#[from] anyhow::Error),
}

/// Std-blocking client that drives [`DiscoveryPacc`] end-to-end.
pub struct DiscoveryPaccClient {
    pool: StreamPool,
    resolver: Url,
}

impl DiscoveryPaccClient {
    /// Builds a client that resolves the digest TXT record through
    /// `resolver` (a `tcp://host:port` URL pointing at a DNS-over-
    /// TCP resolver). The underlying pool is pre-populated with
    /// default `http`/`https`/`tcp` factories using [`Tls::default`];
    /// HTTPS connections fail at runtime if no TLS feature is
    /// enabled.
    pub fn new(resolver: Url) -> Self {
        Self {
            pool: Default::default(),
            resolver,
        }
    }

    /// Replaces the underlying pool's TLS profile (re-registering
    /// the default factories under it).
    pub fn with_tls(mut self, tls: Tls) -> Self {
        self.pool = StreamPool::new(tls);
        self
    }

    /// Registers (or replaces) the pool factory for `scheme`. Use
    /// to plug a custom TLS crate, transport, or mock. Pass a
    /// lowercase literal (`"https"`, `"tcp"`, …).
    pub fn with_factory<F, S>(mut self, scheme: &'static str, factory: F) -> Self
    where
        F: FnMut(&Url) -> anyhow::Result<S> + 'static,
        S: Stream + 'static,
    {
        self.pool = self.pool.with_factory(scheme, factory);
        self
    }

    /// Runs the full PACC discovery for `domain`. Streams are
    /// opened on demand: HTTPS to the well-known PACC URL on the
    /// fetch step, plain TCP to the configured resolver on the
    /// verify step.
    pub fn discover(&mut self, domain: &str) -> Result<PaccConfig, DiscoveryPaccClientError> {
        let mut pacc = DiscoveryPacc::new(domain, self.resolver.clone())?;

        let mut buf = [0u8; 8192];
        let mut arg: Option<&[u8]> = None;

        loop {
            match pacc.resume(arg.take()) {
                DiscoveryPaccResult::Ok(config) => return Ok(config),
                DiscoveryPaccResult::WantsRead { url } => {
                    let stream = self.pool.get(&url)?;
                    let n = stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                DiscoveryPaccResult::WantsWrite { url, bytes } => {
                    let stream = self.pool.get(&url)?;
                    stream.write_all(&bytes)?;
                }
                DiscoveryPaccResult::Err(err) => return Err(err.into()),
            }
        }
    }
}
