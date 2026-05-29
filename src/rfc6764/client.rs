//! # Standard, blocking RFC 6764 SRV discovery client
//!
//! [`DiscoveryRfc6764ClientStd`] drives the [`DiscoveryRfc6764`]
//! combined coroutine (four SRV queries: best-record-per-service
//! assembly) end-to-end through a local [`StreamPool`]. One method:
//! [`discover`].
//!
//! Only the default `tcp` factory is needed: SRV discovery never
//! opens an HTTPS connection. Custom DNS transports plug in via
//! [`with_factory`].
//!
//! [`with_factory`]: DiscoveryRfc6764ClientStd::with_factory
//! [`discover`]: DiscoveryRfc6764ClientStd::discover

use std::io;

use thiserror::Error;
use url::Url;

use crate::{
    coroutine::{DiscoveryCoroutine, DiscoveryCoroutineState, DiscoveryYield},
    rfc6764::{
        discover::{DiscoveryRfc6764, DiscoveryRfc6764Error},
        types::Rfc6764Report,
    },
    shared::pool::{Stream, StreamPool},
};

const READ_BUFFER_SIZE: usize = 8 * 1024;

/// Errors returned by [`DiscoveryRfc6764ClientStd::discover`].
#[derive(Debug, Error)]
pub enum DiscoveryRfc6764ClientStdError {
    /// The combined SRV coroutine errored out on one of its four
    /// lookups.
    #[error(transparent)]
    Discovery(#[from] DiscoveryRfc6764Error),
    /// Read or write against an open stream failed.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// [`StreamPool::get`] failed (unknown scheme, factory error).
    #[error(transparent)]
    Pool(#[from] anyhow::Error),
}

/// Std-blocking RFC 6764 SRV discovery client.
pub struct DiscoveryRfc6764ClientStd {
    dns: Url,
    pool: StreamPool,
}

impl DiscoveryRfc6764ClientStd {
    /// Builds a client that resolves SRV records through `dns` (a
    /// `tcp://host:port` URL pointing at a DNS-over-TCP resolver).
    /// The underlying pool is pre-populated with the default `tcp`
    /// factory; SRV discovery never opens HTTPS, so HTTPS factories
    /// are unnecessary.
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

    /// Runs the four RFC 6764 SRV lookups (`_caldav._tcp`,
    /// `_caldavs._tcp`, `_carddav._tcp`, `_carddavs._tcp`) on
    /// `domain` and returns the best record per service.
    pub fn discover(
        &mut self,
        domain: &str,
    ) -> Result<Rfc6764Report, DiscoveryRfc6764ClientStdError> {
        let mut coroutine = DiscoveryRfc6764::new(domain, self.dns.clone());
        let mut buf = [0u8; READ_BUFFER_SIZE];
        let mut arg: Option<&[u8]> = None;

        loop {
            match coroutine.resume(arg.take()) {
                DiscoveryCoroutineState::Complete(Ok(report)) => return Ok(report),
                DiscoveryCoroutineState::Complete(Err(err)) => return Err(err.into()),
                DiscoveryCoroutineState::Yielded(DiscoveryYield::WantsRead { url }) => {
                    let stream = self.pool.get(&url)?;
                    let n = stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                DiscoveryCoroutineState::Yielded(DiscoveryYield::WantsWrite { url, bytes }) => {
                    let stream = self.pool.get(&url)?;
                    stream.write_all(&bytes)?;
                }
            }
        }
    }
}
