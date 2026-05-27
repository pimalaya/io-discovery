//! # Combined RFC 6186 SRV discovery coroutine
//!
//! [`DiscoverySrv`] runs the three RFC 6186 SRV queries
//! (`_imap._tcp.<domain>`, `_imaps._tcp.<domain>`,
//! `_submission._tcp.<domain>`) in series, picks the best record per
//! service (lowest priority, highest weight on ties; already sorted
//! by [`DiscoveryDnsSrv`]), and yields a single [`SrvReport`] when
//! all three steps have completed.
//!
//! A per-service DNS failure (`InvalidQname`, `QueryTooLarge`,
//! `InvalidResponse`) terminates the whole coroutine with
//! [`DiscoverySrvError`]; empty SRV answers do not, the matching slot
//! is simply left as `None` in the report.

use core::mem;

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use domain::new::{
    base::{
        Record,
        name::{NameBuf, RevNameBuf},
    },
    rdata::Srv,
};
use thiserror::Error;
use url::Url;

use crate::rfc6186::{
    srv::{DiscoveryDnsSrv, DiscoveryDnsSrvError, DiscoveryDnsSrvResult},
    types::{SrvReport, SrvService},
};

/// Errors emitted by [`DiscoverySrv`].
#[derive(Debug, Error)]
pub enum DiscoverySrvError {
    #[error("DNS SRV lookup for `_imap._tcp` failed: {0}")]
    Imap(#[source] DiscoveryDnsSrvError),
    #[error("DNS SRV lookup for `_imaps._tcp` failed: {0}")]
    Imaps(#[source] DiscoveryDnsSrvError),
    #[error("DNS SRV lookup for `_submission._tcp` failed: {0}")]
    Submission(#[source] DiscoveryDnsSrvError),
}

/// Output emitted when the coroutine progresses or terminates.
pub enum DiscoverySrvResult {
    /// All three SRV lookups completed; the report carries the best
    /// record per service (or `None` for services that published no
    /// usable record).
    Ok(SrvReport),
    /// The active sub-step wants more bytes from the stream open on
    /// `url`.
    WantsRead { url: Url },
    /// The active sub-step wants the given bytes written to the
    /// stream open on `url`.
    WantsWrite { url: Url, bytes: Vec<u8> },
    /// One of the SRV lookups failed before the report could be
    /// assembled.
    Err(DiscoverySrvError),
}

#[derive(Default)]
enum State {
    Imap(DiscoveryDnsSrv),
    Imaps(DiscoveryDnsSrv),
    Submission(DiscoveryDnsSrv),
    #[default]
    Done,
}

/// I/O-free combined coroutine that runs the three RFC 6186 SRV
/// queries and assembles their best records into a [`SrvReport`].
pub struct DiscoverySrv {
    state: State,
    domain: String,
    resolver: Url,
    report: SrvReport,
}

impl DiscoverySrv {
    /// Builds the orchestrator. `resolver` must be a `tcp://host:port`
    /// URL pointing at a DNS-over-TCP resolver; it is yielded back on
    /// every `WantsRead` / `WantsWrite` so the runtime can route the
    /// bytes to the correct stream.
    pub fn new(domain: impl AsRef<str>, resolver: Url) -> Self {
        let domain = domain.as_ref().trim_matches('.').to_string();
        let imap = DiscoveryDnsSrv::new(format!("_imap._tcp.{domain}"), resolver.clone());

        Self {
            state: State::Imap(imap),
            domain,
            resolver,
            report: SrvReport::default(),
        }
    }

    /// Drives the orchestrator for one resume cycle.
    pub fn resume(&mut self, arg: Option<&[u8]>) -> DiscoverySrvResult {
        match mem::take(&mut self.state) {
            State::Imap(mut srv) => match srv.resume(arg) {
                DiscoveryDnsSrvResult::Ok(records) => {
                    self.report.imap = records.into_iter().next().map(into_service);
                    self.state = State::Imaps(DiscoveryDnsSrv::new(
                        format!("_imaps._tcp.{}", self.domain),
                        self.resolver.clone(),
                    ));
                    self.resume(None)
                }
                DiscoveryDnsSrvResult::WantsRead { url } => {
                    self.state = State::Imap(srv);
                    DiscoverySrvResult::WantsRead { url }
                }
                DiscoveryDnsSrvResult::WantsWrite { url, bytes } => {
                    self.state = State::Imap(srv);
                    DiscoverySrvResult::WantsWrite { url, bytes }
                }
                DiscoveryDnsSrvResult::Err(err) => {
                    DiscoverySrvResult::Err(DiscoverySrvError::Imap(err))
                }
            },
            State::Imaps(mut srv) => match srv.resume(arg) {
                DiscoveryDnsSrvResult::Ok(records) => {
                    self.report.imaps = records.into_iter().next().map(into_service);
                    self.state = State::Submission(DiscoveryDnsSrv::new(
                        format!("_submission._tcp.{}", self.domain),
                        self.resolver.clone(),
                    ));
                    self.resume(None)
                }
                DiscoveryDnsSrvResult::WantsRead { url } => {
                    self.state = State::Imaps(srv);
                    DiscoverySrvResult::WantsRead { url }
                }
                DiscoveryDnsSrvResult::WantsWrite { url, bytes } => {
                    self.state = State::Imaps(srv);
                    DiscoverySrvResult::WantsWrite { url, bytes }
                }
                DiscoveryDnsSrvResult::Err(err) => {
                    DiscoverySrvResult::Err(DiscoverySrvError::Imaps(err))
                }
            },
            State::Submission(mut srv) => match srv.resume(arg) {
                DiscoveryDnsSrvResult::Ok(records) => {
                    self.report.submission = records.into_iter().next().map(into_service);
                    DiscoverySrvResult::Ok(mem::take(&mut self.report))
                }
                DiscoveryDnsSrvResult::WantsRead { url } => {
                    self.state = State::Submission(srv);
                    DiscoverySrvResult::WantsRead { url }
                }
                DiscoveryDnsSrvResult::WantsWrite { url, bytes } => {
                    self.state = State::Submission(srv);
                    DiscoverySrvResult::WantsWrite { url, bytes }
                }
                DiscoveryDnsSrvResult::Err(err) => {
                    DiscoverySrvResult::Err(DiscoverySrvError::Submission(err))
                }
            },
            State::Done => panic!("DiscoverySrv::resume called after completion"),
        }
    }
}

fn into_service(record: Record<RevNameBuf, Srv<NameBuf>>) -> SrvService {
    SrvService {
        host: record
            .rdata
            .target
            .to_string()
            .trim_end_matches('.')
            .to_string(),
        port: record.rdata.port.get(),
        priority: record.rdata.priority.get(),
        weight: record.rdata.weight.get(),
    }
}
