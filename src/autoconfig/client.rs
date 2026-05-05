//! # Standard, blocking autoconfig discovery client
//!
//! Builder-style wrapper around the autoconfig coroutines. The pool
//! comes with default factories for `http`, `https`, and `tcp`
//! already registered — callers just construct with [`new`] and
//! call one of [`isp`] / [`mx`] / [`mailconf`] / [`srv_query`].
//! HTTPS connections fail at runtime if no TLS feature is enabled.
//! BYO callers register their own scheme factories through
//! [`with_factory`].
//!
//! [`new`]: DiscoveryAutoconfigClient::new
//! [`isp`]: DiscoveryAutoconfigClient::isp
//! [`mx`]: DiscoveryAutoconfigClient::mx
//! [`mailconf`]: DiscoveryAutoconfigClient::mailconf
//! [`srv_query`]: DiscoveryAutoconfigClient::srv_query
//! [`with_factory`]: DiscoveryAutoconfigClient::with_factory

use alloc::{
    borrow::ToOwned,
    string::{String, ToString},
    vec::Vec,
};

use domain::new::{
    base::{
        Record,
        name::{NameBuf, RevNameBuf},
    },
    rdata::{Mx, Srv},
};
use pimalaya_stream::{
    std::pool::{Stream, StreamPool},
    tls::Tls,
};
use thiserror::Error;
use url::{ParseError, Url};

use crate::{
    autoconfig::{
        coroutines::{dns_mx::*, dns_srv::*, isp::*, mailconf::*},
        types::*,
    },
    shared::dns_txt::*,
};

/// Errors returned by [`DiscoveryAutoconfigClient`].
#[derive(Debug, Error)]
pub enum DiscoveryAutoconfigClientError {
    #[error(transparent)]
    Isp(#[from] DiscoveryIspError),
    #[error(transparent)]
    DnsMx(#[from] DiscoveryDnsMxError),
    #[error(transparent)]
    DnsTxt(#[from] DiscoveryDnsTxtError),
    #[error(transparent)]
    DnsSrv(#[from] DiscoveryDnsSrvError),
    #[error(transparent)]
    Mailconf(#[from] DiscoveryMailconfError),
    #[error(transparent)]
    UrlParse(#[from] ParseError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Pool(#[from] anyhow::Error),
    #[error("autoconfig discovery exhausted all strategies for `{0}`")]
    NotFound(String),
}

/// Std-blocking autoconfig client driven through a [`StreamPool`].
pub struct DiscoveryAutoconfigClient {
    pool: StreamPool,
    resolver: Url,
}

impl DiscoveryAutoconfigClient {
    /// Builds a client that resolves DNS lookups through `resolver`
    /// (a `tcp://host:port` URL pointing at a DNS-over-TCP
    /// resolver). The underlying pool is pre-populated with default
    /// `http`/`https`/`tcp` factories using [`Tls::default`].
    pub fn new(resolver: Url) -> Self {
        Self {
            pool: StreamPool::default(),
            resolver,
        }
    }

    /// Replaces the underlying pool's TLS profile (re-registering
    /// the default factories under it).
    pub fn with_tls(mut self, tls: Tls) -> Self {
        self.pool = StreamPool::new(tls);
        self
    }

    /// Registers (or replaces) the pool factory for `scheme`. Pass
    /// a lowercase literal (`"https"`, `"tcp"`, …).
    pub fn with_factory<F, S>(mut self, scheme: &'static str, factory: F) -> Self
    where
        F: FnMut(&Url) -> anyhow::Result<S> + 'static,
        S: Stream + 'static,
    {
        self.pool = self.pool.with_factory(scheme, factory);
        self
    }

    /// Drives [`DiscoveryIsp`] for one ISP candidate URL.
    pub fn isp(&mut self, url: Url) -> Result<Autoconfig, DiscoveryAutoconfigClientError> {
        let mut isp = DiscoveryIsp::new(url);
        let mut buf = [0u8; 8192];
        let mut arg = None;

        loop {
            match isp.resume(arg) {
                DiscoveryIspResult::Ok(autoconfig) => return Ok(autoconfig),
                DiscoveryIspResult::WantsRead { url } => {
                    let stream = self.pool.get(&url)?;
                    let n = stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                DiscoveryIspResult::WantsWrite { url, bytes } => {
                    let stream = self.pool.get(&url)?;
                    stream.write_all(&bytes)?;
                    arg = None;
                }
                DiscoveryIspResult::Err(err) => return Err(err.into()),
            }
        }
    }

    /// Drives [`DiscoveryDnsMx`] for `domain`. Records are returned
    /// sorted by ascending preference.
    pub fn mx(
        &mut self,
        domain: &str,
    ) -> Result<Vec<Record<RevNameBuf, Mx<NameBuf>>>, DiscoveryAutoconfigClientError> {
        let mut dns = DiscoveryDnsMx::new(domain, self.resolver.clone());
        let mut buf = [0u8; 4096];
        let mut arg = None;

        loop {
            match dns.resume(arg) {
                DiscoveryDnsMxResult::Ok(records) => return Ok(records),
                DiscoveryDnsMxResult::WantsRead { url } => {
                    let stream = self.pool.get(&url)?;
                    let n = stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                DiscoveryDnsMxResult::WantsWrite { url, bytes } => {
                    let stream = self.pool.get(&url)?;
                    stream.write_all(&bytes)?;
                    arg = None;
                }
                DiscoveryDnsMxResult::Err(err) => return Err(err.into()),
            }
        }
    }

    /// Drives [`DiscoveryMailconf`] for `domain`. Returns the URL
    /// declared in the `mailconf=` TXT record.
    pub fn mailconf(&mut self, domain: &str) -> Result<Url, DiscoveryAutoconfigClientError> {
        let mut mc = DiscoveryMailconf::new(domain, self.resolver.clone());
        let mut buf = [0u8; 4096];
        let mut arg = None;

        loop {
            match mc.resume(arg) {
                DiscoveryMailconfResult::Ok(url) => return Ok(url),
                DiscoveryMailconfResult::WantsRead { url } => {
                    let stream = self.pool.get(&url)?;
                    let n = stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                DiscoveryMailconfResult::WantsWrite { url, bytes } => {
                    let stream = self.pool.get(&url)?;
                    stream.write_all(&bytes)?;
                    arg = None;
                }
                DiscoveryMailconfResult::Err(err) => return Err(err.into()),
            }
        }
    }

    /// Drives [`DiscoveryDnsSrv`] for the fully-qualified service
    /// name (`_imap._tcp.<domain>`, etc.).
    pub fn srv_query(
        &mut self,
        qname: &str,
    ) -> Result<Vec<Record<RevNameBuf, Srv<NameBuf>>>, DiscoveryAutoconfigClientError> {
        let mut dns = DiscoveryDnsSrv::new(qname, self.resolver.clone());
        let mut buf = [0u8; 4096];
        let mut arg = None;

        loop {
            match dns.resume(arg) {
                DiscoveryDnsSrvResult::Ok(records) => return Ok(records),
                DiscoveryDnsSrvResult::WantsRead { url } => {
                    let stream = self.pool.get(&url)?;
                    let n = stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                DiscoveryDnsSrvResult::WantsWrite { url, bytes } => {
                    let stream = self.pool.get(&url)?;
                    stream.write_all(&bytes)?;
                    arg = None;
                }
                DiscoveryDnsSrvResult::Err(err) => return Err(err.into()),
            }
        }
    }

    /// Builds an [`Autoconfig`] from the best SRV records for the
    /// `_imap._tcp`, `_imaps._tcp` and `_submission._tcp` services on
    /// `domain`. Returns [`DiscoveryAutoconfigClientError::NotFound`]
    /// when none of the three is present.
    pub fn assemble_srv(
        &self,
        domain: &str,
        imap: Option<Srv<NameBuf>>,
        imaps: Option<Srv<NameBuf>>,
        submission: Option<Srv<NameBuf>>,
    ) -> Result<Autoconfig, DiscoveryAutoconfigClientError> {
        let mut config = Autoconfig {
            version: "1.1".to_owned(),
            email_provider: EmailProvider {
                id: domain.to_owned(),
                domain: Vec::new(),
                display_name: None,
                display_short_name: None,
                incoming_server: Vec::new(),
                outgoing_server: Vec::new(),
                documentation: Vec::new(),
            },
            oauth2: None,
        };

        if let Some(srv) = imap {
            config.email_provider.incoming_server.push(Server {
                r#type: ServerType::Imap,
                hostname: Some(srv.target.to_string().trim_end_matches('.').to_owned()),
                port: Some(srv.port.get()),
                socket_type: Some(SecurityType::Starttls),
                username: None,
                authentication: vec![AuthenticationType::PasswordCleartext],
                pop3: None,
            });
        }

        if let Some(srv) = imaps {
            config.email_provider.incoming_server.push(Server {
                r#type: ServerType::Imap,
                hostname: Some(srv.target.to_string().trim_end_matches('.').to_owned()),
                port: Some(srv.port.get()),
                socket_type: Some(SecurityType::Tls),
                username: None,
                authentication: vec![AuthenticationType::PasswordCleartext],
                pop3: None,
            });
        }

        if let Some(srv) = submission {
            let security = match srv.port.get() {
                25 => SecurityType::Plain,
                587 => SecurityType::Starttls,
                _ => SecurityType::Tls,
            };

            config.email_provider.outgoing_server.push(Server {
                r#type: ServerType::Smtp,
                hostname: Some(srv.target.to_string().trim_end_matches('.').to_owned()),
                port: Some(srv.port.get()),
                socket_type: Some(security),
                username: None,
                authentication: vec![AuthenticationType::PasswordCleartext],
                pop3: None,
            });
        }

        if config.email_provider.incoming_server.is_empty()
            && config.email_provider.outgoing_server.is_empty()
        {
            return Err(DiscoveryAutoconfigClientError::NotFound(domain.to_owned()));
        }

        Ok(config)
    }
}
