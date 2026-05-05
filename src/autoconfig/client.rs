//! # Standard, blocking autoconfig discovery client
//!
//! Thin wrapper that drives the [`autoconfig`](crate::autoconfig)
//! coroutines against a caller-provided blocking [`Read`]/[`Write`]
//! stream. Each method consumes one full coroutine cycle on the
//! owned stream — the caller picks an appropriate stream per call
//! (HTTPS for [`isp`], TCP-to-DNS for [`mx`] / [`mailconf`] /
//! [`srv_query`]).
//!
//! [`isp`]: DiscoveryAutoconfigClient::isp
//! [`mx`]: DiscoveryAutoconfigClient::mx
//! [`mailconf`]: DiscoveryAutoconfigClient::mailconf
//! [`srv_query`]: DiscoveryAutoconfigClient::srv_query

use std::{
    borrow::ToOwned,
    io::{self, Read, Write},
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
    Io(#[from] io::Error),
    #[error("autoconfig discovery exhausted all strategies for `{0}`")]
    NotFound(String),
}

/// Std-blocking client wrapping one [`Read`]/[`Write`] stream that
/// the runtime drives against the autoconfig coroutines.
pub struct DiscoveryAutoconfigClient<S: Read + Write> {
    stream: S,
}

impl<S: Read + Write> DiscoveryAutoconfigClient<S> {
    /// Builds a client owning the given stream.
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    /// Releases ownership of the underlying stream to the caller.
    pub fn into_inner(self) -> S {
        self.stream
    }

    /// Drives [`DiscoveryIsp`] against the owned HTTPS stream
    /// (already connected to `url`'s host).
    pub fn isp(&mut self, url: Url) -> Result<Autoconfig, DiscoveryAutoconfigClientError> {
        let mut isp = DiscoveryIsp::new(url);
        let mut buf = [0u8; 8192];
        let mut arg = None;

        loop {
            match isp.resume(arg) {
                DiscoveryIspResult::Ok(autoconfig) => return Ok(autoconfig),
                DiscoveryIspResult::WantsWrite(ref bytes) => {
                    self.stream.write_all(bytes)?;
                    arg = None;
                }
                DiscoveryIspResult::WantsRead => {
                    let n = self.stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                DiscoveryIspResult::Err(err) => return Err(err.into()),
            }
        }
    }

    /// Drives [`DiscoveryDnsMx`] against the owned DNS TCP stream.
    /// Records are returned sorted by ascending preference.
    pub fn mx(
        &mut self,
        domain: &str,
    ) -> Result<Vec<Record<RevNameBuf, Mx<NameBuf>>>, DiscoveryAutoconfigClientError> {
        let mut dns = DiscoveryDnsMx::new(domain);
        let mut buf = [0u8; 4096];
        let mut arg = None;

        loop {
            match dns.resume(arg) {
                DiscoveryDnsMxResult::Ok(records) => return Ok(records),
                DiscoveryDnsMxResult::WantsWrite(ref bytes) => {
                    self.stream.write_all(bytes)?;
                    arg = None;
                }
                DiscoveryDnsMxResult::WantsRead => {
                    let n = self.stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                DiscoveryDnsMxResult::Err(err) => return Err(err.into()),
            }
        }
    }

    /// Drives [`DiscoveryMailconf`] against the owned DNS TCP stream.
    /// Returns the URL declared in the `mailconf=` TXT record.
    pub fn mailconf(&mut self, domain: &str) -> Result<Url, DiscoveryAutoconfigClientError> {
        let mut mc = DiscoveryMailconf::new(domain);
        let mut buf = [0u8; 4096];
        let mut arg = None;

        loop {
            match mc.resume(arg) {
                DiscoveryMailconfResult::Ok(url) => return Ok(url),
                DiscoveryMailconfResult::WantsWrite(ref bytes) => {
                    self.stream.write_all(bytes)?;
                    arg = None;
                }
                DiscoveryMailconfResult::WantsRead => {
                    let n = self.stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                DiscoveryMailconfResult::Err(err) => return Err(err.into()),
            }
        }
    }

    /// Drives [`DiscoveryDnsSrv`] against the owned DNS TCP stream
    /// for the given fully-qualified service name
    /// (`_imap._tcp.<domain>`, etc.).
    pub fn srv_query(
        &mut self,
        qname: &str,
    ) -> Result<Vec<Record<RevNameBuf, Srv<NameBuf>>>, DiscoveryAutoconfigClientError> {
        let mut dns = DiscoveryDnsSrv::new(qname);
        let mut buf = [0u8; 4096];
        let mut arg = None;

        loop {
            match dns.resume(arg) {
                DiscoveryDnsSrvResult::Ok(records) => return Ok(records),
                DiscoveryDnsSrvResult::WantsWrite(ref bytes) => {
                    self.stream.write_all(bytes)?;
                    arg = None;
                }
                DiscoveryDnsSrvResult::WantsRead => {
                    let n = self.stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                DiscoveryDnsSrvResult::Err(err) => return Err(err.into()),
            }
        }
    }
}

/// Builds an [`Autoconfig`] from the best SRV records for the
/// `_imap._tcp`, `_imaps._tcp` and `_submission._tcp` services on
/// `domain`. Returns [`DiscoveryAutoconfigClientError::NotFound`]
/// when none of the three is present.
pub fn assemble_srv(
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
