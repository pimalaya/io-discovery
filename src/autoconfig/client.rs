//! # std-blocking autoconfig client.
//!
//! Thin wrappers that drive each [`autoconfig`](crate::autoconfig)
//! coroutine against blocking
//! [`pimalaya_toolbox::stream::Stream`]s. Suits callers that want a
//! plain `discover_full(local, domain, server) -> Autoconfig` without
//! the resume-loop ceremony.

use std::{
    borrow::ToOwned,
    io::{Read, Write},
    net::TcpStream,
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
use log::trace;
use pimalaya_toolbox::stream::http::HttpSession;
use thiserror::Error;
use url::{ParseError, Url};

use crate::{
    autoconfig::{dns_mx::*, dns_srv::*, isp::*, mailconf::*, types::*},
    shared::dns_txt::*,
};

/// Errors returned by the autoconfig client functions.
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
    #[error("HTTP session setup failed: {0}")]
    Http(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("autoconfig discovery exhausted all strategies for `{0}`")]
    NotFound(String),
}

/// Runs the whole autoconfig discovery: ISP iteration on the user's
/// domain, then ISP iteration against the parent of the best MX
/// target, then a TXT `mailconf=` lookup, then SRV records.
pub fn discover(
    local_part: &str,
    domain: &str,
    dns_server: &str,
) -> Result<Autoconfig, DiscoveryAutoconfigClientError> {
    // 1. ISP iteration on the user's domain.

    if let Some(ac) = try_all_isps(local_part, domain) {
        return Ok(ac);
    }

    // 2. DNS MX, then ISP iteration on the parent of the best MX
    // target.
    let mx_records = mx(domain, dns_server)?
        .first()
        .map(|r| r.rdata.exchange.to_string())
        .and_then(|target| mx_parent_domain(&target))
        .filter(|d| d != domain);

    if let Some(mx_domain) = mx_records {
        trace!("re-trying ISPs against MX parent {mx_domain}");
        if let Some(ac) = try_all_isps(local_part, &mx_domain) {
            return Ok(ac);
        }
    }

    // 3. DNS TXT mailconf, then fetch the URL it points to.
    if let Ok(url) = mailconf(domain, dns_server) {
        trace!("fetching mailconf URL {url}");
        if let Some(ac) = try_isp(url) {
            return Ok(ac);
        }
    }

    // 4. DNS SRV → assemble autoconfig from records.
    srv(domain, dns_server)
}

/// Fetches the ISP main location autoconfig
/// (`http[s]://autoconfig.<domain>/mail/config-v1.1.xml`).
pub fn isp_main(
    local_part: &str,
    domain: &str,
    secure: bool,
) -> Result<Autoconfig, DiscoveryAutoconfigClientError> {
    let url = DiscoveryIsp::main_url(local_part, domain, secure)?;
    isp(url)
}

/// Fetches the ISP fallback location autoconfig
/// (`http[s]://<domain>/.well-known/autoconfig/mail/config-v1.1.xml`).
pub fn isp_fallback(
    domain: &str,
    secure: bool,
) -> Result<Autoconfig, DiscoveryAutoconfigClientError> {
    let url = DiscoveryIsp::fallback_url(domain, secure)?;
    isp(url)
}

/// Fetches the Thunderbird ISPDB autoconfig
/// (`http[s]://autoconfig.thunderbird.net/v1.1/<domain>`).
pub fn ispdb(domain: &str, secure: bool) -> Result<Autoconfig, DiscoveryAutoconfigClientError> {
    let url = DiscoveryIsp::db_url(domain, secure)?;
    isp(url)
}

/// Resolves the MX records for `domain`, returned sorted by ascending
/// preference (best first).
pub fn mx(
    domain: &str,
    dns_server: &str,
) -> Result<Vec<Record<RevNameBuf, Mx<NameBuf>>>, DiscoveryAutoconfigClientError> {
    let mut stream = TcpStream::connect(dns_server)?;
    let mut dns = DiscoveryDnsMx::new(domain);
    let mut buf = [0u8; 4096];
    let mut arg = None;

    loop {
        match dns.resume(arg) {
            DiscoveryDnsMxResult::Ok(records) => return Ok(records),
            DiscoveryDnsMxResult::WantsWrite(ref bytes) => {
                stream.write_all(bytes)?;
                arg = None;
            }
            DiscoveryDnsMxResult::WantsRead => {
                let n = stream.read(&mut buf)?;
                arg = Some(&buf[..n]);
            }
            DiscoveryDnsMxResult::Err(err) => return Err(err.into()),
        }
    }
}

/// Resolves the `mailconf=<URL>` TXT record for `domain` and returns
/// the URL it points to.
pub fn mailconf(domain: &str, dns_server: &str) -> Result<Url, DiscoveryAutoconfigClientError> {
    let mut stream = TcpStream::connect(dns_server)?;
    let mut mc = DiscoveryMailconf::new(domain);
    let mut buf = [0u8; 4096];
    let mut arg = None;

    loop {
        match mc.resume(arg) {
            DiscoveryMailconfResult::Ok(url) => return Ok(url),
            DiscoveryMailconfResult::WantsWrite(ref bytes) => {
                stream.write_all(bytes)?;
                arg = None;
            }
            DiscoveryMailconfResult::WantsRead => {
                let n = stream.read(&mut buf)?;
                arg = Some(&buf[..n]);
            }
            DiscoveryMailconfResult::Err(err) => return Err(err.into()),
        }
    }
}

/// Builds an [`Autoconfig`] from the SRV records published for
/// `_imap._tcp.<domain>`, `_imaps._tcp.<domain>`, and
/// `_submission._tcp.<domain>`.
pub fn srv(domain: &str, dns_server: &str) -> Result<Autoconfig, DiscoveryAutoconfigClientError> {
    let mut buf = [0u8; 4096];
    let mut bests: [Option<Srv<NameBuf>>; 3] = [None, None, None];

    for (i, service) in ["imap", "imaps", "submission"].iter().enumerate() {
        let qname = format!("_{service}._tcp.{domain}");
        let mut stream = TcpStream::connect(dns_server)?;
        let mut dns = DiscoveryDnsSrv::new(&qname);
        let mut arg = None;

        let records = loop {
            match dns.resume(arg) {
                DiscoveryDnsSrvResult::Ok(records) => break records,
                DiscoveryDnsSrvResult::WantsWrite(ref bytes) => {
                    stream.write_all(bytes)?;
                    arg = None;
                }
                DiscoveryDnsSrvResult::WantsRead => {
                    let n = stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                DiscoveryDnsSrvResult::Err(err) => return Err(err.into()),
            }
        };

        bests[i] = records.into_iter().next().map(|r| r.rdata);
    }

    let [imap, imaps, submission] = bests;

    let mut config = Autoconfig {
        version: "1.1".to_owned(),
        email_provider: EmailProvider {
            id: domain.to_owned(),
            properties: Vec::new(),
        },
        oauth2: None,
    };

    if let Some(srv) = imap {
        config
            .email_provider
            .properties
            .push(EmailProviderProperty::IncomingServer(Server {
                r#type: ServerType::Imap,
                properties: vec![
                    ServerProperty::Hostname(
                        srv.target.to_string().trim_end_matches('.').to_owned(),
                    ),
                    ServerProperty::Port(srv.port.get()),
                    ServerProperty::SocketType(SecurityType::Starttls),
                    ServerProperty::Authentication(AuthenticationType::PasswordCleartext),
                ],
            }));
    }

    if let Some(srv) = imaps {
        config
            .email_provider
            .properties
            .push(EmailProviderProperty::IncomingServer(Server {
                r#type: ServerType::Imap,
                properties: vec![
                    ServerProperty::Hostname(
                        srv.target.to_string().trim_end_matches('.').to_owned(),
                    ),
                    ServerProperty::Port(srv.port.get()),
                    ServerProperty::SocketType(SecurityType::Tls),
                    ServerProperty::Authentication(AuthenticationType::PasswordCleartext),
                ],
            }));
    }

    if let Some(srv) = submission {
        let security = match srv.port.get() {
            25 => SecurityType::Plain,
            587 => SecurityType::Starttls,
            _ => SecurityType::Tls,
        };

        config
            .email_provider
            .properties
            .push(EmailProviderProperty::OutgoingServer(Server {
                r#type: ServerType::Smtp,
                properties: vec![
                    ServerProperty::Hostname(
                        srv.target.to_string().trim_end_matches('.').to_owned(),
                    ),
                    ServerProperty::Port(srv.port.get()),
                    ServerProperty::SocketType(security),
                    ServerProperty::Authentication(AuthenticationType::PasswordCleartext),
                ],
            }));
    }

    if config.email_provider.properties.is_empty() {
        return Err(DiscoveryAutoconfigClientError::NotFound(domain.to_owned()));
    }

    Ok(config)
}

fn isp(url: Url) -> Result<Autoconfig, DiscoveryAutoconfigClientError> {
    let mut http = HttpSession::new(&url, Default::default())
        .map_err(|err| DiscoveryAutoconfigClientError::Http(err.to_string()))?;
    let mut isp = DiscoveryIsp::new(url);
    let mut buf = [0u8; 8192];
    let mut arg = None;

    loop {
        match isp.resume(arg) {
            DiscoveryIspResult::Ok(autoconfig) => return Ok(autoconfig),
            DiscoveryIspResult::WantsWrite(ref bytes) => {
                http.stream.write_all(bytes)?;
                arg = None;
            }
            DiscoveryIspResult::WantsRead => {
                let n = http.stream.read(&mut buf)?;
                arg = Some(&buf[..n]);
            }
            DiscoveryIspResult::Err(err) => return Err(err.into()),
        }
    }
}

fn try_isp(url: Url) -> Option<Autoconfig> {
    trace!("trying autoconfig at {url}");

    match isp(url.clone()) {
        Ok(ac) => Some(ac),
        Err(err) => {
            trace!("autoconfig at {url} failed: {err}");
            None
        }
    }
}

fn try_all_isps(local_part: &str, domain: &str) -> Option<Autoconfig> {
    for url in DiscoveryIsp::all_urls(local_part, domain).ok()? {
        if let Some(ac) = try_isp(url) {
            return Some(ac);
        }
    }

    None
}
