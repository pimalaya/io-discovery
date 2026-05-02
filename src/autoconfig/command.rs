use std::{
    io::{Read, Write},
    net::TcpStream,
};

use anyhow::{Result, anyhow, bail};
use clap::Subcommand;
use domain::new::{base::name::NameBuf, rdata::Srv};
use log::trace;
use pimalaya_toolbox::{stream::http::HttpSession, terminal::printer::Printer};
use url::Url;

use crate::autoconfig::{
    dns_mx::*,
    dns_srv::*,
    dns_txt::*,
    isp::*,
    serde::{
        AuthenticationType, AutoConfig, EmailProvider, EmailProviderProperty, SecurityType, Server,
        ServerProperty, ServerType,
    },
};

const DEFAULT_DNS_SERVER: &str = "1.1.1.1:53";

const MAILCONF_PREFIX: &[u8] = b"mailconf=";

/// Autoconfig CLI.
///
/// Each subcommand corresponds to one Mozilla [Autoconfiguration]
/// step. `isps` walks every ISP strategy in order; `full` chains the
/// ISP iteration with the DNS-based fallbacks.
///
/// [Autoconfiguration]: https://wiki.mozilla.org/Thunderbird:Autoconfiguration
#[derive(Debug, Subcommand)]
#[command(rename_all = "kebab-case")]
pub enum AutoconfigCommand {
    /// Try a single ISP main location.
    Isp {
        local_part: String,
        domain: String,
        #[arg(short, long)]
        secure: bool,
    },

    /// Try a single ISP alternative (`/.well-known`) location.
    IspFallback {
        domain: String,
        #[arg(short, long)]
        secure: bool,
    },

    /// Try a single Thunderbird ISPDB lookup.
    Ispdb {
        domain: String,
        #[arg(short, long)]
        secure: bool,
    },

    /// Look up MX records for the given domain.
    DnsMx {
        domain: String,
        #[arg(long)]
        server: Option<String>,
    },

    /// Look up the mailconf URL declared by a TXT record on the
    /// domain.
    DnsTxtMailconf {
        domain: String,
        #[arg(long)]
        server: Option<String>,
    },

    /// Build an autoconfig from the SRV records for `_imap._tcp`,
    /// `_imaps._tcp`, and `_submission._tcp` under the domain.
    DnsSrv {
        domain: String,
        #[arg(long)]
        server: Option<String>,
    },

    /// Run the whole discovery: ISP iteration, then DNS MX (re-run
    /// ISPs against the MX target), then TXT mailconf, then SRV.
    Full {
        local_part: String,
        domain: String,
        #[arg(long)]
        server: Option<String>,
    },
}

impl AutoconfigCommand {
    pub fn execute(self, printer: &mut impl Printer) -> Result<()> {
        match self {
            Self::Isp {
                local_part,
                domain,
                secure,
            } => {
                let url = DiscoveryIsp::isp_url(local_part, domain, secure)?;

                let mut http = HttpSession::new(&url, Default::default())?;
                let mut isp = DiscoveryIsp::new(url);

                let mut buf = [0u8; 8192];
                let mut arg = None;

                let autoconfig = loop {
                    match isp.resume(arg) {
                        DiscoveryIspResult::Ok(autoconfig) => break autoconfig,
                        DiscoveryIspResult::WantsWrite(ref bytes) => {
                            http.stream.write(bytes)?;
                            arg = None;
                        }
                        DiscoveryIspResult::WantsRead => {
                            let n = http.stream.read(&mut buf)?;
                            arg = Some(&buf[..n]);
                        }
                        DiscoveryIspResult::Err(err) => bail!(err),
                    }
                };

                printer.out(autoconfig)
            }

            Self::IspFallback { domain, secure } => {
                let url = DiscoveryIsp::isp_fallback_url(domain, secure)?;

                let mut http = HttpSession::new(&url, Default::default())?;
                let mut isp = DiscoveryIsp::new(url);

                let mut buf = [0u8; 8192];
                let mut arg = None;

                let autoconfig = loop {
                    match isp.resume(arg) {
                        DiscoveryIspResult::Ok(autoconfig) => break autoconfig,
                        DiscoveryIspResult::WantsWrite(ref bytes) => {
                            http.stream.write(bytes)?;
                            arg = None;
                        }
                        DiscoveryIspResult::WantsRead => {
                            let n = http.stream.read(&mut buf)?;
                            arg = Some(&buf[..n]);
                        }
                        DiscoveryIspResult::Err(err) => bail!(err),
                    }
                };

                printer.out(autoconfig)
            }

            Self::Ispdb { domain, secure } => {
                let url = DiscoveryIsp::ispdb_url(domain, secure)?;

                let mut http = HttpSession::new(&url, Default::default())?;
                let mut isp = DiscoveryIsp::new(url);

                let mut buf = [0u8; 8192];
                let mut arg = None;

                let autoconfig = loop {
                    match isp.resume(arg) {
                        DiscoveryIspResult::Ok(autoconfig) => break autoconfig,
                        DiscoveryIspResult::WantsWrite(ref bytes) => {
                            http.stream.write(bytes)?;
                            arg = None;
                        }
                        DiscoveryIspResult::WantsRead => {
                            let n = http.stream.read(&mut buf)?;
                            arg = Some(&buf[..n]);
                        }
                        DiscoveryIspResult::Err(err) => bail!(err),
                    }
                };

                printer.out(autoconfig)
            }

            Self::DnsMx { domain, server } => {
                let server = server.as_deref().unwrap_or(DEFAULT_DNS_SERVER);
                let mut stream = TcpStream::connect(server)?;

                let mut dns = DiscoveryDnsMx::new(domain);
                let mut buf = [0u8; 4096];
                let mut arg = None;

                let records = loop {
                    match dns.resume(arg) {
                        DiscoveryDnsMxResult::Ok(records) => break records,
                        DiscoveryDnsMxResult::WantsWrite(ref bytes) => {
                            stream.write_all(bytes)?;
                            arg = None;
                        }
                        DiscoveryDnsMxResult::WantsRead => {
                            let n = stream.read(&mut buf)?;
                            arg = Some(&buf[..n]);
                        }
                        DiscoveryDnsMxResult::Err(err) => bail!(err),
                    }
                };

                for record in records {
                    println!("{} {}", record.rdata.preference, record.rdata.exchange);
                }

                Ok(())
            }

            Self::DnsTxtMailconf { domain, server } => {
                let server = server.as_deref().unwrap_or(DEFAULT_DNS_SERVER);
                let mut stream = TcpStream::connect(server)?;

                let mut txt = DiscoveryDnsTxt::new(&domain);
                let mut buf = [0u8; 4096];
                let mut arg = None;

                let records = loop {
                    match txt.resume(arg) {
                        DiscoveryDnsTxtResult::Ok(records) => break records,
                        DiscoveryDnsTxtResult::WantsWrite(ref bytes) => {
                            stream.write_all(bytes)?;
                            arg = None;
                        }
                        DiscoveryDnsTxtResult::WantsRead => {
                            let n = stream.read(&mut buf)?;
                            arg = Some(&buf[..n]);
                        }
                        DiscoveryDnsTxtResult::Err(err) => bail!(err),
                    }
                };

                let value = records
                    .iter()
                    .flat_map(|r| r.rdata.iter())
                    .find_map(|cs| cs.octets.strip_prefix(MAILCONF_PREFIX))
                    .ok_or_else(|| anyhow!("no mailconf TXT record found for {domain}"))?;

                let url_str = std::str::from_utf8(value)
                    .map_err(|err| anyhow!("mailconf TXT value is not UTF-8: {err}"))?;
                let url = Url::parse(url_str.trim())
                    .map_err(|err| anyhow!("mailconf TXT value is not a URL: {err}"))?;

                println!("{url}");
                Ok(())
            }

            Self::DnsSrv { domain, server } => {
                let server = server.as_deref().unwrap_or(DEFAULT_DNS_SERVER);

                let mut buf = [0u8; 4096];
                let mut bests: [Option<Srv<NameBuf>>; 3] = [None, None, None];

                for (i, service) in ["imap", "imaps", "submission"].iter().enumerate() {
                    let qname = format!("_{service}._tcp.{domain}");
                    let mut stream = TcpStream::connect(server)?;

                    let mut srv = DiscoveryDnsSrv::new(&qname);
                    let mut arg = None;

                    let records = loop {
                        match srv.resume(arg) {
                            DiscoveryDnsSrvResult::Ok(records) => break records,
                            DiscoveryDnsSrvResult::WantsWrite(ref bytes) => {
                                stream.write_all(bytes)?;
                                arg = None;
                            }
                            DiscoveryDnsSrvResult::WantsRead => {
                                let n = stream.read(&mut buf)?;
                                arg = Some(&buf[..n]);
                            }
                            DiscoveryDnsSrvResult::Err(err) => bail!(err),
                        }
                    };

                    bests[i] = records.into_iter().next().map(|r| r.rdata);
                }

                let [imap, imaps, submission] = bests;

                let mut config = AutoConfig {
                    version: "1.1".to_owned(),
                    email_provider: EmailProvider {
                        id: domain.clone(),
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
                                ServerProperty::Authentication(
                                    AuthenticationType::PasswordCleartext,
                                ),
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
                                ServerProperty::Authentication(
                                    AuthenticationType::PasswordCleartext,
                                ),
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
                                ServerProperty::Authentication(
                                    AuthenticationType::PasswordCleartext,
                                ),
                            ],
                        }));
                }

                if config.email_provider.properties.is_empty() {
                    bail!("no autoconfig SRV record found for {domain}");
                }

                printer.out(config)
            }

            Self::Full {
                local_part,
                domain,
                server,
            } => {
                let dns_server = server.as_deref().unwrap_or(DEFAULT_DNS_SERVER);
                let mut buf = [0u8; 8192];

                let autoconfig: AutoConfig = 'discover: {
                    // ---- 1. ISP iteration on the user's domain ----
                    for url in DiscoveryIsp::all_urls(&local_part, &domain)? {
                        trace!("trying autoconfig at {url}");

                        let Ok(mut http) = HttpSession::new(&url, Default::default()) else {
                            trace!("connect to {url} failed");
                            continue;
                        };

                        let mut isp = DiscoveryIsp::new(url.clone());
                        let mut arg = None;

                        loop {
                            match isp.resume(arg) {
                                DiscoveryIspResult::Ok(ac) => break 'discover ac,
                                DiscoveryIspResult::Err(err) => {
                                    trace!("autoconfig at {url} failed: {err}");
                                    break;
                                }
                                DiscoveryIspResult::WantsWrite(ref bytes) => {
                                    if http.stream.write(bytes).is_err() {
                                        break;
                                    }
                                    arg = None;
                                }
                                DiscoveryIspResult::WantsRead => match http.stream.read(&mut buf) {
                                    Ok(n) => arg = Some(&buf[..n]),
                                    Err(_) => break,
                                },
                            }
                        }
                    }

                    // ---- 2. DNS MX, then ISP iteration on the parent of
                    //         the best MX target ----
                    let mx_records = {
                        let mut stream = TcpStream::connect(dns_server)?;
                        let mut dns = DiscoveryDnsMx::new(&domain);
                        let mut arg = None;
                        loop {
                            match dns.resume(arg) {
                                DiscoveryDnsMxResult::Ok(records) => break records,
                                DiscoveryDnsMxResult::Err(err) => bail!(err),
                                DiscoveryDnsMxResult::WantsWrite(ref bytes) => {
                                    stream.write_all(bytes)?;
                                    arg = None;
                                }
                                DiscoveryDnsMxResult::WantsRead => {
                                    let n = stream.read(&mut buf)?;
                                    arg = Some(&buf[..n]);
                                }
                            }
                        }
                    };

                    if let Some(mx_domain) = mx_records
                        .first()
                        .map(|r| r.rdata.exchange.to_string())
                        .and_then(|target| mx_parent_domain(&target))
                        .filter(|d| d != &domain)
                    {
                        trace!("re-trying ISPs against MX parent {mx_domain}");
                        for url in DiscoveryIsp::all_urls(&local_part, &mx_domain)? {
                            trace!("trying autoconfig at {url}");

                            let Ok(mut http) = HttpSession::new(&url, Default::default()) else {
                                trace!("connect to {url} failed");
                                continue;
                            };
                            let mut isp = DiscoveryIsp::new(url.clone());
                            let mut arg = None;

                            loop {
                                match isp.resume(arg) {
                                    DiscoveryIspResult::Ok(ac) => break 'discover ac,
                                    DiscoveryIspResult::Err(err) => {
                                        trace!("autoconfig at {url} failed: {err}");
                                        break;
                                    }
                                    DiscoveryIspResult::WantsWrite(ref bytes) => {
                                        if http.stream.write(bytes).is_err() {
                                            break;
                                        }
                                        arg = None;
                                    }
                                    DiscoveryIspResult::WantsRead => {
                                        match http.stream.read(&mut buf) {
                                            Ok(n) => arg = Some(&buf[..n]),
                                            Err(_) => break,
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // ---- 3. DNS TXT mailconf, then fetch the URL it points to ----
                    let txt_records = {
                        let mut stream = TcpStream::connect(dns_server)?;
                        let mut txt = DiscoveryDnsTxt::new(&domain);
                        let mut arg = None;
                        loop {
                            match txt.resume(arg) {
                                DiscoveryDnsTxtResult::Ok(records) => break records,
                                DiscoveryDnsTxtResult::Err(err) => bail!(err),
                                DiscoveryDnsTxtResult::WantsWrite(ref bytes) => {
                                    stream.write_all(bytes)?;
                                    arg = None;
                                }
                                DiscoveryDnsTxtResult::WantsRead => {
                                    let n = stream.read(&mut buf)?;
                                    arg = Some(&buf[..n]);
                                }
                            }
                        }
                    };

                    let mailconf_url = txt_records
                        .iter()
                        .flat_map(|r| r.rdata.iter())
                        .find_map(|cs| cs.octets.strip_prefix(MAILCONF_PREFIX))
                        .and_then(|v| std::str::from_utf8(v).ok())
                        .and_then(|s| Url::parse(s.trim()).ok());

                    if let Some(url) = mailconf_url {
                        trace!("fetching mailconf URL {url}");

                        if let Ok(mut http) = HttpSession::new(&url, Default::default()) {
                            let mut isp = DiscoveryIsp::new(url.clone());
                            let mut arg = None;

                            loop {
                                match isp.resume(arg) {
                                    DiscoveryIspResult::Ok(ac) => break 'discover ac,
                                    DiscoveryIspResult::Err(err) => {
                                        trace!("mailconf fetch at {url} failed: {err}");
                                        break;
                                    }
                                    DiscoveryIspResult::WantsWrite(ref bytes) => {
                                        if http.stream.write(bytes).is_err() {
                                            break;
                                        }
                                        arg = None;
                                    }
                                    DiscoveryIspResult::WantsRead => {
                                        match http.stream.read(&mut buf) {
                                            Ok(n) => arg = Some(&buf[..n]),
                                            Err(_) => break,
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // ---- 4. DNS SRV → assemble autoconfig from records ----
                    let mut bests: [Option<Srv<NameBuf>>; 3] = [None, None, None];

                    for (i, service) in ["imap", "imaps", "submission"].iter().enumerate() {
                        let qname = format!("_{service}._tcp.{domain}");
                        let mut stream = TcpStream::connect(dns_server)?;
                        let mut srv = DiscoveryDnsSrv::new(&qname);
                        let mut arg = None;

                        let records = loop {
                            match srv.resume(arg) {
                                DiscoveryDnsSrvResult::Ok(records) => break records,
                                DiscoveryDnsSrvResult::Err(err) => bail!(err),
                                DiscoveryDnsSrvResult::WantsWrite(ref bytes) => {
                                    stream.write_all(bytes)?;
                                    arg = None;
                                }
                                DiscoveryDnsSrvResult::WantsRead => {
                                    let n = stream.read(&mut buf)?;
                                    arg = Some(&buf[..n]);
                                }
                            }
                        };

                        bests[i] = records.into_iter().next().map(|r| r.rdata);
                    }

                    let [imap, imaps, submission] = bests;

                    let mut config = AutoConfig {
                        version: "1.1".to_owned(),
                        email_provider: EmailProvider {
                            id: domain.clone(),
                            properties: Vec::new(),
                        },
                        oauth2: None,
                    };

                    if let Some(srv) = imap {
                        config.email_provider.properties.push(
                            EmailProviderProperty::IncomingServer(Server {
                                r#type: ServerType::Imap,
                                properties: vec![
                                    ServerProperty::Hostname(
                                        srv.target.to_string().trim_end_matches('.').to_owned(),
                                    ),
                                    ServerProperty::Port(srv.port.get()),
                                    ServerProperty::SocketType(SecurityType::Starttls),
                                    ServerProperty::Authentication(
                                        AuthenticationType::PasswordCleartext,
                                    ),
                                ],
                            }),
                        );
                    }

                    if let Some(srv) = imaps {
                        config.email_provider.properties.push(
                            EmailProviderProperty::IncomingServer(Server {
                                r#type: ServerType::Imap,
                                properties: vec![
                                    ServerProperty::Hostname(
                                        srv.target.to_string().trim_end_matches('.').to_owned(),
                                    ),
                                    ServerProperty::Port(srv.port.get()),
                                    ServerProperty::SocketType(SecurityType::Tls),
                                    ServerProperty::Authentication(
                                        AuthenticationType::PasswordCleartext,
                                    ),
                                ],
                            }),
                        );
                    }

                    if let Some(srv) = submission {
                        let security = match srv.port.get() {
                            25 => SecurityType::Plain,
                            587 => SecurityType::Starttls,
                            _ => SecurityType::Tls,
                        };
                        config.email_provider.properties.push(
                            EmailProviderProperty::OutgoingServer(Server {
                                r#type: ServerType::Smtp,
                                properties: vec![
                                    ServerProperty::Hostname(
                                        srv.target.to_string().trim_end_matches('.').to_owned(),
                                    ),
                                    ServerProperty::Port(srv.port.get()),
                                    ServerProperty::SocketType(security),
                                    ServerProperty::Authentication(
                                        AuthenticationType::PasswordCleartext,
                                    ),
                                ],
                            }),
                        );
                    }

                    if !config.email_provider.properties.is_empty() {
                        break 'discover config;
                    }

                    bail!("autoconfig discovery failed for {domain}");
                };

                printer.out(autoconfig)
            }
        }
    }
}
