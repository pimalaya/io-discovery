use std::{
    io::{Read, Write},
    net::TcpStream,
};

use anyhow::{Result, bail};
use clap::Subcommand;
use pimalaya_cli::printer::Printer;
use pimalaya_toolbox::stream::http::HttpSession;

use crate::pacc::{fetch::*, verify::*};

const DEFAULT_DNS_SERVER: &str = "1.1.1.1:53";

/// PACC CLI (`draft-ietf-mailmaint-pacc-02`).
///
/// `fetch` retrieves the JSON configuration. `verify` checks an
/// already-fetched body against the DNS TXT digest. `full` chains
/// the two: fetch, verify, then print the configuration.
#[derive(Debug, Subcommand)]
#[command(rename_all = "kebab-case")]
pub enum PaccCommand {
    /// Fetch the well-known PACC configuration document for `domain`.
    Fetch { domain: String },

    /// Verify a configuration body (read from stdin) against the
    /// `_ua-auto-config` TXT digest published for `domain`.
    Verify {
        domain: String,
        #[arg(long)]
        server: Option<String>,
    },

    /// Fetch and verify the PACC configuration for `domain`.
    Full {
        domain: String,
        #[arg(long)]
        server: Option<String>,
    },
}

impl PaccCommand {
    pub fn execute(self, printer: &mut impl Printer) -> Result<()> {
        match self {
            Self::Fetch { domain } => {
                let url = DiscoveryPaccFetch::url(domain)?;

                let mut http = HttpSession::new(&url, Default::default())?;
                let mut pacc = DiscoveryPaccFetch::new(url);

                let mut buf = [0u8; 8192];
                let mut arg = None;

                let config = loop {
                    match pacc.resume(arg) {
                        DiscoveryPaccFetchResult::Ok { config, .. } => break config,
                        DiscoveryPaccFetchResult::WantsWrite(ref bytes) => {
                            http.stream.write(bytes)?;
                            arg = None;
                        }
                        DiscoveryPaccFetchResult::WantsRead => {
                            let n = http.stream.read(&mut buf)?;
                            arg = Some(&buf[..n]);
                        }
                        DiscoveryPaccFetchResult::Err(err) => bail!(err),
                    }
                };

                printer.out(config)
            }

            Self::Verify { domain, server } => {
                let mut body = Vec::new();
                std::io::stdin().read_to_end(&mut body)?;

                let dns_server = server.as_deref().unwrap_or(DEFAULT_DNS_SERVER);
                let mut stream = TcpStream::connect(dns_server)?;

                let mut verify = DiscoveryPaccVerify::new(&domain, body);
                let mut buf = [0u8; 4096];
                let mut arg = None;

                loop {
                    match verify.resume(arg) {
                        DiscoveryPaccVerifyResult::Ok => break,
                        DiscoveryPaccVerifyResult::WantsWrite(ref bytes) => {
                            stream.write_all(bytes)?;
                            arg = None;
                        }
                        DiscoveryPaccVerifyResult::WantsRead => {
                            let n = stream.read(&mut buf)?;
                            arg = Some(&buf[..n]);
                        }
                        DiscoveryPaccVerifyResult::Err(err) => bail!(err),
                    }
                }

                printer.out("digest verified")
            }

            Self::Full { domain, server } => {
                let url = DiscoveryPaccFetch::url(&domain)?;

                let mut http = HttpSession::new(&url, Default::default())?;
                let mut pacc = DiscoveryPaccFetch::new(url);

                let mut buf = [0u8; 8192];
                let mut arg = None;

                let (config, raw) = loop {
                    match pacc.resume(arg) {
                        DiscoveryPaccFetchResult::Ok { config, raw } => break (config, raw),
                        DiscoveryPaccFetchResult::WantsWrite(ref bytes) => {
                            http.stream.write(bytes)?;
                            arg = None;
                        }
                        DiscoveryPaccFetchResult::WantsRead => {
                            let n = http.stream.read(&mut buf)?;
                            arg = Some(&buf[..n]);
                        }
                        DiscoveryPaccFetchResult::Err(err) => bail!(err),
                    }
                };

                let dns_server = server.as_deref().unwrap_or(DEFAULT_DNS_SERVER);
                let mut stream = TcpStream::connect(dns_server)?;

                let mut verify = DiscoveryPaccVerify::new(&domain, raw);
                let mut dns_buf = [0u8; 4096];
                let mut arg = None;

                loop {
                    match verify.resume(arg) {
                        DiscoveryPaccVerifyResult::Ok => break,
                        DiscoveryPaccVerifyResult::WantsWrite(ref bytes) => {
                            stream.write_all(bytes)?;
                            arg = None;
                        }
                        DiscoveryPaccVerifyResult::WantsRead => {
                            let n = stream.read(&mut dns_buf)?;
                            arg = Some(&dns_buf[..n]);
                        }
                        DiscoveryPaccVerifyResult::Err(err) => bail!(err),
                    }
                }

                printer.out(config)
            }
        }
    }
}
