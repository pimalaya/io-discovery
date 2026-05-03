use std::{
    io::{Read, Write},
    net::TcpStream,
};

use alloc::string::String;
use anyhow::{Result, bail};
use clap::Args;
use pimalaya_cli::printer::Printer;
use pimalaya_toolbox::stream::{Stream, http::HttpSession};

use crate::pacc::coroutine::*;

const DEFAULT_DNS_SERVER: &str = "1.1.1.1:53";

/// PACC discovery (`draft-ietf-mailmaint-pacc-02`).
///
/// Fetches the well-known PACC configuration for `domain` and verifies
/// it against the digest published in the `_ua-auto-config` TXT record
/// before parsing it as JSON.
#[derive(Debug, Args)]
pub struct PaccCommand {
    /// Domain to discover the configuration for.
    pub domain: String,

    /// DNS resolver (`host:port`) used for the digest TXT lookup.
    #[arg(long)]
    pub server: Option<String>,
}

impl PaccCommand {
    pub fn execute(self, printer: &mut impl Printer) -> Result<()> {
        let Self { domain, server } = self;
        let dns_server = server.as_deref().unwrap_or(DEFAULT_DNS_SERVER);

        let url = DiscoveryPacc::url(&domain)?;
        let mut stream = HttpSession::new(&url, Default::default())?.stream;
        let mut pacc = DiscoveryPacc::new(&domain)?;

        let mut buf = [0u8; 8192];
        let mut arg: Option<&[u8]> = None;

        let config = loop {
            match pacc.resume(arg.take()) {
                DiscoveryPaccResult::Ok(config) => break config,
                DiscoveryPaccResult::WantsDnsConnect => {
                    stream = Stream::Tcp(TcpStream::connect(dns_server)?);
                }
                DiscoveryPaccResult::WantsWrite(ref bytes) => {
                    stream.write_all(bytes)?;
                }
                DiscoveryPaccResult::WantsRead => {
                    let n = stream.read(&mut buf)?;
                    arg = Some(&buf[..n]);
                }
                DiscoveryPaccResult::Err(err) => bail!(err),
            }
        };

        printer.out(config)
    }
}
