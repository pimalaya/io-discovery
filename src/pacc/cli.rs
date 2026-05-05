use std::{net::TcpStream, string::String};

use anyhow::Result;
use clap::Args;
use pimalaya_cli::printer::Printer;
use pimalaya_stream::{std::http::HttpSession, tls::Tls};

use crate::{
    pacc::{client::DiscoveryPaccClient, coroutine::DiscoveryPacc},
    shared::defaults::DNS_SERVER,
};

/// PACC discovery (draft-ietf-mailmaint-pacc-02).
///
/// Fetches the well-known PACC configuration for `domain` and
/// verifies it against the digest published in the `_ua-auto-config`
/// TXT record before parsing it as JSON.
#[derive(Debug, Args)]
pub struct PaccCommand {
    /// Domain to discover the configuration for.
    pub domain: String,
    /// DNS resolver (`host:port`) used for the digest TXT lookup.
    #[arg(long, default_value = DNS_SERVER)]
    pub dns_server: String,
}

impl PaccCommand {
    pub fn execute(self, printer: &mut impl Printer, tls: &Tls) -> Result<()> {
        let url = DiscoveryPacc::url(&self.domain)?;
        let http = HttpSession::new(&url, tls.clone())?.stream;
        let dns = TcpStream::connect(&self.dns_server)?;
        let config = DiscoveryPaccClient::new(http, dns).discover(&self.domain)?;
        printer.out(config)
    }
}
