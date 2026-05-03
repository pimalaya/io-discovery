use std::string::String;

use anyhow::Result;
use clap::Args;
use pimalaya_cli::printer::Printer;

use crate::{pacc::client, shared::constants::DEFAULT_DNS_SERVER};

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
    #[arg(long, default_value = DEFAULT_DNS_SERVER)]
    pub server: String,
}

impl PaccCommand {
    pub fn execute(self, printer: &mut impl Printer) -> Result<()> {
        let config = client::discover(&self.domain, &self.server)?;
        printer.out(config)
    }
}
