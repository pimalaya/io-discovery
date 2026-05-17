use std::{fmt, string::String};

use anyhow::Result;
use clap::Args;
use pimalaya_cli::{
    printer::Printer,
    table::{Cell, ContentArrangement, Table, presets::UTF8_FULL},
};
use url::Url;

use crate::{
    rfc6186::{client::DiscoverySrvClientStd, types::SrvReport},
    shared::dns::DNS_SERVER,
};

/// RFC 6186 SRV-based mail service discovery.
///
/// Looks up `_imap._tcp.<domain>`, `_imaps._tcp.<domain>` and
/// `_submission._tcp.<domain>` over DNS-over-TCP and reports the
/// best record per service.
#[derive(Debug, Args)]
pub struct SrvCommand {
    /// Domain to look up SRV records for.
    pub domain: String,
    /// DNS resolver (`host:port`).
    #[arg(long, default_value = DNS_SERVER)]
    pub dns_server: String,
}

impl SrvCommand {
    pub fn execute(self, printer: &mut impl Printer) -> Result<()> {
        let resolver = Url::parse(&format!("tcp://{}", self.dns_server))?;
        let mut client = DiscoverySrvClientStd::new(resolver);
        let report = client.discover(&self.domain)?;
        printer.out(SrvReportOutput(report))
    }
}

#[derive(serde::Serialize)]
#[serde(transparent)]
struct SrvReportOutput(SrvReport);

impl fmt::Display for SrvReportOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                Cell::new("SERVICE"),
                Cell::new("HOST"),
                Cell::new("PORT"),
                Cell::new("PRIORITY"),
                Cell::new("WEIGHT"),
            ]);

        let r = &self.0;
        for (name, service) in [
            ("imap", &r.imap),
            ("imaps", &r.imaps),
            ("submission", &r.submission),
        ] {
            match service {
                Some(s) => table.add_row(vec![
                    Cell::new(name),
                    Cell::new(&s.host),
                    Cell::new(s.port),
                    Cell::new(s.priority),
                    Cell::new(s.weight),
                ]),
                None => table.add_row(vec![
                    Cell::new(name),
                    Cell::new("-"),
                    Cell::new("-"),
                    Cell::new("-"),
                    Cell::new("-"),
                ]),
            };
        }

        write!(f, "{table}")
    }
}
