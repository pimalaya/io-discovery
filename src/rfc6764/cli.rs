use std::{fmt, string::String};

use anyhow::Result;
use clap::Args;
use pimalaya_cli::{
    printer::Printer,
    table::{Cell, ContentArrangement, Table, presets::UTF8_FULL},
};
use url::Url;

use crate::{
    rfc6764::{client::DiscoveryRfc6764ClientStd, types::Rfc6764Report},
    shared::dns::DNS_SERVER,
};

/// RFC 6764 SRV-based CalDAV/CardDAV service discovery.
///
/// Looks up `_caldav._tcp.<domain>`, `_caldavs._tcp.<domain>`,
/// `_carddav._tcp.<domain>` and `_carddavs._tcp.<domain>` over
/// DNS-over-TCP and reports the best record per service.
#[derive(Debug, Args)]
pub struct Rfc6764Command {
    /// Domain to look up SRV records for.
    pub domain: String,
    /// DNS resolver (`host:port`).
    #[arg(long, default_value = DNS_SERVER)]
    pub dns_server: String,
}

impl Rfc6764Command {
    pub fn execute(self, printer: &mut impl Printer) -> Result<()> {
        let resolver = Url::parse(&format!("tcp://{}", self.dns_server))?;
        let mut client = DiscoveryRfc6764ClientStd::new(resolver);
        let report = client.discover(&self.domain)?;
        printer.out(Rfc6764ReportOutput(report))
    }
}

#[derive(serde::Serialize)]
#[serde(transparent)]
struct Rfc6764ReportOutput(Rfc6764Report);

impl fmt::Display for Rfc6764ReportOutput {
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
            ("caldav", &r.caldav),
            ("caldavs", &r.caldavs),
            ("carddav", &r.carddav),
            ("carddavs", &r.carddavs),
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
