use std::{
    fmt,
    string::{String, ToString},
    vec::Vec,
};

use anyhow::Result;
use clap::{Args, Subcommand};
use log::trace;
use pimalaya_cli::{
    printer::Printer,
    table::{Cell, ContentArrangement, Table, presets::UTF8_FULL},
};
use pimalaya_stream::tls::Tls;
use url::Url;

use crate::{
    autoconfig::{
        client::DiscoveryAutoconfigClient,
        coroutines::{dns_mx::mx_parent_domain, isp::DiscoveryIsp},
        types::Autoconfig,
    },
    shared::defaults::DNS_SERVER,
};

/// Thunderbird Autoconfiguration discovery.
///
/// With no subcommand, runs the full discovery chain on
/// `<LOCAL_PART> <DOMAIN>`: ISP iteration, then DNS MX (re-run ISPs
/// against the MX target), then TXT mailconf, then SRV. Use a
/// subcommand to drive a single step.
///
/// Each subcommand corresponds to one Mozilla [Autoconfiguration]
/// step.
///
/// [Autoconfiguration]: https://wiki.mozilla.org/Thunderbird:Autoconfiguration
#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
#[command(arg_required_else_help = true)]
pub struct AutoconfigCommand {
    /// Local part of the email address (default-mode positional).
    local_part: String,
    /// Domain of the email address (default-mode positional).
    domain: String,
    /// DNS resolver (`host:port`).
    #[arg(long, default_value = DNS_SERVER)]
    server: String,

    #[command(subcommand)]
    command: Option<AutoconfigSubcommand>,
}

impl AutoconfigCommand {
    pub fn execute(self, printer: &mut impl Printer, tls: &Tls) -> Result<()> {
        if let Some(sub) = self.command {
            return sub.execute(printer, tls);
        }

        let resolver = parse_resolver(&self.server)?;
        let mut client = DiscoveryAutoconfigClient::new(resolver).with_tls(tls.clone());

        if let Some(ac) = try_all_isps(&mut client, &self.local_part, &self.domain) {
            return printer.out(ac);
        }

        let mx_domain = client
            .mx(&self.domain)?
            .first()
            .map(|r| r.rdata.exchange.to_string())
            .and_then(|target| mx_parent_domain(&target))
            .filter(|d| d != &self.domain);

        if let Some(mx_domain) = mx_domain {
            trace!("re-trying ISPs against MX parent {mx_domain}");
            if let Some(ac) = try_all_isps(&mut client, &self.local_part, &mx_domain) {
                return printer.out(ac);
            }
        }

        if let Ok(url) = client.mailconf(&self.domain) {
            trace!("fetching mailconf URL {url}");
            if let Some(ac) = try_isp(&mut client, url) {
                return printer.out(ac);
            }
        }

        let mut bests = [None, None, None];

        for (i, service) in ["imap", "imaps", "submission"].iter().enumerate() {
            let qname = format!("_{service}._tcp.{}", self.domain);
            bests[i] = client
                .srv_query(&qname)?
                .into_iter()
                .next()
                .map(|r| r.rdata);
        }

        let [imap, imaps, submission] = bests;
        printer.out(client.assemble_srv(&self.domain, imap, imaps, submission)?)
    }
}

#[derive(Debug, Subcommand)]
#[command(rename_all = "kebab-case")]
enum AutoconfigSubcommand {
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
    Mx {
        domain: String,
        #[arg(long, default_value = DNS_SERVER)]
        server: String,
    },

    /// Look up the mailconf URL declared by a TXT record on the
    /// domain.
    Mailconf {
        domain: String,
        #[arg(long, default_value = DNS_SERVER)]
        server: String,
    },

    /// Build an autoconfig from the SRV records for `_imap._tcp`,
    /// `_imaps._tcp`, and `_submission._tcp` under the domain.
    Srv {
        domain: String,
        #[arg(long, default_value = DNS_SERVER)]
        server: String,
    },
}

impl AutoconfigSubcommand {
    fn execute(self, printer: &mut impl Printer, tls: &Tls) -> Result<()> {
        match self {
            Self::Isp {
                local_part,
                domain,
                secure,
            } => {
                let url = DiscoveryIsp::main_url(&local_part, &domain, secure)?;
                printer.out(fetch_isp(url, tls)?)
            }

            Self::IspFallback { domain, secure } => {
                let url = DiscoveryIsp::fallback_url(&domain, secure)?;
                printer.out(fetch_isp(url, tls)?)
            }

            Self::Ispdb { domain, secure } => {
                let url = DiscoveryIsp::db_url(&domain, secure)?;
                printer.out(fetch_isp(url, tls)?)
            }

            Self::Mx { domain, server } => {
                let resolver = parse_resolver(&server)?;
                let records = DiscoveryAutoconfigClient::new(resolver)
                    .with_tls(tls.clone())
                    .mx(&domain)?
                    .into_iter()
                    .map(|record| DnsMxRecordOutput {
                        preference: record.rdata.preference.get(),
                        exchange: record.rdata.exchange.to_string(),
                    })
                    .collect();
                printer.out(DnsMxOutput { records })
            }

            Self::Mailconf { domain, server } => {
                let resolver = parse_resolver(&server)?;
                let url = DiscoveryAutoconfigClient::new(resolver)
                    .with_tls(tls.clone())
                    .mailconf(&domain)?;
                printer.out(MailconfOutput {
                    url: url.to_string(),
                })
            }

            Self::Srv { domain, server } => {
                let resolver = parse_resolver(&server)?;
                let mut client = DiscoveryAutoconfigClient::new(resolver).with_tls(tls.clone());
                let mut bests = [None, None, None];

                for (i, service) in ["imap", "imaps", "submission"].iter().enumerate() {
                    let qname = format!("_{service}._tcp.{domain}");
                    bests[i] = client
                        .srv_query(&qname)?
                        .into_iter()
                        .next()
                        .map(|r| r.rdata);
                }

                let [imap, imaps, submission] = bests;
                printer.out(client.assemble_srv(&domain, imap, imaps, submission)?)
            }
        }
    }
}

fn parse_resolver(server: &str) -> Result<Url> {
    Ok(Url::parse(&format!("tcp://{server}"))?)
}

fn fetch_isp(url: Url, tls: &Tls) -> Result<Autoconfig> {
    // The resolver URL is unused on the ISP path (HTTPS only) but
    // the client still needs one to construct.
    let resolver = parse_resolver(DNS_SERVER)?;
    let mut client = DiscoveryAutoconfigClient::new(resolver).with_tls(tls.clone());
    Ok(client.isp(url)?)
}

fn try_isp(client: &mut DiscoveryAutoconfigClient, url: Url) -> Option<Autoconfig> {
    trace!("trying autoconfig at {url}");

    match client.isp(url.clone()) {
        Ok(ac) => Some(ac),
        Err(err) => {
            trace!("autoconfig at {url} failed: {err}");
            None
        }
    }
}

fn try_all_isps(
    client: &mut DiscoveryAutoconfigClient,
    local_part: &str,
    domain: &str,
) -> Option<Autoconfig> {
    for url in DiscoveryIsp::all_urls(local_part, domain).ok()? {
        if let Some(ac) = try_isp(client, url) {
            return Some(ac);
        }
    }

    None
}

#[derive(serde::Serialize)]
struct DnsMxOutput {
    records: Vec<DnsMxRecordOutput>,
}

#[derive(serde::Serialize)]
struct DnsMxRecordOutput {
    preference: u16,
    exchange: String,
}

impl fmt::Display for DnsMxOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![Cell::new("PREFERENCE"), Cell::new("EXCHANGE")]);

        for record in &self.records {
            table.add_row(vec![
                Cell::new(record.preference),
                Cell::new(&record.exchange),
            ]);
        }

        write!(f, "{table}")
    }
}

#[derive(serde::Serialize)]
struct MailconfOutput {
    url: String,
}

impl fmt::Display for MailconfOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.url)
    }
}
