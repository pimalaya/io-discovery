use std::{println, string::String};

use anyhow::Result;
use clap::Subcommand;
use pimalaya_cli::printer::Printer;

use crate::{autoconfig::client, shared::constants::DEFAULT_DNS_SERVER};

/// Autoconfig CLI.
///
/// Each subcommand corresponds to one Mozilla [Autoconfiguration]
/// step. `full` chains the ISP iteration with the DNS-based
/// fallbacks.
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
        #[arg(long, default_value = DEFAULT_DNS_SERVER)]
        server: String,
    },

    /// Look up the mailconf URL declared by a TXT record on the
    /// domain.
    DnsTxtMailconf {
        domain: String,
        #[arg(long, default_value = DEFAULT_DNS_SERVER)]
        server: String,
    },

    /// Build an autoconfig from the SRV records for `_imap._tcp`,
    /// `_imaps._tcp`, and `_submission._tcp` under the domain.
    DnsSrv {
        domain: String,
        #[arg(long, default_value = DEFAULT_DNS_SERVER)]
        server: String,
    },

    /// Run the whole discovery: ISP iteration, then DNS MX (re-run
    /// ISPs against the MX target), then TXT mailconf, then SRV.
    Full {
        local_part: String,
        domain: String,
        #[arg(long, default_value = DEFAULT_DNS_SERVER)]
        server: String,
    },
}

impl AutoconfigCommand {
    pub fn execute(self, printer: &mut impl Printer) -> Result<()> {
        match self {
            Self::Isp {
                local_part,
                domain,
                secure,
            } => printer.out(client::isp_main(&local_part, &domain, secure)?),

            Self::IspFallback { domain, secure } => {
                printer.out(client::isp_fallback(&domain, secure)?)
            }

            Self::Ispdb { domain, secure } => printer.out(client::ispdb(&domain, secure)?),

            Self::DnsMx { domain, server } => {
                for record in client::mx(&domain, &server)? {
                    println!("{} {}", record.rdata.preference, record.rdata.exchange);
                }
                Ok(())
            }

            Self::DnsTxtMailconf { domain, server } => {
                let url = client::mailconf(&domain, &server)?;
                println!("{url}");
                Ok(())
            }

            Self::DnsSrv { domain, server } => printer.out(client::srv(&domain, &server)?),

            Self::Full {
                local_part,
                domain,
                server,
            } => printer.out(client::discover(&local_part, &domain, &server)?),
        }
    }
}
