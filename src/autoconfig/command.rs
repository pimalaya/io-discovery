use alloc::string::String;

use anyhow::{Result, bail};
use clap::Subcommand;
use io_socket::runtimes::std_stream::handle;
use pimalaya_toolbox::{stream::http::HttpSession, terminal::printer::Printer};

use crate::autoconfig::{isp::*, isp_fallback::*, ispdb::*};

/// IMAP CLI (requires the `imap` cargo feature).
///
/// This command gives you access to the IMAP CLI API, and allows you
/// to manage IMAP mailboxes, envelopes, flags, messages etc.
#[derive(Debug, Subcommand)]
#[command(rename_all = "kebab-case")]
pub enum AutoconfigCommand {
    Isp {
        local_part: String,
        domain: String,
        #[arg(short, long)]
        secure: bool,
    },
    IspFallback {
        domain: String,
        #[arg(short, long)]
        secure: bool,
    },
    Ispdb {
        domain: String,
        #[arg(short, long)]
        secure: bool,
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
                let url = DiscoveryIsp::new_url(local_part, domain, secure)?;
                let mut http = HttpSession::new(url.clone(), Default::default())?;

                let mut arg = None;
                let mut isp = DiscoveryIsp::new(url);

                let autoconfig = loop {
                    match isp.resume(arg.take()) {
                        DiscoveryIspResult::Ok { autoconfig } => break autoconfig,
                        DiscoveryIspResult::Io { input } => {
                            arg = Some(handle(&mut http.stream, input)?)
                        }
                        DiscoveryIspResult::Err { err } => bail!(err),
                    }
                };

                printer.out(autoconfig)
            }
            Self::IspFallback { domain, secure } => {
                let url = DiscoveryIspFallback::new_url(domain, secure)?;
                let mut http = HttpSession::new(url.clone(), Default::default())?;

                let mut arg = None;
                let mut isp = DiscoveryIspFallback::new(url);

                let autoconfig = loop {
                    match isp.resume(arg.take()) {
                        DiscoveryIspFallbackResult::Ok { autoconfig } => break autoconfig,
                        DiscoveryIspFallbackResult::Io { input } => {
                            arg = Some(handle(&mut http.stream, input)?)
                        }
                        DiscoveryIspFallbackResult::Err { err } => bail!(err),
                    }
                };

                printer.out(autoconfig)
            }
            Self::Ispdb { domain, secure } => {
                let url = DiscoveryIspdb::new_url(domain, secure)?;
                let mut http = HttpSession::new(url.clone(), Default::default())?;

                let mut arg = None;
                let mut isp = DiscoveryIspdb::new(url);

                let autoconfig = loop {
                    match isp.resume(arg.take()) {
                        DiscoveryIspdbResult::Ok { autoconfig } => break autoconfig,
                        DiscoveryIspdbResult::Io { input } => {
                            arg = Some(handle(&mut http.stream, input)?)
                        }
                        DiscoveryIspdbResult::Err { err } => bail!(err),
                    }
                };

                printer.out(autoconfig)
            }
        }
    }
}
