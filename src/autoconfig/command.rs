use std::{
    io::{Read, Write},
    net::UdpSocket,
};

use anyhow::{Result, bail};
use clap::Subcommand;
use domain::rdata::Mx;
use pimalaya_toolbox::{stream::http::HttpSession, terminal::printer::Printer};

use crate::autoconfig::{dns_mx::*, isp::*};

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
    // IspFallback {
    //     domain: String,
    //     #[arg(short, long)]
    //     secure: bool,
    // },
    // Ispdb {
    //     domain: String,
    //     #[arg(short, long)]
    //     secure: bool,
    // },
    DnsMx {
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
                let url = DiscoveryIsp::new_url(local_part, domain, secure)?;
                let mut http = HttpSession::new(url.clone(), Default::default())?;

                let mut n = 0;
                let mut arg = [0; 1024];
                let mut isp = DiscoveryIsp::new(url);

                let autoconfig = loop {
                    match isp.resume(&arg[..n]) {
                        DiscoveryIspResult::Ok { autoconfig } => {
                            break autoconfig;
                        }
                        DiscoveryIspResult::WantsWrite(ref bytes) => {
                            http.stream.write(bytes)?;
                        }
                        DiscoveryIspResult::WantsRead => {
                            n = http.stream.read(&mut arg)?;
                        }
                        DiscoveryIspResult::Err { err } => {
                            bail!(err);
                        }
                    }
                };

                printer.out(autoconfig)
            }

            Self::DnsMx { domain, server } => {
                let server = match server.as_deref() {
                    Some(server) => server,
                    None => "8.8.8.8:53",
                };

                let dgram = UdpSocket::bind("0.0.0.0:0")?;
                dgram.connect(server)?;

                let mut n = 0;
                let mut arg = [0; 4096];
                let mut dns = DnsMx::new(&domain);

                let message = loop {
                    match dns.resume(&arg[..n]) {
                        DnsMxResult::Ok(message) => {
                            break message;
                        }
                        DnsMxResult::WantsWrite(msg) => {
                            dgram.send(msg.as_dgram_slice())?;
                        }
                        DnsMxResult::WantsRead => {
                            n = dgram.recv(&mut arg)?;
                        }
                        DnsMxResult::Err(err) => {
                            bail!(err);
                        }
                    }
                };

                for record in message.answer()?.limit_to::<Mx<_>>() {
                    let data = record?.into_data();
                    println!("- {}: {}", data.preference(), data.exchange());
                }

                Ok(())
            } // Self::IspFallback { domain, secure } => {
              //     let url = DiscoveryIspFallback::new_url(domain, secure)?;
              //     let mut http = HttpSession::new(url.clone(), Default::default())?;

              //     let mut arg = None;
              //     let mut isp = DiscoveryIspFallback::new(url);

              //     let autoconfig = loop {
              //         match isp.resume(arg.take()) {
              //             DiscoveryIspFallbackResult::Ok { autoconfig } => break autoconfig,
              //             DiscoveryIspFallbackResult::Io { input } => {
              //                 arg = Some(handle(&mut http.stream, input)?)
              //             }
              //             DiscoveryIspFallbackResult::Err { err } => bail!(err),
              //         }
              //     };

              //     printer.out(autoconfig)
              // }
              // Self::Ispdb { domain, secure } => {
              //     let url = DiscoveryIspdb::new_url(domain, secure)?;
              //     let mut http = HttpSession::new(url.clone(), Default::default())?;

              //     let mut arg = None;
              //     let mut isp = DiscoveryIspdb::new(url);

              //     let autoconfig = loop {
              //         match isp.resume(arg.take()) {
              //             DiscoveryIspdbResult::Ok { autoconfig } => break autoconfig,
              //             DiscoveryIspdbResult::Io { input } => {
              //                 arg = Some(handle(&mut http.stream, input)?)
              //             }
              //             DiscoveryIspdbResult::Err { err } => bail!(err),
              //         }
              //     };

              //     printer.out(autoconfig)
              // }
              // Self::DnsSrv { domain, server } => {
              //     let server = match server.as_deref() {
              //         Some(server) => server,
              //         None => "8.8.8.8:53",
              //     };

              //     let mut stream = TcpStream::connect(server).unwrap();

              //     let mut query = DnsTcpQuery::new(0x0001, &domain, SRV);
              //     let mut arg = None;

              //     let message = loop {
              //         match query.resume(arg.take()) {
              //             DnsTcpQueryResult::Ok { message } => break message,
              //             DnsTcpQueryResult::Io { input } => arg = Some(handle(&mut stream, input)?),
              //             DnsTcpQueryResult::Err { err } => bail!(err),
              //         }
              //     };

              //     let mut mx = Vec::with_capacity(message.answers.len());

              //     for rec in message.answers {
              //         if let DnsRecordData::Mx {
              //             preference,
              //             exchange,
              //         } = rec.data
              //         {
              //             mx.push((preference, exchange));
              //         };
              //     }

              //     if mx.is_empty() {
              //         bail!("No MX record found");
              //     }

              //     mx.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.to_string().cmp(&b.1.to_string())));

              //     for (pref, rec) in mx {
              //         println!(" - {pref}: {rec}");
              //     }

              //     Ok(())
              // }
        }
    }
}
