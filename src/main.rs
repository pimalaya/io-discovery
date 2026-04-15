use anyhow::{Result, bail};
use clap::{CommandFactory, Parser, Subcommand};
use io_discovery::isp::*;
use io_socket::runtimes::std_stream::handle;
use pimalaya_toolbox::{
    long_version,
    stream::http::HttpSession,
    terminal::{
        clap::{
            args::{JsonFlag, LogFlags},
            commands::{CompletionCommand, ManualCommand},
        },
        error::ErrorReport,
        log::Logger,
        printer::{Printer, StdoutPrinter},
    },
};

fn main() {
    let cli = DiscoveryCli::parse();

    Logger::init(&cli.log);
    let mut printer = StdoutPrinter::new(&cli.json);

    let result = cli.command.execute(&mut printer);
    ErrorReport::eval(&mut printer, result)
}

#[derive(Parser, Debug)]
#[command(name = env!("CARGO_PKG_NAME"))]
#[command(author, version, about)]
#[command(long_version = long_version!())]
#[command(propagate_version = true, infer_subcommands = true)]
struct DiscoveryCli {
    #[command(subcommand)]
    pub command: DiscoveryCommand,

    #[command(flatten)]
    pub json: JsonFlag,
    #[command(flatten)]
    pub log: LogFlags,
}

#[derive(Subcommand, Debug)]
enum DiscoveryCommand {
    Isp {
        local_part: String,
        domain: String,
        #[arg(short, long)]
        secure: bool,
    },

    Completions(CompletionCommand),
    Manuals(ManualCommand),
}

impl DiscoveryCommand {
    pub fn execute(self, printer: &mut impl Printer) -> Result<()> {
        match self {
            Self::Isp {
                local_part,
                domain,
                secure,
            } => {
                let url = DiscoveryIspMain::generate_url(local_part, domain, secure)?;
                let mut http = HttpSession::new(url.clone(), Default::default())?;

                let mut arg = None;
                let mut isp = DiscoveryIspMain::new(url);

                let xml = loop {
                    match isp.resume(arg.take()) {
                        DiscoveryIspMainResult::Ok { xml } => break xml,
                        DiscoveryIspMainResult::Io { input } => {
                            arg = Some(handle(&mut http.stream, input)?)
                        }
                        DiscoveryIspMainResult::Err { err } => bail!(err),
                    }
                };

                printer.out(xml)
            }

            Self::Completions(cmd) => cmd.execute(printer, DiscoveryCli::command()),
            Self::Manuals(cmd) => cmd.execute(printer, DiscoveryCli::command()),
        }
    }
}
