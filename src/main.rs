use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
#[cfg(feature = "autoconfig")]
use io_discovery::autoconfig::command::AutoconfigCommand;
#[cfg(feature = "pacc")]
use io_discovery::pacc::command::PaccCommand;
use pimalaya_cli::{
    clap::{
        args::{JsonFlag, LogFlags},
        commands::{CompletionCommand, ManualCommand},
    },
    error::ErrorReport,
    log::Logger,
    long_version,
    printer::{Printer, StdoutPrinter},
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
    #[cfg(feature = "autoconfig")]
    #[command(subcommand)]
    Autoconfig(AutoconfigCommand),
    #[cfg(feature = "pacc")]
    Pacc(PaccCommand),
    Completions(CompletionCommand),
    Manuals(ManualCommand),
}

impl DiscoveryCommand {
    pub fn execute(self, printer: &mut impl Printer) -> Result<()> {
        match self {
            #[cfg(feature = "autoconfig")]
            Self::Autoconfig(cmd) => cmd.execute(printer),
            #[cfg(feature = "pacc")]
            Self::Pacc(cmd) => cmd.execute(printer),
            Self::Completions(cmd) => cmd.execute(printer, DiscoveryCli::command()),
            Self::Manuals(cmd) => cmd.execute(printer, DiscoveryCli::command()),
        }
    }
}
