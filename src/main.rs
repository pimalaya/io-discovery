use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
#[cfg(feature = "autoconfig")]
use io_discovery::autoconfig::cli::AutoconfigCommand;
#[cfg(feature = "pacc")]
use io_discovery::pacc::cli::PaccCommand;
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
use pimalaya_stream::tls::{Rustls, RustlsCrypto, Tls, TlsProvider};

fn main() {
    let cli = DiscoverCli::parse();

    Logger::init(&cli.log);
    let mut printer = StdoutPrinter::new(&cli.json);
    let tls = cli.tls.into();

    let result = cli.command.execute(&mut printer, &tls);
    ErrorReport::eval(&mut printer, result)
}

#[derive(Parser, Debug)]
#[command(name = env!("CARGO_PKG_NAME"))]
#[command(about = "CLI to discover PIM-related services")]
#[command(author, version, long_version = long_version!())]
#[command(propagate_version = true, infer_subcommands = true)]
struct DiscoverCli {
    #[command(subcommand)]
    pub command: DiscoverCommand,
    #[command(flatten)]
    pub tls: TlsFlags,
    #[command(flatten)]
    pub log: LogFlags,
    #[command(flatten)]
    pub json: JsonFlag,
}

#[derive(Subcommand, Debug)]
enum DiscoverCommand {
    #[cfg(feature = "autoconfig")]
    Autoconfig(AutoconfigCommand),
    #[cfg(feature = "pacc")]
    Pacc(PaccCommand),
    Completions(CompletionCommand),
    Manuals(ManualCommand),
}

impl DiscoverCommand {
    pub fn execute(self, printer: &mut impl Printer, tls: &Tls) -> Result<()> {
        match self {
            #[cfg(feature = "autoconfig")]
            Self::Autoconfig(cmd) => cmd.execute(printer, tls),
            #[cfg(feature = "pacc")]
            Self::Pacc(cmd) => cmd.execute(printer, tls),
            Self::Completions(cmd) => cmd.execute(printer, DiscoverCli::command()),
            Self::Manuals(cmd) => cmd.execute(printer, DiscoverCli::command()),
        }
    }
}

#[derive(Args, Debug)]
struct TlsFlags {
    /// TLS provider implementation used for HTTPS connections.
    #[arg(long, global = true)]
    #[arg(value_enum, value_name = "PROVIDER")]
    pub tls: Option<TlsProviderArg>,
    /// Additional TLS root certificate (PEM file).
    #[arg(long, global = true, value_name = "PATH")]
    pub tls_cert: Option<PathBuf>,
    /// Rustls crypto provider.
    #[arg(long, global = true)]
    #[arg(value_enum, value_name = "PROVIDER")]
    pub rustls_crypto: Option<RustlsCryptoArg>,
}

impl From<TlsFlags> for Tls {
    fn from(flags: TlsFlags) -> Self {
        Self {
            provider: flags.tls.map(Into::into),
            rustls: Rustls {
                crypto: flags.rustls_crypto.map(Into::into),
            },
            cert: flags.tls_cert,
        }
    }
}

#[derive(Clone, Debug, ValueEnum)]
enum TlsProviderArg {
    Rustls,
    NativeTls,
}

impl From<TlsProviderArg> for TlsProvider {
    fn from(arg: TlsProviderArg) -> Self {
        match arg {
            TlsProviderArg::Rustls => Self::Rustls,
            TlsProviderArg::NativeTls => Self::NativeTls,
        }
    }
}

#[derive(Clone, Debug, ValueEnum)]
enum RustlsCryptoArg {
    Aws,
    Ring,
}

impl From<RustlsCryptoArg> for RustlsCrypto {
    fn from(arg: RustlsCryptoArg) -> Self {
        match arg {
            RustlsCryptoArg::Aws => Self::Aws,
            RustlsCryptoArg::Ring => Self::Ring,
        }
    }
}
