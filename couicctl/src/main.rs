mod cli;
mod config;
mod ripe;

use clap::{CommandFactory, Parser};

use client::{ApiVersion, CouicClient, LocalConfig, RemoteConfig};

use crate::cli::CommandError;
use crate::config::Mode;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> Result<(), CommandError> {
    let cli = cli::Cli::parse();

    if cli.markdown_help {
        clap_markdown::print_help_markdown::<cli::Cli>();
        std::process::exit(0);
    }

    let config = config::Config::load(&cli.config)?;

    // Create client based on mode
    let client = match config.mode {
        Mode::Local => {
            let lc = LocalConfig::from_file(config.socket.unwrap_or_default(), config.client_file);
            CouicClient::builder()
                .version(ApiVersion::V1)
                .build_local(lc)?
        }
        Mode::Remote => {
            let cc = RemoteConfig {
                token: config.token.unwrap_or_default(),
                host: config.host.unwrap_or_default(),
                port: config.port.unwrap_or_default(),
                tls: config.tls.unwrap_or_default(),
            };
            CouicClient::builder()
                .version(ApiVersion::V1)
                .build_remote(&cc)?
        }
    };

    if let Some(command) = cli.command {
        if let Err(e) = cli::execute(client, command) {
            eprintln!("Error executing command: {e}");
            std::process::exit(1);
        }
    } else {
        cli::Cli::command()
            .print_help()
            .map_err(|e| CommandError::from(config::ConfigError::from(e)))?;
        std::process::exit(0);
    }
    Ok(())
}
