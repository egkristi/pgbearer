//! `pgbearer` server binary.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Identity-aware PostgreSQL gateway: OIDC bearer tokens in, least-privilege PostgreSQL roles out.
#[derive(Parser, Debug)]
#[command(name = "pgbearer", version, about)]
struct Cli {
    /// Path to the configuration file.
    #[arg(
        short,
        long,
        env = "PGBEARER_CONFIG",
        default_value = "/etc/pgbearer/pgbearer.yaml",
        global = true
    )]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the proxy (default).
    Run,
    /// Validate the configuration file and exit.
    CheckConfig,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command.unwrap_or(Command::Run) {
        Command::CheckConfig => match pgbearer_config::Config::load(&cli.config) {
            Ok(_) => {
                eprintln!("configuration {} is valid", cli.config.display());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("{e}");
                ExitCode::from(2)
            }
        },
        Command::Run => run(cli.config),
    }
}

fn run(config_path: PathBuf) -> ExitCode {
    let config = match pgbearer_config::Config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let format = match config.logging.format {
        pgbearer_config::LogFormat::Json => pgbearer_telemetry::LogFormat::Json,
        pgbearer_config::LogFormat::Pretty => pgbearer_telemetry::LogFormat::Pretty,
    };
    pgbearer_telemetry::init_logging(&config.logging.level, format);

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("cannot start async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(async move {
        let app = pgbearer::start(
            config,
            pgbearer::AppOptions {
                config_path: Some(config_path),
                ..Default::default()
            },
        )
        .await?;
        app.run_until_signal().await
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "pgbearer exited with an error");
            eprintln!("pgbearer: {e:#}");
            ExitCode::FAILURE
        }
    }
}
