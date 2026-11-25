#![forbid(unsafe_code)]

use std::process::ExitCode;

use clap::Parser;

use aegis_llm_gateway::config::{Cli, Command};
use aegis_llm_gateway::license::issue_license;
use aegis_llm_gateway::proxy::run_server;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Some(Command::Keygen { tier, days, secret }) => {
            println!("{}", issue_license(&tier, days, &secret));
            ExitCode::SUCCESS
        }
        Some(Command::Serve(args)) => match run_server(args).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("aegis-llm-gateway error: {err}");
                ExitCode::FAILURE
            }
        },
        None => match run_server(cli.serve).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("aegis-llm-gateway error: {err}");
                ExitCode::FAILURE
            }
        },
    }
}
