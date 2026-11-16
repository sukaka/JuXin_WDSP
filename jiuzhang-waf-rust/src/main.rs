use std::{net::SocketAddr, path::PathBuf, process::ExitCode, sync::Arc};

use clap::Parser;
use jiuzhang_native_waf::{
    app::{AppState, admin_router, proxy_router},
    config::Config,
};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "jiuzhang-native-waf",
    about = "Native HTTP application security gateway"
)]
struct Arguments {
    #[arg(short, long, default_value = "config.local.toml")]
    config: PathBuf,
    #[arg(long)]
    check_config: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let arguments = Arguments::parse();
    let config = match Config::load(&arguments.config) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };
    if arguments.check_config {
        println!("configuration is valid");
        return ExitCode::SUCCESS;
    }

    match run(config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "gateway stopped");
            ExitCode::FAILURE
        }
    }
}

async fn run(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    let listen = config.server.listen;
    let admin_listen = config.server.admin_listen;
    let upstream = config.server.upstream.clone();
    let state = Arc::new(AppState::new(config)?);
    let listener = TcpListener::bind(listen).await?;
    let admin_listener = TcpListener::bind(admin_listen).await?;

    tracing::info!(address = %listen, %upstream, "proxy listener started");
    tracing::info!(address = %admin_listen, "local administration listener started");

    let proxy = axum::serve(
        listener,
        proxy_router(state.clone()).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal());
    let admin =
        axum::serve(admin_listener, admin_router(state)).with_graceful_shutdown(shutdown_signal());
    tokio::try_join!(proxy, admin)?;
    Ok(())
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        tracing::error!(%error, "failed to listen for shutdown signal");
    }
}
