use clap::{Parser, Subcommand};
use tracing::info;

use tameshi_watch::config::Config;
use tameshi_watch::error::WatchError;
use tameshi_watch::state::{FsPollStateStore, PollStateStore};

#[derive(Parser)]
#[command(name = "tameshi-watch")]
#[command(about = "Continuous compliance ingestion daemon for tameshi attestation")]
struct Cli {
    /// Path to config file.
    #[arg(short, long)]
    config: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the daemon (poll continuously).
    Daemon,
    /// Poll all sources once and exit.
    PollOnce,
    /// Show current poll state.
    Status,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let config = Config::load(cli.config.as_deref()).map_err(|e| {
        WatchError::Config(format!("failed to load config: {e}"))
    })?;

    init_tracing(&config.log_format);

    match cli.command {
        Command::Daemon => run_daemon(&config).await?,
        Command::PollOnce => run_poll_once(&config).await?,
        Command::Status => run_status(&config)?,
    }

    Ok(())
}

fn init_tracing(log_format: &str) {
    let subscriber = tracing_subscriber::fmt().with_env_filter(
        tracing_subscriber::EnvFilter::from_default_env()
            .add_directive("tameshi_watch=info".parse().unwrap()),
    );

    if log_format == "json" {
        subscriber.json().init();
    } else {
        subscriber.init();
    }
}

async fn run_daemon(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    info!(
        addr = %config.listen_addr,
        port = config.port,
        "starting tameshi-watch daemon"
    );

    let _store = FsPollStateStore::new(config.state_dir.clone())?;

    // In a full implementation, this would:
    // 1. Spawn health server on config.listen_addr:config.port
    // 2. Spawn poll tasks for each enabled source
    // 3. Wire pipeline with configured actions
    // 4. Run until shutdown signal

    info!("daemon started (placeholder — no sources configured yet)");

    // For now, just wait for ctrl+c
    tokio::signal::ctrl_c().await?;
    info!("shutdown signal received");

    Ok(())
}

async fn run_poll_once(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    info!("polling all sources once");

    let _store = FsPollStateStore::new(config.state_dir.clone())?;

    // Placeholder: would instantiate pollers and run one cycle
    info!("poll-once completed (placeholder)");
    Ok(())
}

fn run_status(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let store = FsPollStateStore::new(config.state_dir.clone())?;

    let sources = ["nvd", "osv", "profile_watcher"];
    for source in &sources {
        let state = store.load(source)?;
        println!(
            "{source}: last_poll={}, known_ids={}, total_ingested={}",
            state
                .last_poll
                .map_or_else(|| "never".to_string(), |t| t.to_rfc3339()),
            state.known_ids.len(),
            state.total_ingested,
        );
    }

    Ok(())
}
