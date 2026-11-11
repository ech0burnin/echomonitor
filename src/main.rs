use clap::{Parser, Subcommand};

mod cli;
mod config;
mod crypto;
mod logging;
mod routing;
mod transport;

#[derive(Parser)]
#[command(
    name = "echomonitor",
    version,
    about = "Self-hosted distributed mesh monitoring",
    long_about = "echomonitor — mesh-network monitoring system.\nOne binary acts as either the parent node (web UI + coordinator)\nor a child node. Run `echomonitor init <dir>` on the first host to bootstrap a network."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Bootstrap a node: keys, network config
    Init {
        /// Target directory (created if missing)
        dir: String,
    },
    /// Run the daemon (role is decided by the network config)
    Run {
        /// Directory containing network.toml
        dir: String,
    },
    /// Generate an ed25519 keypair and print it
    Keygen,
    /// Deploy a child node to a remote host via SSH (planned for M5)
    Deploy {
        /// Target host (IP or hostname)
        host: String,
        #[arg(long, default_value_t = 22)]
        port: u16,
        #[arg(long, default_value = "root")]
        user: String,
    },
    /// Show network status: nodes, edges, latencies
    Status {
        /// Directory containing network.toml
        #[arg(default_value = ".")]
        dir: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init { dir } => cli::init(&dir),
        Commands::Run { dir } => cli::run(&dir).await,
        Commands::Keygen => cli::keygen(),
        Commands::Deploy { .. } => {
            println!("deploy: not implemented yet (planned for M5)");
            Ok(())
        }
        Commands::Status { dir } => cli::status(&dir).await,
    }
}
