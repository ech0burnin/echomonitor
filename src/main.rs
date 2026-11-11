use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "echomonitor",
    version,
    about = "Self-hosted distributed mesh monitoring",
    long_about = "echomonitor — mesh-network monitoring system.\nOne binary acts as either the parent node (web UI + coordinator)\nor a child node. Run `echomonitor init` on the first host to bootstrap a network."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Bootstrap the parent node: keys, network config, admin user
    Init,
    /// Run the daemon (parent or child role is decided by the network)
    Run,
    /// Deploy a child node to a remote host via SSH
    Deploy {
        /// Target host (IP or hostname)
        host: String,
        /// SSH port on the target host
        #[arg(long, default_value_t = 22)]
        port: u16,
        /// SSH user on the target host
        #[arg(long, default_value = "root")]
        user: String,
    },
    /// Show network status summary
    Status,
    /// List known mesh nodes
    Nodes,
    /// List configured alert channels
    Channels,
    /// Self-check: config, ports, channels
    Doctor,
    /// Show recent log lines
    Logs {
        /// Follow the log stream
        #[arg(short, long)]
        follow: bool,
    },
    /// Generate a network keypair (used by init and deploy)
    Keygen,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init => {
            println!("not implemented yet (milestone 1)");
            std::process::exit(2);
        }
        Commands::Run => {
            println!("not implemented yet (milestone 1)");
            std::process::exit(2);
        }
        Commands::Deploy { .. } => {
            println!("not implemented yet (milestone 5)");
            std::process::exit(2);
        }
        Commands::Status => {
            println!("not implemented yet (milestone 2)");
            std::process::exit(2);
        }
        Commands::Nodes => {
            println!("not implemented yet (milestone 2)");
            std::process::exit(2);
        }
        Commands::Channels => {
            println!("not implemented yet (milestone 4)");
            std::process::exit(2);
        }
        Commands::Doctor => {
            println!("not implemented yet (milestone 8)");
            std::process::exit(2);
        }
        Commands::Logs { .. } => {
            println!("not implemented yet (milestone 1)");
            std::process::exit(2);
        }
        Commands::Keygen => {
            println!("not implemented yet (milestone 1)");
            std::process::exit(2);
        }
    }
}
