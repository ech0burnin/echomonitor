//! Subcommand implementations (init / run / keygen).

use crate::config::NetworkConfig;
use crate::crypto;
use crate::transport;
use anyhow::{Context, Result};
use std::path::Path;
use std::sync::Arc;

pub fn init(dir: &str) -> Result<()> {
    let dir_path = Path::new(dir);
    std::fs::create_dir_all(dir_path)
        .with_context(|| format!("cannot create {dir}"))?;

    let keys = crypto::KeyPair::generate();
    std::fs::write(dir_path.join("node.key"), &keys.secret_hex)?;
    std::fs::write(dir_path.join("node.pub"), &keys.public_hex)?;

    let network_secret = crypto::random_hex(32);
    let cfg = NetworkConfig::bootstrap(network_secret, "node-1".to_string());
    cfg.save(&dir_path.join("network.toml"))?;

    std::fs::create_dir_all(dir_path.join("logs"))?;

    println!("initialized node in {dir}");
    println!("node public key: {}", keys.public_hex);
    println!("listen port: {}", cfg.net.listen_port);
    Ok(())
}

pub async fn run(dir: &str) -> Result<()> {
    let dir_path = Path::new(dir);
    let cfg = NetworkConfig::load(&dir_path.join("network.toml"))
        .with_context(|| format!("network.toml not found in {dir}; run `echomonitor init` first"))?;

    let _ = crate::logging::init(&dir_path.join("logs"));
    tracing::info!(
        revision = cfg.revision,
        content_hash = %cfg.content_hash,
        self_name = %cfg.self_name,
        "starting echomonitor"
    );

    let state = Arc::new(transport::NodeState {
        network_secret: cfg.auth.network_secret.as_str().into(),
        self_id: cfg.self_id,
        self_name: cfg.self_name.as_str().into(),
        revision: cfg.revision,
        content_hash: cfg.content_hash.as_str().into(),
    });

    transport::serve(state, cfg.net.listen_port).await
}

pub fn keygen() -> Result<()> {
    let kp = crypto::KeyPair::generate();
    println!("secret: {}", kp.secret_hex);
    println!("public: {}", kp.public_hex);
    Ok(())
}
