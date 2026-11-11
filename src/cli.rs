//! Subcommand implementations (init / run / keygen / status).

use crate::config::NetworkConfig;
use crate::crypto;
use crate::transport::{self, GossipMessage, NodeClient};
use crate::routing;
use anyhow::{Context, Result};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

pub fn init(dir: &str) -> Result<()> {
    let dir_path = Path::new(dir);
    std::fs::create_dir_all(dir_path).with_context(|| format!("cannot create {dir}"))?;

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

    let state = Arc::new(transport::NodeState::new(cfg.clone()));

    // gossip loop: every interval, push our snapshot to all reachable peers,
    // merge their replies, record RTT latencies
    let secret: Arc<str> = cfg.auth.network_secret.as_str().into();
    let self_id = cfg.self_id;
    let interval = cfg.net.gossip_interval_secs.max(1);
    let loop_state = state.clone();
    tokio::spawn(async move {
        let client = NodeClient::new(secret, self_id);
        let mut tick = tokio::time::interval(Duration::from_secs(interval));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let results = transport::gossip_round(&loop_state, &client).await;
            let ok = results.iter().filter(|(_, l)| l.is_some()).count();
            tracing::debug!(peers = results.len(), ok, "gossip round done");
        }
    });

    transport::serve(state, cfg.net.listen_port).await
}

pub fn keygen() -> Result<()> {
    let kp = crypto::KeyPair::generate();
    println!("secret: {}", kp.secret_hex);
    println!("public: {}", kp.public_hex);
    Ok(())
}

pub async fn status(dir: &str) -> Result<()> {
    let dir_path = Path::new(dir);
    let cfg = NetworkConfig::load(&dir_path.join("network.toml"))
        .with_context(|| format!("network.toml not found in {dir}"))?;

    let client = NodeClient::new(cfg.auth.network_secret.as_str().into(), cfg.self_id);
    let addr = format!("127.0.0.1:{}", cfg.net.listen_port);

    let (msg, live) = match client.state(&addr).await {
        Ok(m) => (m, true),
        Err(_) => (
            GossipMessage {
                from: cfg.self_id,
                revision: cfg.revision,
                nodes: cfg.nodes.clone(),
                edges: cfg.edges.clone(),
            },
            false,
        ),
    };

    println!("node: {} (id {})", cfg.self_name, cfg.self_id);
    println!("revision {}  hash {}", msg.revision, cfg.content_hash);
    if live {
        println!("source: live daemon at {addr}");
    } else {
        println!("source: local network.toml (daemon not reachable at {addr})");
    }
    println!();
    println!("nodes:");
    for n in &msg.nodes {
        let naddr = n.address.as_deref().unwrap_or("-");
        println!("  {}  {}  {}", n.id, n.name, naddr);
    }
    if msg.edges.is_empty() {
        println!("edges: (none yet)");
    } else {
        println!("edges:");
        for e in &msg.edges {
            match e.latency_ms {
                Some(ms) => println!("  {} - {}  {} ms", e.a, e.b, ms),
                None => println!("  {} - {}  ?", e.a, e.b),
            }
        }
    }
    println!();
    let table = routing::RoutingTable::build(cfg.self_id, &msg.nodes, &msg.edges);
    let routes: Vec<&u32> = table.all().keys().collect();
    if routes.is_empty() {
        println!("routes: (no peers reachable yet)");
    } else {
        println!("routes:");
        let mut targets: Vec<_> = table.all().keys().copied().collect();
        targets.sort();
        for t in targets {
            let r = table.route(t).unwrap();
            let path: Vec<String> = r.path.iter().map(|x| x.to_string()).collect();
            println!("  → {}  via {}  {} ms  [{}]", t, r.next_hop, r.cost_ms, path.join("→"));
        }
    }
    Ok(())
}
