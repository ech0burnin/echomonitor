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
    // M2.6: OpenSSH-format public half of the same key — paste into the
    // peer user's authorized_keys for the SSH fallback tunnel (and M5.1 deploy).
    let openssh = crate::tunnel::openssh_public_line(&keys.public_hex)
        .context("cannot derive openssh public line")?;
    std::fs::write(dir_path.join("node.pub.openssh"), &openssh)?;

    let network_secret = crypto::random_hex(32);
    let cfg = NetworkConfig::bootstrap(network_secret, "node-1".to_string());
    cfg.save(&dir_path.join("network.toml"))?;

    std::fs::create_dir_all(dir_path.join("logs"))?;

    println!("initialized node in {dir}");
    println!("node public key: {}", keys.public_hex);
    println!("authorized_keys line: {openssh}");
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

    let state = Arc::new(transport::NodeState::with_persist(
        cfg.clone(),
        dir_path.join("network.toml"),
    ));

    // M2.6: SSH fallback transport — one TunnelManager from our node key,
    // enabled when node.key exists and parses. TOFU pins go next to it.
    let key_path = dir_path.join("node.key");
    if key_path.exists() {
        match std::fs::read_to_string(&key_path)
            .map_err(|e| anyhow::anyhow!("cannot read node.key: {e}"))
            .and_then(|seed| {
                crate::tunnel::TunnelManager::new(
                    seed.trim(),
                    dir_path.join("ssh_known_hosts"),
                )
            }) {
            Ok(tm) => {
                *state.tunnels.lock().await = Some(tm);
                tracing::info!("ssh tunnel manager ready (fallback transport)");
            }
            Err(e) => tracing::warn!(error = %e, "node.key unusable; ssh fallback disabled"),
        }
    }

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
        // M2.5: deterministic parent election after each round; act on a
        // change only once the desired parent held for ELECT_STABILITY rounds.
        let mut gate = crate::elector::StabilityGate::new();
        loop {
            tick.tick().await;
            let results = transport::gossip_round(&loop_state, &client).await;
            let ok = results.iter().filter(|(_, l)| l.is_some()).count();
            tracing::debug!(peers = results.len(), ok, "gossip round done");
            let now_ms = crate::checks::chrono_pseudo::Ts::now().unix_ms();
            let desired = {
                let g = loop_state.cfg.read().unwrap();
                let evidence = loop_state.evidence.read().unwrap();
                crate::elector::elect(&g.nodes, &g.edges, &evidence, now_ms)
            };
            let (effective, changed) = gate.observe(desired);
            *loop_state.parent.write().unwrap() = effective;
            if changed {
                match (effective, self_id) {
                    (Some(p), _) if p == self_id => {
                        tracing::info!(parent = p, "PARENT role acquired");
                    }
                    (Some(p), _) => {
                        tracing::info!(parent = p, "parent changed");
                    }
                    (None, _) => tracing::warn!("no parent eligible"),
                }
            }
        }
    });

    // M3.1 wiring: scheduled HTTP checks from [[checks]] config.
    // M3.3: EVERY node runs all configured checks locally (config is
    // replicated); finished records feed the gossip-shared probe table.
    if !cfg.checks.is_empty() {
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let specs = cfg.checks.clone();
        tracing::info!(count = specs.len(), "check engine starting");

        let sink_state = state.clone();
        let sink_node = cfg.self_id;
        let engine = crate::checks::Engine::new(10, 3).with_sink(std::sync::Arc::new(
            move |rec: &crate::checks::CheckRecord| {
                sink_state.record_own_probe(crate::checks::SiteProbe {
                    check_id: rec.check.clone(),
                    node_id: sink_node,
                    measured_at: rec.at,
                    outcome: rec.outcome.clone(),
                    status: rec.status,
                    ip: rec.ip.clone(),
                });
            },
        ));
        let engine = std::sync::Arc::new(engine);

        tokio::spawn(async move {
            engine.run(specs, shutdown_rx).await;
        });
        // keep the sender alive for the daemon's lifetime; dropping it would
        // make `changed()` return immediately and shut the engine down.
        std::mem::forget(shutdown_tx);
    }

    transport::serve(state, cfg.net.listen_port).await
}

pub fn keygen() -> Result<()> {
    let kp = crypto::KeyPair::generate();
    println!("secret: {}", kp.secret_hex);
    println!("public: {}", kp.public_hex);
    match crate::tunnel::openssh_public_line(&kp.public_hex) {
        Ok(line) => println!("authorized_keys line: {line}"),
        Err(e) => println!("authorized_keys line: (unavailable: {e})"),
    }
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
                probes: Vec::new(),
                seen: Vec::new(),
            },
            false,
        ),
    };

    println!("node: {} (id {})", cfg.self_name, cfg.self_id);
    println!("revision {}  hash {}", msg.revision, cfg.content_hash);
    // M2.6: show the same-key authorized_keys line for convenience
    let pub_path = dir_path.join("node.pub");
    if pub_path.exists() {
        if let Ok(hex) = std::fs::read_to_string(&pub_path) {
            if let Ok(line) = crate::tunnel::openssh_public_line(hex.trim()) {
                println!("authorized_keys line: {line}");
            }
        }
    }
    if live {
        println!("source: live daemon at {addr}");
    } else {
        println!("source: local network.toml (daemon not reachable at {addr})");
    }
    println!();
    println!("nodes:");
    for n in &msg.nodes {
        let naddr = n
            .address
            .clone()
            .or_else(|| n.ssh.as_ref().map(|s| format!("ssh {}:{}@{}", s.user, s.host, s.port)))
            .unwrap_or_else(|| "-".into());
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
    // M3.4: self observation (local /proc + statvfs, not part of gossip)
    match crate::selfstats::SelfStats::collect() {
        Ok(s) => {
            println!("self: (collected_at unix {})", s.collected_at);
            println!("  ram   used {:>5.1}%  ({:.1} GiB available / {:.1} GiB total)",
                s.mem.used_pct,
                s.mem.available_kb as f64 / 1024.0 / 1024.0,
                s.mem.total_kb as f64 / 1024.0 / 1024.0);
            println!("  load  {:.2} {:.2} {:.2}  (procs {}/{})",
                s.load.one, s.load.five, s.load.fifteen, s.load.running, s.load.total_procs);
            println!("  disk  used {:>5.1}%  ({:.1} GiB free / {:.1} GiB total)",
                s.disk.used_pct,
                s.disk.free_bytes as f64 / 1024.0 / 1024.0 / 1024.0,
                s.disk.total_bytes as f64 / 1024.0 / 1024.0 / 1024.0);
        }
        Err(e) => println!("self: (unavailable: {e})"),
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
    println!();
    // M3.3: consolidated site report from the gossip-shared probe table
    println!("sites:");
    if cfg.checks.is_empty() {
        println!("  (none configured)");
    } else {
        let mut probes: crate::sitereport::ProbeTable = crate::sitereport::ProbeTable::new();
        for p in &msg.probes {
            probes.insert((p.check_id.clone(), p.node_id), p.clone());
        }
        let lines = crate::sitereport::report_now(&cfg.checks, &msg.nodes, &probes);
        for l in lines {
            println!("{l}");
        }
        if !live {
            println!("  (daemon offline — no probe data can flow)");
        }
    }
    Ok(())
}
