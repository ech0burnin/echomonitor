//! M3.2: directed SSH matrix over a real three-node mesh — production
//! code path end to end. Every node runs the REAL gossip loop, the REAL
//! axum server and the REAL ssh-matrix loop (`sshmatrix::
//! spawn_ssh_matrix_loop`, the same one `cli::run` spawns); each node's
//! "system sshd" is a fake banner-writing TcpListener living INSIDE that
//! node's runtime, so killing the node kills its sshd too — an honest
//! crash on both channels at once.
//!
//! Directionality check: node-1 observes (1→2) and (1→3) ONLY. After
//! node-3 dies, its rows must go [STALE] on the survivors while the
//! surviving pairs keep refreshing — the honest signal by design (a dead
//! `from` lets its rows age out instead of leaving a coordinator hole).
//!
//! Same harness ideas as m27 (own single-worker runtime per node, kill =
//! runtime shutdown_timeout(0) dropping every socket, poll-until with
//! deadlines and diagnostics) with a faster cadence: matrix interval 1s
//! -> stale after 3s (STALE_FACTOR=3).

use echoeye::config::{EdgeEntry, NetworkConfig, NodeEntry, SshDial};
use echoeye::sshmatrix::{build_ssh_report, SshMatrix};
use echoeye::transport::{self, NodeClient, NodeState};
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::io::AsyncWriteExt;

const INTERVAL_SECS: u64 = 1;
/// stale = STALE_FACTOR(3) x 1s = 3s; give it margin for CI jitter.
const STALE_MARGIN: Duration = Duration::from_secs(2);
const PHASE_DEADLINE: Duration = Duration::from_secs(30);
const POLL_STEP: Duration = Duration::from_millis(250);

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

struct Node {
    id: u32,
    addr: String,
    rt: Option<tokio::runtime::Runtime>,
}

impl Node {
    fn kill(&mut self) {
        if let Some(rt) = self.rt.take() {
            rt.shutdown_timeout(Duration::from_millis(0));
        }
    }
}

/// Shared replicated config: full triangle, every node has an ssh dial
/// pointing at its OWN fake sshd port, fast cadence everywhere.
fn mesh_config(secret: &str, self_id: u32, gossip: &[u16; 3], ssh: &[u16; 3]) -> NetworkConfig {
    let mut cfg = NetworkConfig::bootstrap(secret.to_string(), format!("node-{self_id}"));
    cfg.self_id = self_id;
    cfg.net.gossip_interval_secs = INTERVAL_SECS;
    cfg.net.ssh_check_interval_secs = INTERVAL_SECS;
    cfg.nodes = (1..=3u32)
        .map(|i| NodeEntry {
            id: i,
            name: format!("node-{i}"),
            public_key: None,
            address: Some(format!("127.0.0.1:{}", gossip[(i - 1) as usize])),
            ssh: Some(SshDial {
                host: "127.0.0.1".into(),
                port: ssh[(i - 1) as usize],
                user: "deploy".into(),
                forward_host: None,
                forward_port: None,
            }),
        })
        .collect();
    cfg.edges = vec![
        EdgeEntry { a: 1, b: 2, latency_ms: None },
        EdgeEntry { a: 1, b: 3, latency_ms: None },
    ];
    cfg.recompute_hash();
    cfg
}

/// A fake sshd that greets every client with its banner line and closes.
async fn fake_sshd(port: u16, banner: &'static str) {
    let l = match TcpListener::bind(("127.0.0.1", port)).await {
        Ok(l) => l,
        Err(_) => return,
    };
    loop {
        let Ok((mut sock, _)) = l.accept().await else { return };
        let _ = sock.write_all(banner.as_bytes()).await;
    }
}

/// Bind all listeners up front (3 gossip + 3 fake sshd), then per node:
/// a dedicated runtime carrying the axum server, the real gossip loop,
/// the real ssh-matrix loop, and its fake sshd. Everything a node owns
/// dies with its runtime.
async fn spawn_mesh(secret: &str) -> std::io::Result<Vec<Node>> {
    let mut gossip_ports = [0u16; 3];
    let mut listeners = Vec::with_capacity(3);
    for p in gossip_ports.iter_mut() {
        let l = TcpListener::bind("127.0.0.1:0").await?;
        *p = l.local_addr()?.port();
        listeners.push(l);
    }
    let mut ssh_ports = [0u16; 3];
    for p in ssh_ports.iter_mut() {
        let l = TcpListener::bind("127.0.0.1:0").await?;
        *p = l.local_addr()?.port();
    }

    let mut nodes = Vec::with_capacity(3);
    for (idx, listener) in listeners.into_iter().enumerate() {
        let id = idx as u32 + 1;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()?;
        let state = Arc::new(NodeState::new(mesh_config(secret, id, &gossip_ports, &ssh_ports)));

        let srv_state = state.clone();
        rt.spawn(async move {
            axum::serve(listener, transport::router(srv_state))
                .await
                .expect("node server");
        });
        // gossip + election loop (production path)
        let loop_state = state.clone();
        rt.spawn(async move {
            transport::spawn_gossip_loop(loop_state);
        });
        // ssh matrix loop (production path)
        let matrix_state = state.clone();
        rt.spawn(async move {
            echoeye::sshmatrix::spawn_ssh_matrix_loop(matrix_state);
        });
        // the node's "system sshd"
        let banner: &'static str = Box::leak(format!("SSH-2.0-fake-{id}\r\n").into_boxed_str());
        rt.spawn(fake_sshd(ssh_ports[idx], banner));

        nodes.push(Node {
            id,
            addr: format!("127.0.0.1:{}", gossip_ports[idx]),
            rt: Some(rt),
        });
    }
    Ok(nodes)
}

async fn poll_until<F, Fut, D, DFut>(what: &str, mut check: F, mut diag: D)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
    D: FnMut() -> DFut,
    DFut: Future<Output = String>,
{
    let t0 = Instant::now();
    loop {
        if check().await {
            return;
        }
        assert!(
            t0.elapsed() < PHASE_DEADLINE,
            "timed out waiting for: {what} (elapsed {:?})\n{}",
            t0.elapsed(),
            diag().await
        );
        tokio::time::sleep(POLL_STEP).await;
    }
}

/// Dump every node's ssh rows (from /api/state) with ages, for timeouts.
async fn diagnostics(nodes: &[Node], obs: &NodeClient) -> String {
    let now = unix_ms_now();
    let mut out = String::from("diagnostics:\n");
    for n in nodes {
        let task = if n.rt.is_some() { "running" } else { "CRASHED" };
        match obs.state(&n.addr).await {
            Ok(v) => {
                out += &format!("  node {} [{task}] revision {} rows:\n", n.id, v.revision);
                for p in &v.ssh {
                    out += &format!(
                        "    {}->{} {:?} banner={:?} age={}ms\n",
                        p.from,
                        p.to,
                        p.outcome,
                        p.banner,
                        now.saturating_sub(p.measured_at.unix_ms())
                    );
                }
            }
            Err(e) => out += &format!("  node {} [{task}] unreachable ({e})\n", n.id),
        }
    }
    out
}

/// The ssh rows of a node's /api/state, keyed by (from, to).
async fn rows_of(obs: &NodeClient, n: &Node) -> Option<SshMatrix> {
    let v = obs.state(&n.addr).await.ok()?;
    Some(v.ssh.iter().map(|p| ((p.from, p.to), p.clone())).collect())
}

#[tokio::test]
async fn three_node_matrix_full_and_survives_node_death() {
    let secret = "m32-matrix-secret";
    let (mut nodes, obs) = match spawn_mesh(secret).await {
        Ok(n) => {
            let obs = NodeClient::new(secret.into(), 99);
            (n, obs)
        }
        Err(e) => panic!("mesh spawn failed: {e}"),
    };

    // --- phase 1: full directed matrix, 6 pairs, seen from a NON-parent
    // node (gossip replicates the table everywhere, parent renders only)
    poll_until(
        "node-2 holds all 6 directed pairs, all fresh Ok with banners",
        || async {
            match rows_of(&obs, &nodes[1]).await {
                Some(m) => m.len() == 6 && all_fresh_ok(&m) && banners_distinct(&m),
                None => false,
            }
        },
        || diagnostics(&nodes, &obs),
    )
    .await;

    // directionality: node-1's OWN table only ever holds rows FROM node-1
    // (written by its own loop); rows from others arrive via gossip, so
    // the snapshot carries the full mesh — but the rows node-1 measures
    // are exactly {(1,2),(1,3)}. Verify by banner: node-1's rows show the
    // TARGET's banner (fake-2 / fake-3), never its own.
    {
        let m = rows_of(&obs, &nodes[0]).await.expect("node-1 alive");
        assert_eq!(m.len(), 6, "full table replicated on node-1 too");
        for ((from, _to), p) in &m {
            if *from == 1 {
                assert!(p.banner.as_deref().unwrap_or("").starts_with("SSH-2.0-fake-"), "got {:?}", p.banner);
            }
        }
    }

    // --- phase 2: kill node-3 (its runtime takes its axum server AND its
    // fake sshd down — an honest crash)
    let t_kill = unix_ms_now();
    nodes[2].kill();
    poll_until(
        "killed node-3 is really down (connection refused)",
        || async { obs.health(&nodes[2].addr).await.is_err() },
        || diagnostics(&nodes, &obs),
    )
    .await;

    // --- phase 3: survivors' tables keep node-3's rows but they STALE
    // (age > stale_after = 3s), while surviving pairs stay fresh. Wait
    // until the stale boundary is behind us, then assert both directions
    // of the split in ONE check.
    let stale_after_ms = INTERVAL_SECS * 1000 * echoeye::sitereport::STALE_FACTOR;
    poll_until(
        "node-3 rows stale, surviving rows fresh, on node-2",
        || async {
            let now = unix_ms_now();
            if now.saturating_sub(t_kill) < stale_after_ms + STALE_MARGIN.as_millis() as u64 {
                return false;
            }
            let Some(m) = rows_of(&obs, &nodes[1]).await else { return false };
            let age = |k: &(u32, u32)| now.saturating_sub(m.get(k).expect("row present").measured_at.unix_ms());
            // dead observer: rows frozen at/before the kill moment
            age(&(3, 1)) > stale_after_ms && age(&(3, 2)) > stale_after_ms
                // survivors keep refreshing each other well past the kill
                && age(&(1, 2)) < stale_after_ms && age(&(2, 1)) < stale_after_ms
                // node-1 keeps probing the dead sshd — its row refreshes
                // (with a FAIL outcome now), proving the loop is alive
                && m.get(&(1, 3)).is_some_and(|p| {
                    p.measured_at.unix_ms() > t_kill
                        && matches!(p.outcome, echoeye::checks::CheckOutcome::Fail { .. })
                })
        },
        || diagnostics(&nodes, &obs),
    )
    .await;

    // --- phase 4: the report renders the split: [STALE] on the dead
    // node's rows, fresh OK lines for the surviving pair, derived purely
    // from a survivor's /api/state (what a parent would render in M4.5)
    {
        let v = obs.state(&nodes[1].addr).await.expect("survivor state");
        let matrix: SshMatrix = v.ssh.iter().map(|p| ((p.from, p.to), p.clone())).collect();
        let lines = build_ssh_report(&v.nodes, &matrix, unix_ms_now(), INTERVAL_SECS);
        let dead_rows: Vec<&String> = lines
            .iter()
            .filter(|l| l.starts_with("  node-3 ->") && l.contains("STALE"))
            .collect();
        assert_eq!(dead_rows.len(), 2, "both of node-3's rows must render [STALE]: {lines:?}");
        assert!(
            lines.iter().any(|l| l.starts_with("  node-1 -> node-2")
                && l.contains("OK") && l.contains("SSH-2.0-fake-2")),
            "node-1 -> node-2 must render OK with node-2's banner: {lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.starts_with("  node-2 -> node-1") && l.contains("OK") && l.contains("SSH-2.0-fake-1")),
            "node-2 -> node-1 must render OK with node-1's banner: {lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.starts_with("  node-1 -> node-3") && l.contains("FAIL")),
            "dead sshd must show as FAIL (refreshed by the live loop): {lines:?}"
        );
    }

    // teardown
    nodes[0].kill();
    nodes[1].kill();
}

fn all_fresh_ok(m: &SshMatrix) -> bool {
    let now = unix_ms_now();
    m.values().all(|p| {
        matches!(p.outcome, echoeye::checks::CheckOutcome::Ok { .. })
            && now.saturating_sub(p.measured_at.unix_ms())
                < INTERVAL_SECS * 1000 * echoeye::sitereport::STALE_FACTOR
    })
}

/// Each row's banner is the TARGET's fake banner — the matrix really
/// measures node-to-node, six distinct directed observations.
fn banners_distinct(m: &SshMatrix) -> bool {
    let expected: HashMap<(u32, u32), &str> = [
        ((1, 2), "SSH-2.0-fake-2"),
        ((1, 3), "SSH-2.0-fake-3"),
        ((2, 1), "SSH-2.0-fake-1"),
        ((2, 3), "SSH-2.0-fake-3"),
        ((3, 1), "SSH-2.0-fake-1"),
        ((3, 2), "SSH-2.0-fake-2"),
    ]
    .into_iter()
    .collect();
    expected.iter().all(|(k, want)| {
        m.get(k).is_some_and(|p| p.banner.as_deref() == Some(*want))
    })
}
