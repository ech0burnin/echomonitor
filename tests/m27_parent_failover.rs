//! M2.7: full-mesh failover drill — three nodes with REAL gossip loops and
//! REAL axum servers on loopback, the elected parent is killed mid-flight,
//! the survivors must re-elect and converge. This drives the exact
//! production code path: `transport::spawn_gossip_loop` (shared with
//! `cli::run`) plus the public HTTP API (`/api/health`, `/api/state`).
//!
//! Node isolation: each node gets its OWN single-worker tokio runtime —
//! the closest in-process equivalent of a separate process. `kill` shuts
//! the runtime down with a zero timeout, which drops ALL of its sockets
//! (the listener AND established keep-alive connections alike), exactly
//! like a crashed daemon. (Aborting an `axum::serve` task is NOT enough:
//! the accept loop dies but per-connection tasks survive and keep serving
//! gossip over pooled connections — the first version of this test died
//! on exactly that; see the failover drill in LOG.md.)
//!
//! Speed: production cadence (15s rounds, 45s dead threshold) would make
//! the drill wait ~75s in pure timeouts. The test mesh instead configures
//! `gossip_interval_secs = 2`; the dead threshold scales with the interval
//! (`elector::t_dead_for` = 3 missed rounds), so failover completes in
//! ~10s while running the same code with the same constants ratio.
//!
//! No sleep-driving: every wait is a poll with a deadline, and a timeout
//! fails the test with a full diagnostic dump (per-node health, view,
//! evidence ages).

use echomonitor::config::{EdgeEntry, NetworkConfig, NodeEntry};
use echomonitor::transport::{self, GossipMessage, NodeClient, NodeState};
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;

/// Test mesh cadence: 2s rounds -> 6s dead threshold (3 missed rounds).
const INTERVAL_SECS: u64 = 2;
/// Per-phase budget. Failover needs ~6s (stale evidence) + 2 gate rounds;
/// 30s leaves 3x margin for CI load without approaching the 90s target.
const PHASE_DEADLINE: Duration = Duration::from_secs(30);
const POLL_STEP: Duration = Duration::from_millis(250);

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// One live node: its own runtime carrying the axum server (pre-bound
/// loopback listener) and the gossip/election loop. `kill` shuts the
/// runtime down — every socket it owns is dropped, peers see instant
/// connection resets, evidence freezes: an honest crash.
struct Node {
    id: u32,
    addr: String,
    rt: Option<tokio::runtime::Runtime>,
}

impl Node {
    fn crashed(&self) -> bool {
        self.rt.is_none()
    }

    fn kill(&mut self) {
        if let Some(rt) = self.rt.take() {
            rt.shutdown_timeout(Duration::from_millis(0));
        }
    }
}

/// Same shared topology on every node (config is replicated in prod):
/// star around node-1, all addresses on loopback, fast gossip cadence.
fn mesh_config(secret: &str, self_id: u32, ports: &[u16; 3]) -> NetworkConfig {
    let mut cfg = NetworkConfig::bootstrap(secret.to_string(), format!("node-{self_id}"));
    cfg.self_id = self_id;
    cfg.net.gossip_interval_secs = INTERVAL_SECS;
    cfg.nodes = (1..=3u32)
        .map(|i| NodeEntry {
            id: i,
            name: format!("node-{i}"),
            public_key: None,
            address: Some(format!("127.0.0.1:{}", ports[(i - 1) as usize])),
            ssh: None,
        })
        .collect();
    // star around node-1 (same shape as the M2.5 manual drill); the 2-3
    // edge appears on its own once peers gossip (set_edge_latency)
    cfg.edges = vec![
        EdgeEntry { a: 1, b: 2, latency_ms: None },
        EdgeEntry { a: 1, b: 3, latency_ms: None },
    ];
    cfg.recompute_hash();
    cfg
}

/// Bind three loopback listeners first so the configs can carry the real
/// ports, then per node: a dedicated runtime running the real axum server
/// (on the pre-bound listener) and the real gossip/election loop. Returns
/// the nodes and an outside observer client.
async fn spawn_mesh(secret: &str) -> std::io::Result<(Vec<Node>, NodeClient)> {
    let mut ports = [0u16; 3];
    let mut listeners: Vec<TcpListener> = Vec::with_capacity(3);
    for p in &mut ports {
        let l = TcpListener::bind("127.0.0.1:0").await?;
        *p = l.local_addr()?.port();
        listeners.push(l);
    }

    let mut nodes = Vec::with_capacity(3);
    for (idx, listener) in listeners.into_iter().enumerate() {
        let id = idx as u32 + 1;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()?;
        let state = Arc::new(NodeState::new(mesh_config(secret, id, &ports)));
        let srv_state = state.clone();
        rt.spawn(async move {
            axum::serve(listener, transport::router(srv_state))
                .await
                .expect("node server");
        });
        // spawn_gossip_loop calls tokio::spawn internally: run it from
        // inside the node's runtime so its tasks live (and die) there
        let loop_state = state.clone();
        rt.spawn(async move {
            transport::spawn_gossip_loop(loop_state);
        });
        nodes.push(Node {
            id,
            addr: format!("127.0.0.1:{}", ports[idx]),
            rt: Some(rt),
        });
    }
    let obs = NodeClient::new(secret.into(), 99);
    Ok((nodes, obs))
}

/// Poll `check` until it holds or the phase deadline expires; on timeout
/// fail with `diag()` (async diagnostic dump) attached.
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
            "timed out waiting for: {what} (deadline {:?}, elapsed {:?})\n{}",
            PHASE_DEADLINE,
            t0.elapsed(),
            diag().await
        );
        tokio::time::sleep(POLL_STEP).await;
    }
}

/// Per-node snapshot for timeout messages: task liveness, /api/health,
/// /api/state (revision, node ids, edge pairs, evidence ages in seconds).
async fn diagnostics(nodes: &[Node], obs: &NodeClient) -> String {
    let now = unix_ms_now();
    let mut out = String::from("diagnostics:\n");
    for n in nodes {
        let task = if n.crashed() { "CRASHED" } else { "running" };
        match obs.health(&n.addr).await {
            Ok(h) => out += &format!("  node {} [{task}] health: {h}\n", n.id),
            Err(e) => out += &format!("  node {} [{task}] health: unreachable ({e})\n", n.id),
        }
        match obs.state(&n.addr).await {
            Ok(view) => {
                let ids: Vec<u32> = view.nodes.iter().map(|n| n.id).collect();
                let edges: Vec<(u32, u32)> =
                    view.edges.iter().map(|e| (e.a.min(e.b), e.a.max(e.b))).collect();
                let seen: Vec<String> = view
                    .seen
                    .iter()
                    .map(|s| format!("{}: {}s ago", s.id, (now.saturating_sub(s.at_ms)) / 1000))
                    .collect();
                out += &format!(
                    "    view: revision {} nodes {ids:?} edges {edges:?} seen {seen:?}\n",
                    view.revision
                );
            }
            Err(e) => out += &format!("    view: unreachable ({e})\n"),
        }
    }
    out
}

async fn parent_of(obs: &NodeClient, n: &Node) -> Option<u64> {
    let h = obs.health(&n.addr).await.ok()?;
    h["parent"]["id"].as_u64()
}

/// Node/edge identity of a view, latency-insensitive (admin level).
fn view_identity(v: &GossipMessage) -> (Vec<u32>, Vec<(u32, u32)>, u64) {
    let mut ids: Vec<u32> = v.nodes.iter().map(|n| n.id).collect();
    ids.sort_unstable();
    let mut edges: Vec<(u32, u32)> =
        v.edges.iter().map(|e| (e.a.min(e.b), e.a.max(e.b))).collect();
    edges.sort_unstable();
    (ids, edges, v.revision)
}

#[tokio::test]
async fn three_nodes_survive_parent_death_and_re_elect() {
    let secret = "m27-failover-secret";
    let (mut nodes, obs) = spawn_mesh(secret).await.expect("spawn mesh");
    let node1_addr = nodes[0].addr.clone();
    let node2_addr = nodes[1].addr.clone();

    // --- phase 1: the mesh converges; star hub node-1 (two alive
    // neighbors) is elected parent everywhere, including by itself
    poll_until(
        "all three nodes report parent = node-1",
        || async {
            let mut ok = true;
            for n in &nodes {
                if parent_of(&obs, n).await != Some(1) {
                    ok = false;
                }
            }
            ok
        },
        || diagnostics(&nodes, &obs),
    )
    .await;

    // gossip tables agree: same node set on every node, every node sees
    // fresh evidence for all three ids (full mesh dialed from addresses)
    poll_until(
        "converged views: same nodes everywhere, all ids evidenced",
        || async {
            let t_dead = echomonitor::elector::t_dead_for(INTERVAL_SECS);
            let mut good = 0;
            for n in &nodes {
                if let Ok(v) = obs.state(&n.addr).await {
                    let (ids, _, _) = view_identity(&v);
                    let now = unix_ms_now();
                    if ids == [1, 2, 3]
                        && v.seen.len() == 3
                        && v.seen.iter().all(|s| now.saturating_sub(s.at_ms) < t_dead)
                    {
                        good += 1;
                    }
                }
            }
            good == 3
        },
        || diagnostics(&nodes, &obs),
    )
    .await;

    // --- phase 2: kill the parent (runtime shutdown = every socket
    // dropped, established keep-alive connections included)
    nodes[0].kill();
    poll_until(
        "killed parent is really down (connection refused)",
        || async { obs.health(&node1_addr).await.is_err() },
        || diagnostics(&nodes, &obs),
    )
    .await;

    // --- phase 3: survivors re-elect. Alive set {2,3} < 3 -> the
    // two-neighbor rule is waived -> lowest alive id (node-2) wins,
    // after the evidence goes stale (t_dead) and the stability gate
    // holds it for 2 rounds. /api/health must reflect the new parent.
    poll_until(
        "both survivors report parent = node-2",
        || async {
            parent_of(&obs, &nodes[1]).await == Some(2)
                && parent_of(&obs, &nodes[2]).await == Some(2)
        },
        || diagnostics(&nodes, &obs),
    )
    .await;

    // --- phase 4: survivors share a consistent view: identical admin
    // content (nodes/edges/revision), the dead node still listed
    // (removal is an admin action, not automatic), and the new parent's
    // health points at its real address
    let v2 = obs.state(&nodes[1].addr).await.unwrap();
    let v3 = obs.state(&nodes[2].addr).await.unwrap();
    let (ids2, edges2, rev2) = view_identity(&v2);
    let (ids3, edges3, rev3) = view_identity(&v3);
    assert_eq!(
        (ids2.as_slice(), edges2.as_slice(), rev2),
        (ids3.as_slice(), edges3.as_slice(), rev3),
        "survivors must hold the same view after failover"
    );
    assert_eq!(ids2, vec![1, 2, 3], "dead node stays in the topology");
    // the 2-3 edge was discovered live (full-mesh dialing), all three
    // pair edges must be present on both survivors by now
    assert_eq!(edges2, vec![(1, 2), (1, 3), (2, 3)]);

    let h2 = obs.health(&nodes[1].addr).await.unwrap();
    let h3 = obs.health(&nodes[2].addr).await.unwrap();
    assert_eq!(h2["parent"]["id"].as_u64(), Some(2));
    assert_eq!(h3["parent"]["id"].as_u64(), Some(2));
    assert_eq!(h2["parent"]["addr"].as_str(), Some(node2_addr.as_str()));
    assert_eq!(h3["parent"]["addr"].as_str(), Some(node2_addr.as_str()));

    // survivors keep running; the dead node stays dead
    assert!(!nodes[1].crashed() && !nodes[2].crashed());
    assert!(nodes[0].crashed());

    // teardown: shut the survivors down so no runtime outlives the test
    nodes[1].kill();
    nodes[2].kill();
}
