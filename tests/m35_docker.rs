//! M3.5: docker snapshots over a real two-node mesh — production code
//! path end to end. Every node runs the REAL gossip loop, the REAL axum
//! server and the REAL docker monitoring loop
//! (`docker::spawn_docker_loop_with_sock`, the test seam of the same
//! tick shape `cli::run` spawns via `spawn_docker_loop`); each node's
//! "dockerd" is a fake UnixListener daemon living INSIDE that node's
//! runtime, answering with the live d1337 header shape and a trimmed
//! slice of the real fixture body. The real /var/run/docker.sock is
//! never touched here (that is the live smoke's job, not the suite's).
//!
//! Honest-signal check: killing node-1's fake dockerd (abort + unlink,
//! i.e. the socket vanishes like an uninstalled daemon) must leave its
//! row in place on the peer, AGEING — the loop goes quiet on a missing
//! socket instead of overwriting the last good snapshot, and the report
//! renders the growing age exactly like the ssh matrix does.
//!
//! Harness ideas are m32's: one single-worker runtime per node, kill =
//! runtime shutdown_timeout(0), poll-until with deadlines + diagnostics,
//! 1s cadence everywhere.

use echoeye::config::{EdgeEntry, NetworkConfig, NodeEntry};
use echoeye::docker::{self, build_docker_report, DockerTable};
use echoeye::transport::{self, NodeClient, NodeState};
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::runtime::Runtime;

const INTERVAL_SECS: u64 = 1;
/// a row older than 3 ticks (1s each) counts as stale-in-place;
/// the live peer's row must stay well under the same bound.
const STALE_MS: u64 = INTERVAL_SECS * 1000 * 3;
const PHASE_DEADLINE: Duration = Duration::from_secs(30);
const POLL_STEP: Duration = Duration::from_millis(250);

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// node-1's fake dockerd payload: trimmed slice of the live d1337
/// fixture (docker 29.7.2, API 1.55, captured 2026-11-14) — running,
/// running+healthy, exited+unhealthy, so replication carries real
/// states and health normalization across the mesh.
const BODY_NODE1: &str = r#"[
 {"Id":"1453ab53b707112fdac5b110e5a125816f5d183cdb6a9e550a7f1e7aa6230b21","Names":["/searxng"],"State":"running","Status":"Up 22 minutes","Health":{"Status":"none","FailingStreak":0},"Created":1794328855},
 {"Id":"06e65d50894b5deaf8b4a9bf8ddafb421f90fd0d1f0157dfe1d7b4579180f758","Names":["/tuwunel"],"State":"running","Status":"Up 22 minutes (healthy)","Health":{"Status":"healthy","FailingStreak":0},"Created":1793490413},
 {"Id":"e5d8cb828b0c1d13cc32c1a9744288447e08978869993f130fd4ec9dc8a0ba9f","Names":["/samba"],"State":"exited","Status":"Exited (1) 2 minutes ago","Health":{"Status":"unhealthy","FailingStreak":3},"Created":1790116781}
]"#;

/// node-2's fake dockerd payload: plain running fleet, no healthchecks
/// (Health.Status "none" everywhere) — distinct names from node-1 prove
/// each row really came from THAT node's daemon.
const BODY_NODE2: &str = r#"[
 {"Id":"aef68c7693f19436849d84926969ffbd2d4f23d708de6729816500af28fabf61","Names":["/npm"],"State":"running","Status":"Up 3 hours","Health":{"Status":"none","FailingStreak":0},"Created":1793491437},
 {"Id":"ebee0dd678c789b6656b2c6c89c3ee28e539516f6c7858c4190878ef07c3c0f2","Names":["/nextcloud-app"],"State":"running","Status":"Up 5 days","Health":{"Status":"none","FailingStreak":0},"Created":1788114634},
 {"Id":"63772a7bacef45a5a50da631735c8d530a6da0741530a1088da406a7371370fb","Names":["/nextcloud-db"],"State":"running","Status":"Up 5 days","Health":{"Status":"none","FailingStreak":0},"Created":1788114629}
]"#;

struct Node {
    id: u32,
    addr: String,
    rt: Option<Runtime>,
    #[allow(dead_code)]
    dir: PathBuf,
    sock: PathBuf,
    dockerd: Option<tokio::task::JoinHandle<()>>,
}

impl Node {
    fn kill(&mut self) {
        if let Some(rt) = self.rt.take() {
            rt.shutdown_timeout(Duration::from_millis(0));
        }
    }

    /// Kill ONLY the fake docker daemon: abort the accept loop and
    /// unlink the socket file — the node itself, its gossip and its
    /// docker loop stay alive, so the missing-socket quiet path is what
    /// the loop now takes every tick.
    fn kill_dockerd(&mut self) {
        if let Some(h) = self.dockerd.take() {
            h.abort();
        }
        let _ = std::fs::remove_file(&self.sock);
    }
}

/// Shared replicated config: a 1-2 edge, fast cadence, docker interval
/// per scenario. The ssh matrix is not under test here (interval 0).
fn mesh_config(secret: &str, self_id: u32, gossip: &[u16; 2], docker_interval: u64) -> NetworkConfig {
    let mut cfg = NetworkConfig::bootstrap(secret.to_string(), format!("node-{self_id}"));
    cfg.self_id = self_id;
    cfg.net.gossip_interval_secs = INTERVAL_SECS;
    cfg.net.ssh_check_interval_secs = 0;
    cfg.net.docker_check_interval_secs = docker_interval;
    cfg.nodes = (1..=2u32)
        .map(|i| NodeEntry {
            id: i,
            name: format!("node-{i}"),
            public_key: None,
            address: Some(format!("127.0.0.1:{}", gossip[(i - 1) as usize])),
            ssh: None,
        })
        .collect();
    cfg.edges = vec![EdgeEntry { a: 1, b: 2, latency_ms: None }];
    cfg.recompute_hash();
    cfg
}

/// Fake dockerd over a real unix socket: drains the GET, answers with
/// the live d1337 header shape + fixture body, then drops the stream —
/// the HTTP/1.0 EOF framing the hand-rolled client expects.
async fn fake_dockerd(path: PathBuf, body: &'static str) {
    let l = match UnixListener::bind(&path) {
        Ok(l) => l,
        Err(_) => return,
    };
    while let Ok((mut sock, _)) = l.accept().await {
        let mut req = [0u8; 1024];
        let _ = sock.read(&mut req).await;
        let resp = format!(
            "HTTP/1.0 200 OK\r\nApi-Version: 1.55\r\nContent-Type: application/json\r\nServer: Docker/29.7.2 (linux)\r\n\r\n{body}"
        );
        let _ = sock.write_all(resp.as_bytes()).await;
    }
}

static DIR_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Fresh tempdir per node (parallel tests would collide otherwise).
fn sock_dir(tag: &str) -> PathBuf {
    let n = DIR_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let d = std::env::temp_dir().join(format!("em-m35c-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Bind both gossip listeners up front, then per node: a dedicated
/// runtime carrying the axum server, the real gossip loop, its fake
/// dockerd, and the real docker loop pointed at the INJECTED socket
/// path. Reports each spawn result ("did the loop start?") over a
/// channel so tests can assert the interval=0 branch without guessing.
async fn spawn_mesh(
    secret: &str,
    tag: &str,
    docker_interval: u64,
) -> std::io::Result<(Vec<Node>, std::sync::mpsc::Receiver<bool>)> {
    let mut gossip_ports = [0u16; 2];
    let mut listeners = Vec::with_capacity(2);
    for p in gossip_ports.iter_mut() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        *p = l.local_addr()?.port();
        listeners.push(l);
    }
    let (tx, rx) = std::sync::mpsc::channel::<bool>();

    let mut nodes = Vec::with_capacity(2);
    for (idx, listener) in listeners.into_iter().enumerate() {
        let id = idx as u32 + 1;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()?;
        let state = Arc::new(NodeState::new(mesh_config(secret, id, &gossip_ports, docker_interval)));

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

        // the node's "dockerd", bound inside the node's runtime so it
        // dies with it (dir/sock kept per node for the kill scenario)
        let dir = sock_dir(tag);
        let sock = dir.join(format!("dockerd-{id}.sock"));
        let body = if id == 1 { BODY_NODE1 } else { BODY_NODE2 };
        let dockerd = rt.spawn(fake_dockerd(sock.clone(), body));

        // docker monitoring loop against the injected socket path (the
        // M3.5-b test seam; production hardcodes DOCKER_SOCK)
        let dstate = state.clone();
        let dsock = sock.to_string_lossy().into_owned();
        let dtx = tx.clone();
        rt.spawn(async move {
            let handle = docker::spawn_docker_loop_with_sock(dstate, &dsock);
            let _ = dtx.send(handle.is_some());
        });

        nodes.push(Node {
            id,
            addr: format!("127.0.0.1:{}", gossip_ports[idx]),
            rt: Some(rt),
            dir,
            sock,
            dockerd: Some(dockerd),
        });
    }
    drop(tx);
    Ok((nodes, rx))
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

/// Dump every node's docker rows (from /api/state) with ages, for
/// timeout diagnostics.
async fn diagnostics(nodes: &[Node], obs: &NodeClient) -> String {
    let now = unix_ms_now();
    let mut out = String::from("diagnostics:\n");
    for n in nodes {
        let task = if n.rt.is_some() { "running" } else { "CRASHED" };
        match obs.state(&n.addr).await {
            Ok(v) => {
                out += &format!("  node {} [{task}] revision {} docker rows:\n", n.id, v.revision);
                for p in &v.docker {
                    out += &format!(
                        "    node-{}: {} containers error={:?} age={}ms\n",
                        p.node_id,
                        p.containers.len(),
                        p.error,
                        now.saturating_sub(p.measured_at.unix_ms())
                    );
                }
            }
            Err(e) => out += &format!("  node {} [{task}] unreachable ({e})\n", n.id),
        }
    }
    out
}

/// A replica's docker rows keyed by node id (from /api/state).
async fn table_of(obs: &NodeClient, n: &Node) -> Option<DockerTable> {
    let v = obs.state(&n.addr).await.ok()?;
    Some(v.docker.iter().map(|p| (p.node_id, p.clone())).collect())
}

fn row_matches(t: &DockerTable, id: u32, names: &[&str]) -> bool {
    match t.get(&id) {
        Some(p) => {
            p.error.is_none()
                && p.containers
                    .iter()
                    .map(|c| c.name.as_str())
                    .eq(names.iter().copied())
        }
        None => false,
    }
}

#[tokio::test]
async fn docker_rows_replicate_via_gossip_and_go_stale_in_place() {
    let secret = "m35-docker-mesh";
    let (mut nodes, spawn_rx) = match spawn_mesh(secret, "mesh", INTERVAL_SECS).await {
        Ok(v) => v,
        Err(e) => panic!("mesh spawn failed: {e}"),
    };
    let obs = NodeClient::new(secret.into(), 99);

    // sanity: with interval=1 both loops really spawned
    for _ in 0..2 {
        let spawned = spawn_rx.recv_timeout(Duration::from_secs(5)).expect("spawn result");
        assert!(spawned, "interval=1 must spawn the docker loop");
    }

    // --- phase 1: through gossip node-2 sees node-1's containers in
    // /api/state (and its own), parsed out of the fake daemon's answer
    poll_until(
        "node-2 holds both docker rows with the fixture containers",
        || async {
            match table_of(&obs, &nodes[1]).await {
                Some(t) => {
                    t.len() == 2
                        && row_matches(&t, 1, &["searxng", "tuwunel", "samba"])
                        && row_matches(&t, 2, &["npm", "nextcloud-app", "nextcloud-db"])
                }
                None => false,
            }
        },
        || diagnostics(&nodes, &obs),
    )
    .await;

    // deep content check on node-2's replica: states and healths really
    // crossed the mesh, not just bare names
    {
        let t = table_of(&obs, &nodes[1]).await.expect("node-2 alive");
        let p1 = &t[&1];
        assert!(p1.error.is_none(), "healthy daemon must not set error: {p1:?}");
        assert_eq!(p1.containers[0].state, "running");
        assert_eq!(p1.containers[0].health, None, "Health \"none\" normalizes to None");
        assert_eq!(p1.containers[1].health.as_deref(), Some("healthy"));
        assert_eq!(p1.containers[2].state, "exited");
        assert_eq!(p1.containers[2].health.as_deref(), Some("unhealthy"));

        // replication is symmetric: node-1 holds the full table too
        let t1 = table_of(&obs, &nodes[0]).await.expect("node-1 alive");
        assert_eq!(t1.len(), 2, "full table replicated on node-1 as well");

        // the report (what cli status prints) renders names, health and
        // the ! marker for non-running/unhealthy containers
        let v = obs.state(&nodes[1].addr).await.expect("node-2 alive");
        let lines = build_docker_report(&v.nodes, &t, unix_ms_now());
        assert!(
            lines.iter().any(|l| l.contains(
                "node-1: searxng: running, tuwunel: running (healthy), !samba: exited (unhealthy)"
            )),
            "got: {lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains(
                "node-2: npm: running, nextcloud-app: running, nextcloud-db: running"
            )),
            "got: {lines:?}"
        );
    }

    // --- phase 2: kill node-1's fake dockerd (socket file vanishes) —
    // its row must NOT disappear from node-2's view and must AGE while
    // node-2's own row keeps refreshing: the honest signal
    let t_kill = unix_ms_now();
    nodes[0].kill_dockerd();
    poll_until(
        "node-1's row survives on node-2 but goes stale in place",
        || async {
            let now = unix_ms_now();
            if now.saturating_sub(t_kill) < STALE_MS + 500 {
                return false; // let the stale boundary pass first
            }
            let Some(t) = table_of(&obs, &nodes[1]).await else { return false };
            let (Some(p1), Some(p2)) = (t.get(&1), t.get(&2)) else { return false };
            let age1 = now.saturating_sub(p1.measured_at.unix_ms());
            let age2 = now.saturating_sub(p2.measured_at.unix_ms());
            age1 > STALE_MS // no rewrite for 3+ ticks: stale in place
                && p1.containers.len() == 3 // last good snapshot kept, not blanked
                && p1.error.is_none() // and not replaced by an error row
                && age2 < STALE_MS // the live node keeps refreshing itself
        },
        || diagnostics(&nodes, &obs),
    )
    .await;

    // teardown
    nodes[0].kill();
    nodes[1].kill();
}

#[tokio::test]
async fn docker_daemon_errors_propagate_as_honest_error_rows() {
    let secret = "m35-docker-err";
    let (mut nodes, spawn_rx) = match spawn_mesh(secret, "err", INTERVAL_SECS).await {
        Ok(v) => v,
        Err(e) => panic!("mesh spawn failed: {e}"),
    };
    let obs = NodeClient::new(secret.into(), 99);

    for _ in 0..2 {
        let spawned = spawn_rx.recv_timeout(Duration::from_secs(5)).expect("spawn result");
        assert!(spawned, "interval=1 must spawn the docker loop");
    }

    // replace node-1's daemon with a DEAD one: accept loop aborted and
    // the socket file replaced by a plain regular file — the path still
    // exists (so the loop's missing-socket quiet path does NOT trigger)
    // but connecting fails with ECONNREFUSED, exactly like a dockerd
    // that crashed leaving its socket file behind.
    nodes[0].kill_dockerd();
    std::fs::write(&nodes[0].sock, b"dead dockerd placeholder").expect("plant fake socket file");

    // via gossip the peer sees an HONEST error row for node-1 — fresh,
    // not frozen — while node-2's own row stays healthy
    poll_until(
        "node-2 sees node-1's fresh error row via gossip",
        || async {
            let now = unix_ms_now();
            let Some(t) = table_of(&obs, &nodes[1]).await else { return false };
            let (Some(p1), Some(p2)) = (t.get(&1), t.get(&2)) else { return false };
            let age1 = now.saturating_sub(p1.measured_at.unix_ms());
            p1.error.as_deref().is_some_and(|e| e.contains("refused"))
                && p1.containers.is_empty()
                && age1 < 2500 // the loop keeps ticking: row is fresh
                && p2.error.is_none()
                && p2.containers.len() == 3
        },
        || diagnostics(&nodes, &obs),
    )
    .await;

    // the error row keeps REFRESHING (measured_at advances), proving the
    // loop stays alive and honest instead of freezing or going quiet
    let first = table_of(&obs, &nodes[1]).await.expect("node-2 alive")[&1].measured_at.unix_ms();
    tokio::time::sleep(Duration::from_millis(2300)).await;
    let second = table_of(&obs, &nodes[1]).await.expect("node-2 alive")[&1].measured_at.unix_ms();
    assert!(second > first, "error rows must keep refreshing: {first} -> {second}");

    // and the report renders the error line (truncated to the
    // snippet budget — the path eats it before "refused" fits),
    // not a silent gap
    {
        let v = obs.state(&nodes[1].addr).await.expect("node-2 alive");
        let t: DockerTable = v.docker.iter().map(|p| (p.node_id, p.clone())).collect();
        let lines = build_docker_report(&v.nodes, &t, unix_ms_now());
        assert!(
            lines.iter().any(|l| l.contains("node-1: error: docker socket")),
            "got: {lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("node-2: npm: running")),
            "got: {lines:?}"
        );
    }

    nodes[0].kill();
    nodes[1].kill();
}

#[tokio::test]
async fn docker_loop_disabled_by_interval_zero_keeps_state_empty() {
    let secret = "m35-docker-off";
    let (mut nodes, spawn_rx) = match spawn_mesh(secret, "off", 0).await {
        Ok(v) => v,
        Err(e) => panic!("mesh spawn failed: {e}"),
    };
    let obs = NodeClient::new(secret.into(), 99);

    // the spawn call itself must report "no loop" for interval=0
    for _ in 0..2 {
        let spawned = spawn_rx.recv_timeout(Duration::from_secs(5)).expect("spawn result");
        assert!(!spawned, "interval=0 must not spawn the docker loop");
    }

    // the fake daemons DO answer — so an empty state can only mean the
    // loop never ran, not that the sockets were dead
    let body = docker::fetch(nodes[0].sock.to_str().unwrap())
        .await
        .expect("fake dockerd answers");
    assert!(body.contains("searxng"));

    // give a wrongly-spawned loop time for 2+ ticks at the 1s cadence
    // before declaring victory
    tokio::time::sleep(Duration::from_millis(2600)).await;

    for n in &nodes {
        let v = obs.state(&n.addr).await.expect("node alive");
        assert!(
            v.docker.is_empty(),
            "interval=0 must leave the docker field empty, got {:?}",
            v.docker
        );
    }

    nodes[0].kill();
    nodes[1].kill();
}
