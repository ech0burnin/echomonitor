//! Inter-node HTTP transport with HMAC-token auth and topology gossip.
//! Every request carries `X-Em-Token` (current 30s-period HMAC) and `X-Em-Node` (self id).
//! Middleware rejects anything whose token doesn't verify against the shared network secret.
//!
//! M2.2: gossip is a real exchange — the peer replies with its own snapshot,
//! both sides merge. Latency (RTT) is measured per round and stored on edges.
//!
//! M2.4: conflict-resolve by revision + admin hash. Admin content = revision +
//! nodes + edges (latency-free, order-independent). Forks at the same revision
//! converge deterministically to the larger admin hash. Merges persist to disk.

// Items wired for later milestones (M2.5 elections read VerifiedNode) are exercised by tests only.
#![allow(dead_code)]

use crate::config::{admin_hash, EdgeEntry, NetworkConfig, NodeEntry};
use crate::crypto;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Instant;

// ---------- shared node state ----------

pub struct NodeState {
    /// Working view of the network config; mutated by gossip merges and
    /// latency measurements.
    pub cfg: Arc<RwLock<NetworkConfig>>,
    /// Where merged configs are persisted (network.toml); None in tests.
    pub persist_path: Option<std::path::PathBuf>,
}

impl NodeState {
    pub fn new(cfg: NetworkConfig) -> Self {
        Self {
            cfg: Arc::new(RwLock::new(cfg)),
            persist_path: None,
        }
    }

    pub fn with_persist(cfg: NetworkConfig, path: std::path::PathBuf) -> Self {
        Self {
            cfg: Arc::new(RwLock::new(cfg)),
            persist_path: Some(path),
        }
    }

    /// Atomically persist the current config view (tmp file + rename).
    /// Best-effort: persistence failure is logged, never fatal.
    pub fn persist(&self) {
        if let Some(path) = &self.persist_path {
            let snapshot = self.cfg.read().unwrap().clone();
            let tmp = path.with_extension("toml.tmp");
            match snapshot.save(&tmp) {
                Ok(()) => {
                    if let Err(e) = std::fs::rename(&tmp, path) {
                        tracing::warn!(error = %e, "config persist rename failed");
                    }
                }
                Err(e) => tracing::warn!(error = %e, "config persist save failed"),
            }
        }
    }

    /// Point-in-time copy of our topology for gossip/state replies.
    pub fn snapshot_msg(&self) -> GossipMessage {
        let g = self.cfg.read().unwrap();
        GossipMessage {
            from: g.self_id,
            revision: g.revision,
            nodes: g.nodes.clone(),
            edges: g.edges.clone(),
        }
    }
}

// ---------- gossip message ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipMessage {
    pub from: u32,
    pub revision: u64,
    pub nodes: Vec<NodeEntry>,
    pub edges: Vec<EdgeEntry>,
}

// ---------- merge logic ----------

fn normalized(e: &EdgeEntry) -> EdgeEntry {
    EdgeEntry {
        a: e.a.min(e.b),
        b: e.a.max(e.b),
        latency_ms: e.latency_ms,
    }
}

fn same_edge(a: &EdgeEntry, b: &EdgeEntry) -> bool {
    let (alo, ahi) = (a.a.min(a.b), a.a.max(a.b));
    let (blo, bhi) = (b.a.min(b.b), b.a.max(b.b));
    alo == blo && ahi == bhi
}

fn ensure_self_present(g: &mut NetworkConfig) {
    if !g.nodes.iter().any(|n| n.id == g.self_id) {
        g.nodes.push(NodeEntry {
            id: g.self_id,
            name: g.self_name.clone(),
            public_key: None,
            address: None,
        });
    }
}

/// Adopt the sender's admin content wholesale, preserving locally measured
/// latencies for edges that survive the adoption.
fn adopt(g: &mut NetworkConfig, msg: &GossipMessage) {
    let local_latencies: std::collections::HashMap<(u32, u32), u64> = g
        .edges
        .iter()
        .filter_map(|e| {
            e.latency_ms
                .map(|ms| ((e.a.min(e.b), e.a.max(e.b)), ms))
        })
        .collect();
    g.nodes = msg.nodes.clone();
    g.edges = msg
        .edges
        .iter()
        .map(|e| {
            let mut e = normalized(e);
            if e.latency_ms.is_none() {
                e.latency_ms = local_latencies.get(&(e.a, e.b)).copied();
            }
            e
        })
        .collect();
    g.revision = msg.revision;
    ensure_self_present(g);
    g.recompute_hash();
}

/// Deterministic field merge for conflicting entries of the same node id:
/// missing values fill in, conflicting values resolve to the lexicographic max.
/// Fully commutative: merge(a, b) == merge(b, a), so both sides of an exchange
/// compute the identical result and converge in a single round.
fn pick_opt(a: Option<String>, b: Option<String>) -> Option<String> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

fn merge_node_entry(local: &NodeEntry, remote: &NodeEntry) -> NodeEntry {
    NodeEntry {
        id: local.id,
        name: local.name.clone().max(remote.name.clone()),
        public_key: pick_opt(local.public_key.clone(), remote.public_key.clone()),
        address: pick_opt(local.address.clone(), remote.address.clone()),
    }
}

/// Union merge at equal revisions (covers both "same content, exchange
/// latencies" and "forked content, reconcile"). Commutative: nodes union by
/// id with deterministic entry merge, edges union by normalized pair, edge
/// latency keeps the local measurement and fills from the peer if missing.
fn union_merge(g: &mut NetworkConfig, msg: &GossipMessage) {
    for n in &msg.nodes {
        match g.nodes.iter_mut().find(|x| x.id == n.id) {
            Some(existing) => *existing = merge_node_entry(existing, n),
            None => g.nodes.push(n.clone()),
        }
    }
    for e in &msg.edges {
        let e = normalized(e);
        match g.edges.iter_mut().find(|x| same_edge(x, &e)) {
            Some(local) => {
                if local.latency_ms.is_none() {
                    local.latency_ms = e.latency_ms;
                }
            }
            None => g.edges.push(e),
        }
    }
    g.recompute_hash();
}

/// Merge a received gossip message into the local config view.
/// - newer revision: adopt wholesale (preserve local latencies)
/// - same revision: commutative union merge — identical result on both sides,
///   so forks converge deterministically in a single exchange round
/// - older revision: ignore (we are ahead); sender learns from our reply
pub fn merge_into(cfg: &RwLock<NetworkConfig>, msg: &GossipMessage) {
    let mut g = cfg.write().unwrap();
    if msg.revision > g.revision {
        adopt(&mut g, msg);
    } else if msg.revision == g.revision {
        let local_admin = admin_hash(g.revision, &g.nodes, &g.edges);
        let msg_admin = admin_hash(msg.revision, &msg.nodes, &msg.edges);
        if local_admin != msg_admin {
            tracing::warn!(
                local = %local_admin,
                remote = %msg_admin,
                "config fork at same revision: union-merging"
            );
        }
        union_merge(&mut g, msg);
    }
    // older revision: ignore
}

/// Record measured RTT to a peer. Latency churn does not bump the revision:
/// revision tracks admin-level topology changes only.
pub fn set_edge_latency(cfg: &RwLock<NetworkConfig>, x: u32, y: u32, ms: u64) {
    let (lo, hi) = (x.min(y), x.max(y));
    let mut g = cfg.write().unwrap();
    match g.edges.iter_mut().find(|e| e.a == lo && e.b == hi) {
        Some(e) => e.latency_ms = Some(ms),
        None => g.edges.push(EdgeEntry {
            a: lo,
            b: hi,
            latency_ms: Some(ms),
        }),
    }
    g.recompute_hash();
}

/// One gossip pass: push our snapshot to every reachable peer, merge replies,
/// measure RTT, persist. Returns (peer_id, Some(latency_ms)) per peer, None on failure.
pub async fn gossip_round(state: &NodeState, client: &NodeClient) -> Vec<(u32, Option<u64>)> {
    let (self_id, targets) = {
        let g = state.cfg.read().unwrap();
        let targets: Vec<(u32, String)> = g
            .nodes
            .iter()
            .filter(|n| n.id != g.self_id)
            .filter_map(|n| n.address.as_ref().map(|a| (n.id, a.clone())))
            .collect();
        (g.self_id, targets)
    };

    let mut out = Vec::new();
    for (peer_id, addr) in targets {
        let msg = state.snapshot_msg();
        let t0 = Instant::now();
        match client.gossip(&addr, &msg).await {
            Ok(reply) => {
                let ms = t0.elapsed().as_millis() as u64;
                merge_into(&state.cfg, &reply);
                set_edge_latency(&state.cfg, self_id, peer_id, ms);
                tracing::debug!(peer = peer_id, latency_ms = ms, "gossip ok");
                out.push((peer_id, Some(ms)));
            }
            Err(e) => {
                tracing::warn!(peer = peer_id, error = %e, "gossip failed");
                out.push((peer_id, None));
            }
        }
    }
    state.persist();
    out
}

// ---------- auth middleware ----------

#[derive(Clone, Debug)]
pub struct VerifiedNode(pub String);

pub async fn auth_middleware(
    State(state): State<Arc<NodeState>>,
    mut req: Request,
    next: Next,
) -> Response {
    let token = req.headers().get("X-Em-Token").and_then(|v| v.to_str().ok());
    let node = req.headers().get("X-Em-Node").and_then(|v| v.to_str().ok());

    let (token, node) = match (token, node) {
        (Some(t), Some(n)) => (t, n.to_string()),
        _ => return (StatusCode::UNAUTHORIZED, "missing X-Em-Token / X-Em-Node").into_response(),
    };

    if !crypto::verify_token(state.cfg.read().unwrap().auth.network_secret.as_str(), token) {
        return (StatusCode::UNAUTHORIZED, "invalid or expired token").into_response();
    }

    req.extensions_mut().insert(VerifiedNode(node));
    next.run(req).await
}

// ---------- handlers ----------

async fn health(State(state): State<Arc<NodeState>>) -> Json<serde_json::Value> {
    let g = state.cfg.read().unwrap();
    Json(json!({
        "status": "ok",
        "node": g.self_name,
        "revision": g.revision,
    }))
}

/// Inbound topology gossip: merge the peer's view, persist, reply with our
/// own snapshot (push-pull in a single round trip).
async fn gossip(
    State(state): State<Arc<NodeState>>,
    Json(msg): Json<GossipMessage>,
) -> Json<GossipMessage> {
    merge_into(&state.cfg, &msg);
    state.persist();
    Json(state.snapshot_msg())
}

/// Current topology view (auth'd; used by `echomonitor status`).
async fn state_handler(State(state): State<Arc<NodeState>>) -> Json<GossipMessage> {
    Json(state.snapshot_msg())
}

// ---------- client ----------

pub struct NodeClient {
    pub http: reqwest::Client,
    pub network_secret: Arc<str>,
    pub self_id: u32,
}

impl NodeClient {
    pub fn new(network_secret: Arc<str>, self_id: u32) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .expect("reqwest client"),
            network_secret,
            self_id,
        }
    }

    fn auth_headers(&self) -> reqwest::header::HeaderMap {
        let mut h = reqwest::header::HeaderMap::new();
        h.insert(
            "X-Em-Token",
            crypto::token_now(&self.network_secret)
                .parse()
                .expect("hex token is valid header value"),
        );
        h.insert(
            "X-Em-Node",
            self.self_id.to_string().parse().expect("numeric id"),
        );
        h
    }

    pub async fn health(&self, addr: &str) -> anyhow::Result<serde_json::Value> {
        let url = format!("http://{addr}/api/health");
        let resp = self.http.get(&url).headers(self.auth_headers()).send().await?;
        Ok(resp.json().await?)
    }

    pub async fn gossip(&self, addr: &str, msg: &GossipMessage) -> anyhow::Result<GossipMessage> {
        let url = format!("http://{addr}/api/gossip");
        let resp = self
            .http
            .post(&url)
            .headers(self.auth_headers())
            .json(msg)
            .send()
            .await?;
        let resp = resp.error_for_status()?;
        Ok(resp.json().await?)
    }

    pub async fn state(&self, addr: &str) -> anyhow::Result<GossipMessage> {
        let url = format!("http://{addr}/api/state");
        let resp = self.http.get(&url).headers(self.auth_headers()).send().await?;
        let resp = resp.error_for_status()?;
        Ok(resp.json().await?)
    }
}

// ---------- router ----------

pub fn router(state: Arc<NodeState>) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route(
            "/api/gossip",
            post(gossip).route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            )),
        )
        .route(
            "/api/state",
            get(state_handler).route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                auth_middleware,
            )),
        )
        .with_state(state)
}

pub async fn serve(state: Arc<NodeState>, port: u16) -> anyhow::Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "listening");
    axum::serve(listener, router(state)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- merge unit tests ----------

    #[test]
    fn merge_adopts_newer_revision() {
        let local = NetworkConfig::bootstrap("s".into(), "n1".into());
        let shared = RwLock::new(local);
        let msg = GossipMessage {
            from: 2,
            revision: 5,
            nodes: vec![
                NodeEntry { id: 1, name: "n1".into(), public_key: None, address: None },
                NodeEntry { id: 2, name: "n2".into(), public_key: None, address: Some("10.0.0.2:8687".into()) },
            ],
            edges: vec![EdgeEntry { a: 2, b: 1, latency_ms: Some(7) }],
        };
        merge_into(&shared, &msg);
        let g = shared.read().unwrap();
        assert_eq!(g.revision, 5);
        assert_eq!(g.nodes.len(), 2);
        // edge normalized to (min, max)
        assert!(g.edges.iter().any(|e| e.a == 1 && e.b == 2 && e.latency_ms == Some(7)));
    }

    #[test]
    fn merge_ignores_older_revision() {
        let mut local = NetworkConfig::bootstrap("s".into(), "n1".into());
        local.revision = 9;
        local.recompute_hash();
        let shared = RwLock::new(local);
        let msg = GossipMessage {
            from: 2,
            revision: 2,
            nodes: vec![NodeEntry { id: 9, name: "x".into(), public_key: None, address: None }],
            edges: vec![],
        };
        merge_into(&shared, &msg);
        let g = shared.read().unwrap();
        assert_eq!(g.revision, 9);
        assert!(!g.nodes.iter().any(|n| n.id == 9));
    }

    #[test]
    fn adopt_preserves_local_latencies() {
        let mut local = NetworkConfig::bootstrap("s".into(), "n1".into());
        local.edges.push(EdgeEntry { a: 1, b: 2, latency_ms: Some(42) });
        local.recompute_hash();
        let shared = RwLock::new(local);
        // newer revision from a peer whose edge has NO latency yet
        let msg = GossipMessage {
            from: 2,
            revision: 7,
            nodes: vec![
                NodeEntry { id: 1, name: "n1".into(), public_key: None, address: None },
                NodeEntry { id: 2, name: "n2".into(), public_key: None, address: None },
            ],
            edges: vec![EdgeEntry { a: 1, b: 2, latency_ms: None }],
        };
        merge_into(&shared, &msg);
        let g = shared.read().unwrap();
        assert_eq!(g.revision, 7);
        assert!(
            g.edges.iter().any(|e| e.a == 1 && e.b == 2 && e.latency_ms == Some(42)),
            "locally measured latency must survive adoption"
        );
    }

    #[test]
    fn same_admin_content_exchanges_latencies() {
        // identical admin content on both sides, only the peer knows the latency
        let mut local = NetworkConfig::bootstrap("s".into(), "n1".into());
        local.nodes.push(NodeEntry { id: 2, name: "n2".into(), public_key: None, address: None });
        local.edges.push(EdgeEntry { a: 1, b: 2, latency_ms: None });
        local.recompute_hash();
        let shared = RwLock::new(local);
        let msg = GossipMessage {
            from: 2,
            revision: shared.read().unwrap().revision,
            nodes: vec![
                NodeEntry { id: 1, name: "n1".into(), public_key: None, address: None },
                NodeEntry { id: 2, name: "n2".into(), public_key: None, address: None },
            ],
            edges: vec![EdgeEntry { a: 2, b: 1, latency_ms: Some(12) }],
        };
        merge_into(&shared, &msg);
        let g = shared.read().unwrap();
        assert!(
            g.edges.iter().any(|e| e.a == 1 && e.b == 2 && e.latency_ms == Some(12)),
            "latency from the peer must fill our missing value"
        );
    }

    #[test]
    fn same_revision_fork_converges_deterministically() {
        // two nodes bootstrapped independently: same revision, different node sets
        let mut a = NetworkConfig::bootstrap("s".into(), "n1".into());
        a.revision = 5;
        let mut b = NetworkConfig::bootstrap("s".into(), "n2".into());
        b.self_id = 2;
        b.nodes[0].id = 2;
        b.revision = 5;
        a.recompute_hash();
        b.recompute_hash();

        let shared_a = RwLock::new(a);
        let shared_b = RwLock::new(b);

        // each receives the other's snapshot (like a real gossip exchange)
        let msg_b_to_a = shared_b.read().unwrap().clone();
        let msg_a_to_b = shared_a.read().unwrap().clone();
        merge_into(
            &shared_a,
            &GossipMessage { from: 2, revision: msg_b_to_a.revision, nodes: msg_b_to_a.nodes.clone(), edges: msg_b_to_a.edges.clone() },
        );
        merge_into(
            &shared_b,
            &GossipMessage { from: 1, revision: msg_a_to_b.revision, nodes: msg_a_to_b.nodes.clone(), edges: msg_a_to_b.edges.clone() },
        );

        let ga = shared_a.read().unwrap();
        let gb = shared_b.read().unwrap();
        let ha = admin_hash(ga.revision, &ga.nodes, &ga.edges);
        let hb = admin_hash(gb.revision, &gb.nodes, &gb.edges);
        assert_eq!(
            ha, hb,
            "both sides must converge to the same admin content after a fork"
        );
        // both know both nodes (loser adopts winner content, ensure_self re-adds self)
        assert!(ga.nodes.iter().any(|n| n.id == 1) && ga.nodes.iter().any(|n| n.id == 2));
        assert!(gb.nodes.iter().any(|n| n.id == 1) && gb.nodes.iter().any(|n| n.id == 2));
    }

    #[test]
    fn persist_writes_merged_config_to_disk() {
        let dir = std::env::temp_dir().join("em-persist-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("network.toml");
        let _ = std::fs::remove_file(&path);

        let state = NodeState::with_persist(
            NetworkConfig::bootstrap("s".into(), "n1".into()),
            path.clone(),
        );
        merge_into(
            &state.cfg,
            &GossipMessage {
                from: 2,
                revision: 3,
                nodes: vec![NodeEntry { id: 2, name: "n2".into(), public_key: None, address: None }],
                edges: vec![],
            },
        );
        state.persist();

        let loaded = NetworkConfig::load(&path).unwrap();
        assert_eq!(loaded.revision, 3);
        assert!(loaded.nodes.iter().any(|n| n.id == 2));
    }

    // ---------- HTTP integration tests ----------

    fn test_state() -> Arc<NodeState> {
        Arc::new(NodeState::new(NetworkConfig::bootstrap("test-secret".into(), "n1".into())))
    }

    #[tokio::test]
    async fn gossip_requires_valid_token() {
        let state = test_state();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let srv = state.clone();
        tokio::spawn(async move { axum::serve(listener, router(srv)).await.unwrap() });

        let client = reqwest::Client::new();

        // no headers -> 401
        let r = client
            .post(format!("http://127.0.0.1:{port}/api/gossip"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401);

        // valid token -> 200 with the peer's snapshot as JSON
        let nc = NodeClient::new("test-secret".into(), 1);
        let msg = GossipMessage {
            from: 2,
            revision: 1,
            nodes: vec![],
            edges: vec![],
        };
        let reply = nc.gossip(&format!("127.0.0.1:{port}"), &msg).await.unwrap();
        assert_eq!(reply.from, 1);
        assert_eq!(reply.revision, 1);

        // state endpoint: valid token -> snapshot, no token -> 401
        let st = nc.state(&format!("127.0.0.1:{port}")).await.unwrap();
        assert_eq!(st.from, 1);
        let r = client
            .get(format!("http://127.0.0.1:{port}/api/state"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401);

        // wrong secret -> 401 (token from different secret)
        let bad = NodeClient::new("other-secret".into(), 1);
        let r = bad
            .http
            .post(format!("http://127.0.0.1:{port}/api/gossip"))
            .headers(bad.auth_headers())
            .json(&msg)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401);
    }

    #[tokio::test]
    async fn gossip_round_converges_two_nodes() {
        let mut cfg_a = NetworkConfig::bootstrap("test-secret".into(), "node-1".into());
        let mut cfg_b = NetworkConfig::bootstrap("test-secret".into(), "node-2".into());
        cfg_b.self_id = 2;
        cfg_b.nodes[0].id = 2;
        cfg_a.recompute_hash();
        cfg_b.recompute_hash();

        let state_a = Arc::new(NodeState::new(cfg_a));
        let state_b = Arc::new(NodeState::new(cfg_b));

        let la = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let lb = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port_a = la.local_addr().unwrap().port();
        let port_b = lb.local_addr().unwrap().port();
        let sa = state_a.clone();
        tokio::spawn(async move { axum::serve(la, router(sa)).await.unwrap() });
        let sb = state_b.clone();
        tokio::spawn(async move { axum::serve(lb, router(sb)).await.unwrap() });

        // wire addresses (normally configured at join time / M5 deploy)
        {
            let mut g = state_a.cfg.write().unwrap();
            g.nodes.push(NodeEntry {
                id: 2,
                name: "node-2".into(),
                public_key: None,
                address: Some(format!("127.0.0.1:{port_b}")),
            });
            g.recompute_hash();
        }
        {
            let mut g = state_b.cfg.write().unwrap();
            g.nodes.push(NodeEntry {
                id: 1,
                name: "node-1".into(),
                public_key: None,
                address: Some(format!("127.0.0.1:{port_a}")),
            });
            g.recompute_hash();
        }

        // A gossips to B
        let client_a = NodeClient::new("test-secret".into(), 1);
        let res = gossip_round(&state_a, &client_a).await;
        assert_eq!(res.len(), 1);
        assert!(res[0].1.is_some(), "gossip to node-2 should succeed");
        {
            let g = state_a.cfg.read().unwrap();
            assert_eq!(g.nodes.len(), 2, "A should know both nodes");
            assert!(
                g.edges.iter().any(|e| e.a == 1 && e.b == 2 && e.latency_ms.is_some()),
                "A should have measured latency to B"
            );
        }

        // B gossips to A
        let client_b = NodeClient::new("test-secret".into(), 2);
        let res_b = gossip_round(&state_b, &client_b).await;
        assert!(res_b[0].1.is_some());
        {
            let g = state_b.cfg.read().unwrap();
            assert_eq!(g.nodes.len(), 2);
            assert!(g.edges.iter().any(|e| e.a == 1 && e.b == 2 && e.latency_ms.is_some()));
        }
    }
}
