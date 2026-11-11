//! Inter-node HTTP transport with HMAC-token auth and topology gossip.
//! Every request carries `X-Em-Token` (current 30s-period HMAC) and `X-Em-Node` (self id).
//! Middleware rejects anything whose token doesn't verify against the shared network secret.
//!
//! M2.2: gossip is a real exchange now — the peer replies with its own snapshot,
//! both sides merge. Latency (RTT) is measured per round and stored on edges.

// Items wired for M2.3 (routing reads VerifiedNode) are exercised by tests only.
#![allow(dead_code)]

use crate::config::{EdgeEntry, NetworkConfig, NodeEntry};
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
    /// latency measurements. Stricter conflict rules arrive in M2.4.
    pub cfg: Arc<RwLock<NetworkConfig>>,
}

impl NodeState {
    pub fn new(cfg: NetworkConfig) -> Self {
        Self {
            cfg: Arc::new(RwLock::new(cfg)),
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

/// Merge a received gossip message into the local config view.
/// - newer revision: adopt wholesale (sender is ahead)
/// - same revision: union nodes, fill in latencies we lack
/// - older revision: ignore content (we are ahead); sender still learns from our reply
pub fn merge_into(cfg: &RwLock<NetworkConfig>, msg: &GossipMessage) {
    let mut g = cfg.write().unwrap();
    if msg.revision > g.revision {
        g.nodes = msg.nodes.clone();
        g.edges = msg.edges.iter().map(normalized).collect();
        g.revision = msg.revision;
        ensure_self_present(&mut g);
        g.recompute_hash();
    } else if msg.revision == g.revision {
        for n in &msg.nodes {
            if !g.nodes.iter().any(|x| x.id == n.id) {
                g.nodes.push(n.clone());
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
        ensure_self_present(&mut g);
        g.recompute_hash();
    }
}

/// Record measured RTT to a peer. Latency churn does not bump the revision:
/// revision tracks admin-level topology changes (M2.4 refines this).
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
/// measure RTT. Returns (peer_id, Some(latency_ms)) per peer, None on failure.
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

/// Inbound topology gossip: merge the peer's view, reply with our own snapshot
/// (push-pull in a single round trip).
async fn gossip(
    State(state): State<Arc<NodeState>>,
    Json(msg): Json<GossipMessage>,
) -> Json<GossipMessage> {
    merge_into(&state.cfg, &msg);
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
    fn merge_equal_revision_fills_missing_latency() {
        let local = NetworkConfig::bootstrap("s".into(), "n1".into());
        let shared = RwLock::new(local);
        let msg = GossipMessage {
            from: 2,
            revision: 1,
            nodes: vec![NodeEntry { id: 2, name: "n2".into(), public_key: None, address: None }],
            edges: vec![EdgeEntry { a: 2, b: 1, latency_ms: Some(12) }],
        };
        merge_into(&shared, &msg);
        let g = shared.read().unwrap();
        assert!(g.nodes.iter().any(|n| n.id == 2));
        assert!(g.edges.iter().any(|e| e.a == 1 && e.b == 2 && e.latency_ms == Some(12)));
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
