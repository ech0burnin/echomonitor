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
//!
//! M3.3: gossip messages also carry site probe results (runtime-only state,
//! never persisted, never hashed). Probe merge is a commutative union with
//! last-write-wins per (check_id, node_id) — see merge_probes.

// Items wired for later milestones (M2.5 elections read VerifiedNode) are exercised by tests only.
#![allow(dead_code)]

use crate::checks::SiteProbe;
use crate::config::{admin_hash, EdgeEntry, NetworkConfig, NodeEntry};
use crate::crypto;
use crate::sitereport::ProbeTable;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
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
    /// M3.3: gossip-shared site probe results, latest per (check_id, node_id).
    /// Runtime-only state: never persisted, never part of admin_hash.
    pub probes: Arc<RwLock<ProbeTable>>,
    /// M2.5: liveness evidence — node_id -> unix ms of the last successful
    /// direct gossip with that node (self seeded at boot). Replicated via
    /// `GossipMessage::seen`, max-merged. Runtime-only, never persisted.
    pub evidence: Arc<RwLock<crate::elector::Evidence>>,
    /// M2.5: last computed parent (id), for health/status/redirect.
    pub parent: RwLock<Option<u32>>,
    /// M3.6: last observed systemd unit liveness on THIS node (filled by
    /// the daemon's unit monitor loop). Runtime-only state: never
    /// persisted, never part of admin_hash, ignored by peers on merge.
    pub units: Arc<RwLock<Vec<crate::selfstats::UnitStatus>>>,
    /// M2.6: SSH fallback tunnel manager (tokio Mutex — building a tunnel
    /// is async). None when `node.key` is absent/unusable (tests, plain
    /// status runs): no node gets a tunnel, behavior is M2.5-identical.
    pub tunnels: tokio::sync::Mutex<Option<crate::tunnel::TunnelManager>>,
}

impl NodeState {
    pub fn new(cfg: NetworkConfig) -> Self {
        let evidence = seeded_evidence(&cfg);
        Self {
            cfg: Arc::new(RwLock::new(cfg)),
            persist_path: None,
            probes: Arc::new(RwLock::new(HashMap::new())),
            evidence: Arc::new(RwLock::new(evidence)),
            parent: RwLock::new(None),
            units: Arc::new(RwLock::new(Vec::new())),
            tunnels: tokio::sync::Mutex::new(None),
        }
    }

    pub fn with_persist(cfg: NetworkConfig, path: std::path::PathBuf) -> Self {
        let evidence = seeded_evidence(&cfg);
        Self {
            cfg: Arc::new(RwLock::new(cfg)),
            persist_path: Some(path),
            probes: Arc::new(RwLock::new(HashMap::new())),
            evidence: Arc::new(RwLock::new(evidence)),
            parent: RwLock::new(None),
            units: Arc::new(RwLock::new(Vec::new())),
            tunnels: tokio::sync::Mutex::new(None),
        }
    }

    /// M2.5: record a successful direct contact with `peer` (either
    /// direction). Kept per-observer wall clock; merged max-wins.
    pub fn record_seen(&self, peer: u32, at_ms: u64) {
        let mut ev = self.evidence.write().unwrap();
        let e = ev.entry(peer).or_insert(0);
        if at_ms > *e {
            *e = at_ms;
        }
    }

    /// Record one of OUR OWN probe results (from the check engine sink).
    pub fn record_own_probe(&self, probe: SiteProbe) {
        let mut t = self.probes.write().unwrap();
        t.insert((probe.check_id.clone(), probe.node_id), probe);
    }

    /// M3.6: replace the shared unit-liveness snapshot (writer: the
    /// daemon's periodic unit monitor; readers: snapshot_msg/api state).
    pub fn set_units(&self, units: Vec<crate::selfstats::UnitStatus>) {
        *self.units.write().unwrap() = units;
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
    /// Includes the full probe table (ours + everything learned from peers),
    /// so results propagate transitively through the mesh.
    pub fn snapshot_msg(&self) -> GossipMessage {
        let g = self.cfg.read().unwrap();
        let probes: Vec<SiteProbe> = self.probes.read().unwrap().values().cloned().collect();
        let seen: Vec<SeenEntry> = self
            .evidence
            .read()
            .unwrap()
            .iter()
            .map(|(&id, &at_ms)| SeenEntry { id, at_ms })
            .collect();
        GossipMessage {
            from: g.self_id,
            revision: g.revision,
            nodes: g.nodes.clone(),
            edges: g.edges.clone(),
            probes,
            seen,
            units: self.units.read().unwrap().clone(),
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
    /// Site probe results shared M3.3-style. `serde(default)` keeps messages
    /// from older binaries (no probes field) deserializable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub probes: Vec<SiteProbe>,
    /// M2.5 liveness evidence shared through gossip. Same old-wire safety.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub seen: Vec<SeenEntry>,
    /// M3.6: THIS node's systemd unit liveness, served with `/api/state`.
    /// Local observation only: peers ignore it when merging gossip (there
    /// is nothing to merge — each node reports its own units). Same
    /// old-wire safety as probes/seen.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub units: Vec<crate::selfstats::UnitStatus>,
}

/// One liveness observation: node `id` was directly reachable at `at_ms`
/// (observer wall clock). Serialized separately from the HashMap.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SeenEntry {
    pub id: u32,
    pub at_ms: u64,
}

fn seeded_evidence(cfg: &NetworkConfig) -> crate::elector::Evidence {
    let mut ev = crate::elector::Evidence::new();
    let now = crate::checks::chrono_pseudo::Ts::now().unix_ms();
    ev.insert(cfg.self_id, now);
    ev
}

/// Merge incoming liveness evidence: max per node id (commutative,
/// associative — all sides of an exchange converge in one round).
pub fn merge_seen(table: &RwLock<crate::elector::Evidence>, incoming: &[SeenEntry]) {
    let mut t = table.write().unwrap();
    for s in incoming {
        let e = t.entry(s.id).or_insert(0);
        if s.at_ms > *e {
            *e = s.at_ms;
        }
    }
}

// ---------- probe merge ----------

/// Merge incoming probe results into the shared table: union of keys,
/// latest `measured_at` wins per (check_id, node_id). On an exact timestamp
/// tie the lexicographically larger serialized probe wins, making the merge
/// fully commutative and associative (both sides of an exchange converge to
/// the identical table in one round, like the M2.4 union merge).
pub fn merge_probes(table: &RwLock<ProbeTable>, incoming: &[SiteProbe]) {
    let mut t = table.write().unwrap();
    for p in incoming {
        match t.get(&(p.check_id.clone(), p.node_id)) {
            None => {
                t.insert((p.check_id.clone(), p.node_id), p.clone());
            }
            Some(cur) => {
                let newer = p.measured_at.unix_ms() > cur.measured_at.unix_ms();
                let tie_break = p.measured_at.unix_ms() == cur.measured_at.unix_ms()
                    && serde_json::to_string(p).unwrap_or_default()
                        > serde_json::to_string(cur).unwrap_or_default();
                if newer || tie_break {
                    t.insert((p.check_id.clone(), p.node_id), p.clone());
                }
            }
        }
    }
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
            ssh: None,
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

/// Field merge for `SshDial` — same commutative rules as the string fields
/// (lexicographic max per field, max for port), so both sides of an exchange
/// converge to the identical entry in one round. M2.8: the forward fields
/// follow the same rules (Option fill-in / max) individually —
/// `forward_host` and `forward_port` never force each other to be set.
fn pick_opt_u16(a: Option<u16>, b: Option<u16>) -> Option<u16> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

fn merge_ssh(local: &Option<crate::config::SshDial>, remote: &Option<crate::config::SshDial>) -> Option<crate::config::SshDial> {
    match (local, remote) {
        (Some(a), Some(b)) => Some(crate::config::SshDial {
            host: a.host.clone().max(b.host.clone()),
            user: a.user.clone().max(b.user.clone()),
            port: a.port.max(b.port),
            forward_host: pick_opt(a.forward_host.clone(), b.forward_host.clone()),
            forward_port: pick_opt_u16(a.forward_port, b.forward_port),
        }),
        (Some(x), None) | (None, Some(x)) => Some(x.clone()),
        (None, None) => None,
    }
}

fn merge_node_entry(local: &NodeEntry, remote: &NodeEntry) -> NodeEntry {
    NodeEntry {
        id: local.id,
        name: local.name.clone().max(remote.name.clone()),
        public_key: pick_opt(local.public_key.clone(), remote.public_key.clone()),
        address: pick_opt(local.address.clone(), remote.address.clone()),
        ssh: merge_ssh(&local.ssh, &remote.ssh),
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
///
/// M2.6 fallback: when direct HTTP fails (or the peer has no `address` at
/// all — NAT child), retry through an SSH tunnel to the peer's system sshd.
/// Tunnel-mediated contact counts as liveness evidence and produces an honest
/// (higher) edge latency, so Dijkstra still prefers a direct path when one
/// exists. A failed tunnel attempt tears the tunnel down; the next round
/// retries direct HTTP first and rebuilds only if needed.
pub async fn gossip_round(state: &NodeState, client: &NodeClient) -> Vec<(u32, Option<u64>)> {
    let (self_id, listen_port, targets) = {
        let g = state.cfg.read().unwrap();
        // (peer, address, ssh-dial) — address OR ssh makes a node dialable;
        // specs are copied out so no cfg lock is held across awaits.
        let targets: Vec<(u32, Option<String>, Option<crate::config::SshDial>)> = g
            .nodes
            .iter()
            .filter(|n| n.id != g.self_id)
            .filter(|n| n.address.is_some() || n.ssh.is_some())
            .map(|n| (n.id, n.address.clone(), n.ssh.clone()))
            .collect();
        (g.self_id, g.net.listen_port, targets)
    };

    let mut out = Vec::new();
    for (peer_id, address, ssh) in targets {
        // outcome = Some((reply, rtt_ms)) on success, plus how we got there
        let mut outcome: Option<(GossipMessage, u64)> = None;
        let mut via_tunnel = false;

        // 1) direct HTTP when an address is known (always preferred)
        if let Some(addr) = address.as_deref() {
            let msg = state.snapshot_msg();
            let t0 = Instant::now();
            match client.gossip(addr, &msg).await {
                Ok(reply) => outcome = Some((reply, t0.elapsed().as_millis() as u64)),
                Err(e) => tracing::warn!(peer = peer_id, error = %e, "direct gossip failed"),
            }
        }

        // 2) SSH fallback: no address at all, or direct just failed
        if outcome.is_none() {
            if let Some(ssh) = ssh.as_ref() {
                match tunnel_endpoint(state, peer_id, ssh, listen_port).await {
                    Ok(ep) => {
                        let msg = state.snapshot_msg();
                        // RTT wraps only the request — the handshake cost
                        // is paid once per tunnel, not per gossip.
                        let t0 = Instant::now();
                        match client.gossip(&ep.to_string(), &msg).await {
                            Ok(reply) => {
                                via_tunnel = true;
                                outcome = Some((reply, t0.elapsed().as_millis() as u64));
                            }
                            Err(e) => {
                                tracing::warn!(peer = peer_id, error = %e, "gossip via ssh tunnel failed");
                                // tunnel or peer daemon unhealthy — force a
                                // rebuild next round
                                let mut guard = state.tunnels.lock().await;
                                if let Some(tm) = guard.as_mut() {
                                    tm.note_dead(peer_id);
                                }
                            }
                        }
                    }
                    Err(e) => tracing::warn!(peer = peer_id, error = %e, "ssh tunnel unavailable"),
                }
            }
        }

        match outcome {
            Some((reply, ms)) => {
                merge_into(&state.cfg, &reply);
                merge_probes(&state.probes, &reply.probes);
                merge_seen(&state.evidence, &reply.seen);
                state.record_seen(peer_id, crate::checks::chrono_pseudo::Ts::now().unix_ms());
                set_edge_latency(&state.cfg, self_id, peer_id, ms);
                if via_tunnel {
                    tracing::info!(peer = peer_id, latency_ms = ms, "gossip ok (ssh tunnel)");
                } else {
                    tracing::debug!(peer = peer_id, latency_ms = ms, "gossip ok");
                }
                out.push((peer_id, Some(ms)));
            }
            None => out.push((peer_id, None)),
        }
    }
    state.persist();
    out
}

/// The daemon's gossip + election loop (M2.7: extracted from `cli::run`
/// so the integration test drives the exact production code path).
/// Every `net.gossip_interval_secs` it push-pulls a snapshot with all
/// reachable peers, then recomputes the deterministic parent; a desired
/// change is acted on only after it held for `ELECT_STABILITY`
/// consecutive rounds (flap guard). The dead threshold scales with the
/// interval (`elector::t_dead_for`) so a fast test mesh behaves like a
/// slow production one. Aborting the returned task stops the node's
/// gossiping — peers notice through the evidence table.
pub fn spawn_gossip_loop(state: Arc<NodeState>) -> tokio::task::JoinHandle<()> {
    let (interval, self_id, secret) = {
        let g = state.cfg.read().unwrap();
        (
            g.net.gossip_interval_secs.max(1),
            g.self_id,
            g.auth.network_secret.clone(),
        )
    };
    let t_dead_ms = crate::elector::t_dead_for(interval);
    tokio::spawn(async move {
        let secret: Arc<str> = secret.as_str().into();
        let client = NodeClient::new(secret, self_id);
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(interval));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // M2.5: deterministic parent election after each round; act on a
        // change only once the desired parent held for ELECT_STABILITY rounds.
        let mut gate = crate::elector::StabilityGate::new();
        loop {
            tick.tick().await;
            let results = gossip_round(&state, &client).await;
            let ok = results.iter().filter(|(_, l)| l.is_some()).count();
            tracing::debug!(peers = results.len(), ok, "gossip round done");
            let now_ms = crate::checks::chrono_pseudo::Ts::now().unix_ms();
            let desired = {
                let g = state.cfg.read().unwrap();
                let evidence = state.evidence.read().unwrap();
                crate::elector::elect(&g.nodes, &g.edges, &evidence, now_ms, t_dead_ms)
            };
            let (effective, changed) = gate.observe(desired);
            *state.parent.write().unwrap() = effective;
            if changed {
                match effective {
                    Some(p) if p == self_id => {
                        tracing::info!(parent = p, "PARENT role acquired");
                    }
                    Some(p) => {
                        tracing::info!(parent = p, "parent changed");
                    }
                    None => tracing::warn!("no parent eligible"),
                }
            }
        }
    })
}

/// Ask the node's TunnelManager for a local endpoint towards the peer,
/// building/rebuilding the tunnel when needed. `peer_http_port` is the
/// network-global `net.listen_port` — the DEFAULT forward target port,
/// overridden per-entry by `SshDial.forward_port`.
async fn tunnel_endpoint(
    state: &NodeState,
    peer: u32,
    ssh: &crate::config::SshDial,
    peer_http_port: u16,
) -> anyhow::Result<SocketAddr> {
    let spec = crate::tunnel::TunnelSpec::from_dial(ssh, peer_http_port);
    let mut guard = state.tunnels.lock().await;
    match guard.as_mut() {
        Some(tm) => tm.endpoint(peer, &spec).await,
        None => Err(anyhow::anyhow!("no tunnel manager (node.key missing?)")),
    }
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
    let parent_id = *state.parent.read().unwrap();
    let parent = parent_id.map(|pid| {
        let n = g.nodes.iter().find(|n| n.id == pid);
        json!({
            "id": pid,
            "name": n.map(|n| n.name.clone()),
            "addr": n.and_then(|n| n.address.clone()),
        })
    });
    Json(json!({
        "status": "ok",
        "node": g.self_name,
        "revision": g.revision,
        "parent": parent,
    }))
}

/// Inbound topology gossip: merge the peer's view (config, probe results,
/// liveness evidence), persist the config, reply with our own snapshot
/// (push-pull in a single round trip).
//
// Runtime state — merged, NOT persisted.
async fn gossip(
    State(state): State<Arc<NodeState>>,
    Json(msg): Json<GossipMessage>,
) -> Json<GossipMessage> {
    merge_into(&state.cfg, &msg);
    merge_probes(&state.probes, &msg.probes);
    merge_seen(&state.evidence, &msg.seen);
    state.record_seen(msg.from, crate::checks::chrono_pseudo::Ts::now().unix_ms());
    state.persist();
    Json(state.snapshot_msg())
}

/// Current topology view (auth'd; used by `echomonitor status`).
async fn state_handler(State(state): State<Arc<NodeState>>) -> Json<GossipMessage> {
    Json(state.snapshot_msg())
}

/// M2.5: unauthenticated root — point a browser at the elected parent.
/// 307 to the parent's address when known; otherwise a JSON hint with the
/// parent id/name and the next hop (NAT'd parent case).
async fn root_redirect(State(state): State<Arc<NodeState>>) -> Response {
    let parent_id = *state.parent.read().unwrap();
    let g = state.cfg.read().unwrap();
    let parent = parent_id.and_then(|pid| g.nodes.iter().find(|n| n.id == pid));
    match parent.and_then(|n| n.address.as_deref()) {
        Some(addr) => {
            let loc = if addr.starts_with("http://") || addr.starts_with("https://") {
                addr.to_string()
            } else {
                format!("http://{addr}/")
            };
            Redirect::temporary(&loc).into_response()
        }
        None => {
            let (id, name) = match parent {
                Some(n) => (json!(n.id), json!(n.name)),
                None => (serde_json::Value::Null, serde_json::Value::Null),
            };
            let next_hop = parent_id.and_then(|pid| {
                crate::routing::RoutingTable::build(g.self_id, &g.nodes, &g.edges).next_hop(pid)
            });
            Json(json!({
                "hint": "this node is not the parent",
                "parent": {"id": id, "name": name},
                "next_hop": next_hop,
            }))
            .into_response()
        }
    }
}

// ---------- client ----------

/// Strip an accidental `http(s)://` scheme from a configured address.
/// `address` is a bare `host:port` (IP or domain); a scheme-carrying value
/// pasted from a browser would produce `http://http://…` URLs below.
/// (`root_redirect` already tolerates schemes the same way.)
fn strip_scheme(addr: &str) -> &str {
    let a = addr.trim();
    let a = a.strip_prefix("https://").unwrap_or(a);
    a.strip_prefix("http://").unwrap_or(a)
}

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
        let url = format!("http://{}/api/health", strip_scheme(addr));
        let resp = self.http.get(&url).headers(self.auth_headers()).send().await?;
        Ok(resp.json().await?)
    }

    pub async fn gossip(&self, addr: &str, msg: &GossipMessage) -> anyhow::Result<GossipMessage> {
        let url = format!("http://{}/api/gossip", strip_scheme(addr));
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
        let url = format!("http://{}/api/state", strip_scheme(addr));
        let resp = self.http.get(&url).headers(self.auth_headers()).send().await?;
        let resp = resp.error_for_status()?;
        Ok(resp.json().await?)
    }
}

// ---------- router ----------

pub fn router(state: Arc<NodeState>) -> Router {
    Router::new()
        .route("/", get(root_redirect))
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

    // ---------- M3.6: unit liveness in state replies ----------

    #[test]
    fn snapshot_msg_carries_units() {
        let state = test_state();
        state.set_units(vec![
            crate::selfstats::UnitStatus { name: "zeroclaw.service".into(), active: true },
            crate::selfstats::UnitStatus { name: "docker.service".into(), active: false },
        ]);
        let msg = state.snapshot_msg();
        assert_eq!(msg.units.len(), 2);
        assert!(msg.units[0].active);
        assert!(!msg.units[1].active);
        // and it serializes into the /api/state wire format
        let j = serde_json::to_value(&msg).unwrap();
        assert_eq!(j["units"][0]["name"], "zeroclaw.service");
        assert_eq!(j["units"][1]["active"], false);
    }

    #[test]
    fn gossip_message_without_units_still_parses() {
        // Pre-M3.6 wire format (no units key) must stay deserializable.
        let raw = r#"{
            "from": 2, "revision": 1,
            "nodes": [], "edges": [], "probes": [], "seen": []
        }"#;
        let msg: GossipMessage = serde_json::from_str(raw).expect("legacy message parses");
        assert!(msg.units.is_empty());
    }

    // ---------- merge unit tests ----------

    #[test]
    fn merge_adopts_newer_revision() {
        let local = NetworkConfig::bootstrap("s".into(), "n1".into());
        let shared = RwLock::new(local);
        let msg = GossipMessage {
            from: 2,
            revision: 5,
            nodes: vec![
                NodeEntry { id: 1, name: "n1".into(), public_key: None, address: None, ssh: None },
                NodeEntry { id: 2, name: "n2".into(), public_key: None, address: Some("10.0.0.2:8687".into()), ssh: None },
            ],
            edges: vec![EdgeEntry { a: 2, b: 1, latency_ms: Some(7) }],
            probes: vec![], seen: vec![], units: vec![],
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
            nodes: vec![NodeEntry { id: 9, name: "x".into(), public_key: None, address: None, ssh: None }],
            edges: vec![],
            probes: vec![], seen: vec![], units: vec![],
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
                NodeEntry { id: 1, name: "n1".into(), public_key: None, address: None, ssh: None },
                NodeEntry { id: 2, name: "n2".into(), public_key: None, address: None, ssh: None },
            ],
            edges: vec![EdgeEntry { a: 1, b: 2, latency_ms: None }],
            probes: vec![], seen: vec![], units: vec![],
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
        local.nodes.push(NodeEntry { id: 2, name: "n2".into(), public_key: None, address: None, ssh: None });
        local.edges.push(EdgeEntry { a: 1, b: 2, latency_ms: None });
        local.recompute_hash();
        let shared = RwLock::new(local);
        let msg = GossipMessage {
            from: 2,
            revision: shared.read().unwrap().revision,
            nodes: vec![
                NodeEntry { id: 1, name: "n1".into(), public_key: None, address: None, ssh: None },
                NodeEntry { id: 2, name: "n2".into(), public_key: None, address: None, ssh: None },
            ],
            edges: vec![EdgeEntry { a: 2, b: 1, latency_ms: Some(12) }],
            probes: vec![], seen: vec![], units: vec![],
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
            &GossipMessage { from: 2, revision: msg_b_to_a.revision, nodes: msg_b_to_a.nodes.clone(), edges: msg_b_to_a.edges.clone(), probes: vec![], seen: vec![], units: vec![] },
        );
        merge_into(
            &shared_b,
            &GossipMessage { from: 1, revision: msg_a_to_b.revision, nodes: msg_a_to_b.nodes.clone(), edges: msg_a_to_b.edges.clone(), probes: vec![], seen: vec![], units: vec![] },
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
                nodes: vec![NodeEntry { id: 2, name: "n2".into(), public_key: None, address: None, ssh: None }],
                edges: vec![],
            probes: vec![], seen: vec![], units: vec![],
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
            probes: vec![], seen: vec![], units: vec![],
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
                address: Some(format!("127.0.0.1:{port_b}")), ssh: None,
            });
            g.recompute_hash();
        }
        {
            let mut g = state_b.cfg.write().unwrap();
            g.nodes.push(NodeEntry {
                id: 1,
                name: "node-1".into(),
                public_key: None,
                address: Some(format!("127.0.0.1:{port_a}")), ssh: None,
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

    // ---------- M3.3 probe sharing ----------

    use crate::checks::{chrono_pseudo::Ts, CheckOutcome, SiteProbe};

    fn probe(check: &str, node: u32, at_ms: u64, outcome: CheckOutcome) -> SiteProbe {
        SiteProbe { check_id: check.into(), node_id: node, measured_at: Ts(at_ms), outcome, status: None, ip: None }
    }

    fn table_of(list: &[SiteProbe]) -> RwLock<ProbeTable> {
        let mut t = ProbeTable::new();
        for p in list {
            t.insert((p.check_id.clone(), p.node_id), p.clone());
        }
        RwLock::new(t)
    }

    fn sorted_table(t: &RwLock<ProbeTable>) -> Vec<SiteProbe> {
        let mut v: Vec<SiteProbe> = t.read().unwrap().values().cloned().collect();
        v.sort_by_key(|p| (p.check_id.clone(), p.node_id));
        v
    }

    #[test]
    fn probe_merge_is_commutative_and_latest_wins() {
        let a = vec![
            probe("c1", 1, 1_000, CheckOutcome::Ok { latency_ms: 10 }),
            probe("c1", 2, 900, CheckOutcome::Ok { latency_ms: 20 }),
            probe("c2", 1, 800, CheckOutcome::Fail { reason: "old".into() }),
        ];
        let b = vec![
            probe("c1", 1, 1_500, CheckOutcome::Ok { latency_ms: 11 }), // newer: must win
            probe("c1", 3, 1_200, CheckOutcome::Ok { latency_ms: 30 }), // new key: union
            probe("c2", 1, 900, CheckOutcome::Ok { latency_ms: 40 }),   // newer: outcome flips
        ];
        let ta = table_of(&a);
        let tb = table_of(&b);
        merge_probes(&ta, &b);
        merge_probes(&tb, &a);

        let (va, vb) = (sorted_table(&ta), sorted_table(&tb));
        assert_eq!(va, vb, "merge must be commutative: both sides identical after one exchange");
        assert_eq!(va.len(), 4, "union of keys: c1/1, c1/2, c1/3, c2/1");
        let t = ta.read().unwrap();
        assert_eq!(
            t.get(&("c1".into(), 1)).unwrap().measured_at.unix_ms(),
            1_500,
            "latest measured_at wins"
        );
        assert_eq!(
            t.get(&("c2".into(), 1)).unwrap().outcome,
            CheckOutcome::Ok { latency_ms: 40 },
            "newer result replaces older even across outcome classes"
        );
    }

    #[test]
    fn probe_merge_tie_breaks_deterministically() {
        // same key, same timestamp, different content: the larger serialized
        // probe wins on BOTH sides — commutativity must not depend on order
        let x = probe("c", 1, 5_000, CheckOutcome::Fail { reason: "aaa".into() });
        let y = probe("c", 1, 5_000, CheckOutcome::Fail { reason: "zzz".into() });
        let ta = table_of(std::slice::from_ref(&x));
        let tb = table_of(std::slice::from_ref(&y));
        merge_probes(&ta, &[y]);
        merge_probes(&tb, &[x]);
        assert_eq!(sorted_table(&ta), sorted_table(&tb), "tie must resolve identically on both sides");
    }

    #[test]
    fn gossip_message_without_probes_still_parses() {
        // wire format from a pre-M3.3 binary
        let raw = r#"{"from":2,"revision":3,"nodes":[],"edges":[]}"#;
        let msg: GossipMessage = serde_json::from_str(raw).unwrap();
        assert_eq!(msg.from, 2);
        assert!(msg.probes.is_empty());
    }

    #[test]
    fn probe_results_not_persisted_into_config() {
        let dir = std::env::temp_dir().join("em-m33-nopersist");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("network.toml");
        let _ = std::fs::remove_file(&path);

        let state = NodeState::with_persist(
            NetworkConfig::bootstrap("s".into(), "n1".into()),
            path.clone(),
        );
        state.record_own_probe(probe("web", 1, 42, CheckOutcome::Ok { latency_ms: 5 }));
        state.persist();

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("probe"), "probe data must not leak into network.toml");
        let loaded = NetworkConfig::load(&path).unwrap();
        let before = loaded.content_hash.clone();
        // a gossip carrying probes must not change the persisted admin hash
        merge_probes(&state.probes, &[probe("web", 2, 50, CheckOutcome::Ok { latency_ms: 7 })]);
        state.persist();
        let after = NetworkConfig::load(&path).unwrap().content_hash;
        assert_eq!(before, after, "admin_hash must be unaffected by probe data");
    }

    #[tokio::test]
    async fn probes_converge_in_one_exchange_round() {
        let mut cfg_a = NetworkConfig::bootstrap("test-secret".into(), "node-1".into());
        let mut cfg_b = NetworkConfig::bootstrap("test-secret".into(), "node-2".into());
        cfg_b.self_id = 2;
        cfg_b.nodes[0].id = 2;
        cfg_a.recompute_hash();
        cfg_b.recompute_hash();

        let state_a = Arc::new(NodeState::new(cfg_a));
        let state_b = Arc::new(NodeState::new(cfg_b));

        // each side has ONLY its own probe result
        state_a.record_own_probe(probe("web", 1, 1_000, CheckOutcome::Ok { latency_ms: 10 }));
        state_b.record_own_probe(probe("web", 2, 1_000, CheckOutcome::Fail { reason: "conn refused".into() }));

        let lb = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port_b = lb.local_addr().unwrap().port();
        let sb = state_b.clone();
        tokio::spawn(async move { axum::serve(lb, router(sb)).await.unwrap() });

        {
            let mut g = state_a.cfg.write().unwrap();
            g.nodes.push(NodeEntry {
                id: 2,
                name: "node-2".into(),
                public_key: None,
                address: Some(format!("127.0.0.1:{port_b}")), ssh: None,
            });
            g.recompute_hash();
        }

        // ONE round: A pushes (B merges A's probes), B replies (A merges B's)
        let client_a = NodeClient::new("test-secret".into(), 1);
        let res = gossip_round(&state_a, &client_a).await;
        assert_eq!(res.len(), 1);
        assert!(res[0].1.is_some(), "gossip must succeed");

        for (state, label) in [(&state_a, "A"), (&state_b, "B")] {
            let t = state.probes.read().unwrap();
            assert_eq!(t.len(), 2, "{label} must hold both nodes' results after one round");
            assert!(t.contains_key(&("web".into(), 1)), "{label} missing node-1 result");
            assert!(t.contains_key(&("web".into(), 2)), "{label} missing node-2 result");
        }
    }

    // ---------- M2.6 ssh dial merge ----------

    #[test]
    fn merge_node_entry_ssh_is_commutative() {
        let local = NodeEntry {
            id: 2,
            name: "n".into(),
            public_key: None,
            address: None,
            ssh: Some(crate::config::SshDial {
                host: "10.0.0.5".into(),
                port: 22,
                user: "root".into(),
                forward_host: None,
                forward_port: None,
            }),
        };
        let remote = NodeEntry {
            id: 2,
            name: "n".into(),
            public_key: None,
            address: None,
            ssh: Some(crate::config::SshDial {
                host: "10.0.0.9".into(),
                port: 2222,
                user: "op".into(),
                forward_host: None,
                forward_port: None,
            }),
        };
        let ab = merge_node_entry(&local, &remote);
        let ba = merge_node_entry(&remote, &local);
        assert_eq!(ab, ba, "merge must be commutative");
        assert_eq!(
            ab.ssh,
            Some(crate::config::SshDial { host: "10.0.0.9".into(), port: 2222, user: "root".into(), forward_host: None, forward_port: None }),
            "lexicographic max per field, numeric max for port"
        );

        // one-sided fill
        let none_ssh = NodeEntry { id: 2, name: "n".into(), public_key: None, address: None, ssh: None };
        assert_eq!(
            merge_node_entry(&none_ssh, &remote).ssh,
            Some(crate::config::SshDial { host: "10.0.0.9".into(), port: 2222, user: "op".into(), forward_host: None, forward_port: None })
        );
        assert_eq!(merge_node_entry(&none_ssh, &none_ssh).ssh, None);
    }

    // ---------- M2.5 parent election ----------

    fn wire_pair(state_a: &Arc<NodeState>, state_b: &Arc<NodeState>, port_a: u16, port_b: u16) {
        let mut g = state_a.cfg.write().unwrap();
        g.nodes.push(NodeEntry {
            id: 2,
            name: "node-2".into(),
            public_key: None,
            address: Some(format!("127.0.0.1:{port_b}")), ssh: None,
        });
        g.recompute_hash();
        let mut g = state_b.cfg.write().unwrap();
        g.nodes.push(NodeEntry {
            id: 1,
            name: "node-1".into(),
            public_key: None,
            address: Some(format!("127.0.0.1:{port_a}")), ssh: None,
        });
        g.recompute_hash();
    }

    async fn spawn_node_router(state: &Arc<NodeState>) -> u16 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let s = state.clone();
        tokio::spawn(async move { axum::serve(l, router(s)).await.unwrap() });
        port
    }

    #[tokio::test]
    async fn two_nodes_agree_on_parent() {
        let mut cfg_a = NetworkConfig::bootstrap("test-secret".into(), "node-1".into());
        let mut cfg_b = NetworkConfig::bootstrap("test-secret".into(), "node-2".into());
        cfg_b.self_id = 2;
        cfg_b.nodes[0].id = 2;
        cfg_a.recompute_hash();
        cfg_b.recompute_hash();

        let state_a = Arc::new(NodeState::new(cfg_a));
        let state_b = Arc::new(NodeState::new(cfg_b));
        let port_a = spawn_node_router(&state_a).await;
        let port_b = spawn_node_router(&state_b).await;
        wire_pair(&state_a, &state_b, port_a, port_b);

        let client_a = NodeClient::new("test-secret".into(), 1);
        let client_b = NodeClient::new("test-secret".into(), 2);
        assert!(gossip_round(&state_a, &client_a).await[0].1.is_some());
        assert!(gossip_round(&state_b, &client_b).await[0].1.is_some());

        let now = crate::checks::chrono_pseudo::Ts::now().unix_ms();
        for state in [&state_a, &state_b] {
            let g = state.cfg.read().unwrap();
            let ev = state.evidence.read().unwrap();
            assert_eq!(
                crate::elector::elect(&g.nodes, &g.edges, &ev, now, crate::elector::T_DEAD_MS),
                Some(1),
                "both nodes must elect node-1 (lowest id, rule waived at N=2)"
            );
        }
    }

    #[tokio::test]
    async fn parent_death_re_elects_on_survivors() {
        // star: 1<->2, 1<->3; node-1 dies -> no alive-alive edge remains,
        // strict rule finds no candidate -> degraded fallback to lowest alive
        let mut cfg1 = NetworkConfig::bootstrap("s".into(), "n1".into());
        let mut cfg2 = NetworkConfig::bootstrap("s".into(), "n2".into());
        let mut cfg3 = NetworkConfig::bootstrap("s".into(), "n3".into());
        cfg2.self_id = 2;
        cfg3.self_id = 3;
        cfg2.nodes[0].id = 2;
        cfg3.nodes[0].id = 3;
        for c in [&mut cfg1, &mut cfg2, &mut cfg3] {
            c.recompute_hash();
        }
        let s1 = Arc::new(NodeState::new(cfg1));
        let s2 = Arc::new(NodeState::new(cfg2));
        let s3 = Arc::new(NodeState::new(cfg3));
        let p1 = spawn_node_router(&s1).await;
        let p2 = spawn_node_router(&s2).await;
        let p3 = spawn_node_router(&s3).await;
        wire_pair(&s1, &s2, p1, p2);
        wire_pair(&s1, &s3, p1, p3);

        let c1 = NodeClient::new("s".into(), 1);
        assert!(gossip_round(&s1, &c1).await.iter().all(|(_, l)| l.is_some()));
        let c2 = NodeClient::new("s".into(), 2);
        let c3 = NodeClient::new("s".into(), 3);
        assert!(gossip_round(&s2, &c2).await[0].1.is_some());
        assert!(gossip_round(&s3, &c3).await[0].1.is_some());

        let now = crate::checks::chrono_pseudo::Ts::now().unix_ms();
        // before the crash: node-1 has two alive neighbors -> parent
        for s in [&s2, &s3] {
            let g = s.cfg.read().unwrap();
            let ev = s.evidence.read().unwrap();
            assert_eq!(crate::elector::elect(&g.nodes, &g.edges, &ev, now, crate::elector::T_DEAD_MS), Some(1));
        }

        // node-1 dies: its evidence goes stale on the survivors
        for s in [&s2, &s3] {
            let mut ev = s.evidence.write().unwrap();
            ev.insert(1, now - crate::elector::T_DEAD_MS - 1);
        }
        for s in [&s2, &s3] {
            let g = s.cfg.read().unwrap();
            let ev = s.evidence.read().unwrap();
            assert_eq!(
                crate::elector::elect(&g.nodes, &g.edges, &ev, now, crate::elector::T_DEAD_MS),
                Some(2),
                "survivors must re-elect: strict rule finds no candidate (no 2-3 edge), degraded fallback to lowest alive"
            );
        }
    }

    #[tokio::test]
    async fn root_redirects_to_elected_parent() {
        let mut cfg = NetworkConfig::bootstrap("s".into(), "n2".into());
        cfg.self_id = 2;
        cfg.nodes[0].id = 2;
        cfg.nodes.push(NodeEntry {
            id: 1,
            name: "n1".into(),
            public_key: None,
            address: Some("10.9.9.9:8687".into()), ssh: None,
        });
        cfg.recompute_hash();
        let state = Arc::new(NodeState::new(cfg));
        *state.parent.write().unwrap() = Some(1);

        let resp = root_redirect(State(state)).await;
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            resp.headers().get(axum::http::header::LOCATION).unwrap(),
            "http://10.9.9.9:8687/"
        );
    }

    #[test]
    fn gossip_without_seen_field_parses() {
        let raw = serde_json::json!({
            "from": 1, "revision": 1,
            "nodes": [{"id": 1, "name": "n1"}],
            "edges": []
        });
        let msg: GossipMessage = serde_json::from_value(raw).expect("pre-M2.5 wire must parse");
        assert!(msg.seen.is_empty());
        assert!(msg.probes.is_empty());
    }

    // ---------- M2.8: domain addressing ----------

    #[test]
    fn nodeclient_strips_accidental_scheme() {
        assert_eq!(strip_scheme("10.0.0.9:8687"), "10.0.0.9:8687");
        assert_eq!(strip_scheme("http://10.0.0.9:8687"), "10.0.0.9:8687");
        assert_eq!(strip_scheme("https://docs.example.internal:8687"), "docs.example.internal:8687");
        assert_eq!(strip_scheme("  http://h:1  "), "h:1");
        // untouched when no scheme: a domain address passes through verbatim
        assert_eq!(strip_scheme("docs.example.internal:8687"), "docs.example.internal:8687");
    }

    #[tokio::test]
    async fn gossip_round_converges_two_nodes_by_domain() {
        // Same shape as gossip_round_converges_two_nodes, but the addresses
        // are the NAME "localhost" instead of an IP literal — proving the
        // resolver path end-to-end: reqwest resolves the name at dial time
        // (getaddrinfo), nothing in the config layer parses it as an IP.
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

        {
            let mut g = state_a.cfg.write().unwrap();
            g.nodes.push(NodeEntry {
                id: 2,
                name: "node-2".into(),
                public_key: None,
                address: Some(format!("localhost:{port_b}")), ssh: None,
            });
            g.recompute_hash();
        }
        {
            let mut g = state_b.cfg.write().unwrap();
            g.nodes.push(NodeEntry {
                id: 1,
                name: "node-1".into(),
                public_key: None,
                address: Some(format!("localhost:{port_a}")), ssh: None,
            });
            g.recompute_hash();
        }

        let client_a = NodeClient::new("test-secret".into(), 1);
        let res = gossip_round(&state_a, &client_a).await;
        assert_eq!(res.len(), 1);
        assert!(res[0].1.is_some(), "gossip by domain name should succeed");
        assert_eq!(state_a.cfg.read().unwrap().nodes.len(), 2);

        let client_b = NodeClient::new("test-secret".into(), 2);
        let res_b = gossip_round(&state_b, &client_b).await;
        assert!(res_b[0].1.is_some());
        assert_eq!(state_b.cfg.read().unwrap().nodes.len(), 2);
        assert!(
            state_b
                .cfg
                .read()
                .unwrap()
                .edges
                .iter()
                .any(|e| e.a == 1 && e.b == 2 && e.latency_ms.is_some()),
            "latency measured over the name-dialed path"
        );
    }

    #[tokio::test]
    async fn root_redirect_accepts_domain_address() {
        let mut cfg = NetworkConfig::bootstrap("s".into(), "n2".into());
        cfg.self_id = 2;
        cfg.nodes[0].id = 2;
        cfg.nodes.push(NodeEntry {
            id: 1,
            name: "n1".into(),
            public_key: None,
            address: Some("docs.example.internal:8687".into()), ssh: None,
        });
        cfg.recompute_hash();
        let state = Arc::new(NodeState::new(cfg));
        *state.parent.write().unwrap() = Some(1);

        let resp = root_redirect(State(state)).await;
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            resp.headers().get(axum::http::header::LOCATION).unwrap(),
            "http://docs.example.internal:8687/"
        );
    }

    // ---------- M2.8: forward-jump field merge ----------

    #[test]
    fn merge_node_entry_ssh_forward_fields_are_commutative() {
        let plain = crate::config::SshDial {
            host: "10.0.0.9".into(),
            port: 2222,
            user: "op".into(),
            forward_host: None,
            forward_port: None,
        };
        let jumped = crate::config::SshDial {
            host: "10.0.0.5".into(),
            port: 22,
            user: "root".into(),
            forward_host: Some("vps2.example.org".into()),
            forward_port: Some(8687),
        };
        let mk = |ssh| NodeEntry {
            id: 2,
            name: "n".into(),
            public_key: None,
            address: None,
            ssh: Some(ssh),
        };
        let a = mk(plain.clone());
        let b = mk(jumped.clone());

        let ab = merge_node_entry(&a, &b);
        let ba = merge_node_entry(&b, &a);
        assert_eq!(ab, ba, "forward-field merge must be commutative");
        // one-sided fill wins over None (admin intent union)
        assert_eq!(
            ab.ssh,
            Some(crate::config::SshDial {
                host: "10.0.0.9".into(),
                port: 2222,
                user: "root".into(),
                forward_host: Some("vps2.example.org".into()),
                forward_port: Some(8687),
            })
        );

        // conflicting forward fields resolve to the max, still commutative
        let other_jump = mk(crate::config::SshDial {
            host: "10.0.0.5".into(),
            port: 22,
            user: "root".into(),
            forward_host: Some("aaa.example.org".into()),
            forward_port: Some(9999),
        });
        let x = merge_node_entry(&b, &other_jump);
        let y = merge_node_entry(&other_jump, &b);
        assert_eq!(x, y);
        assert_eq!(x.ssh.as_ref().unwrap().forward_host.as_deref(), Some("vps2.example.org"));
        assert_eq!(x.ssh.as_ref().unwrap().forward_port, Some(9999));

        // legacy entries merge unchanged (forward stays None)
        let none_ssh = NodeEntry { id: 2, name: "n".into(), public_key: None, address: None, ssh: None };
        assert_eq!(
            merge_node_entry(&none_ssh, &mk(plain)).ssh,
            Some(crate::config::SshDial {
                host: "10.0.0.9".into(),
                port: 2222,
                user: "op".into(),
                forward_host: None,
                forward_port: None,
            })
        );
    }
}
