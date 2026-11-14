//! M3.5: local docker container state via the docker.sock HTTP API.
//!
//! Every node polls its OWN local docker daemon over the unix socket
//! (`GET /containers/json?all=1`) and shares the snapshot through gossip,
//! exactly like the M3.3 site probes and the M3.2 ssh matrix: one table
//! row per node id, LWW merge on `measured_at` (see merge_docker_probes).
//! Never persisted, never part of admin_hash.
//!
//! No docker CLI and no HTTP library: reqwest 0.11 cannot speak unix
//! sockets (that arrived in 0.12), and pulling hyper in for one endpoint
//! would betray the project's bare-socket precedent (M3.2 dropped russh
//! for a raw TcpStream). So this is a hand-rolled HTTP/1.0 GET over
//! `tokio::net::UnixStream` — verified against docker 29.7.2: the daemon
//! answers HTTP/1.0 WITHOUT chunked encoding and closes the connection
//! after the body, so "read to EOF" IS the framing. The request must not
//! be HTTP/1.1, or the daemon switches to Transfer-Encoding: chunked.
//!
//! A node without /var/run/docker.sock is NOT unhealthy: the daemon loop
//! (wired in M3.5-b) treats a missing socket as "feature not present on
//! this host" and stays quiet — the table simply has no row for it.

use crate::checks::chrono_pseudo::Ts;
use crate::config::NodeEntry;
use crate::transport::NodeState;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Unix-socket connect budget (same shape as sshmatrix::CONNECT_BUDGET).
pub const CONNECT_BUDGET: Duration = Duration::from_secs(3);
/// Whole-response budget: the daemon closes the socket after the body
/// (HTTP/1.0), so EOF must arrive well within this on a healthy host.
pub const READ_BUDGET: Duration = Duration::from_secs(3);
/// Docker API endpoint polled every tick: `all=1` includes stopped
/// containers — an exited container is a signal, not noise.
pub const LIST_PATH: &str = "/containers/json?all=1";
/// The docker daemon's unix socket (constant by the same policy as
/// selfstats::DISK_PATH: not worth a config knob, standard path everywhere).
pub const DOCKER_SOCK: &str = "/var/run/docker.sock";
/// Response body cap: a real host has a bounded number of containers;
/// this only guards against a pathological peer streaming forever.
const MAX_BODY_BYTES: u64 = 8 * 1024 * 1024;
/// Long error strings are truncated to this many characters in report lines
/// (same length as sshmatrix::REASON_SNIPPET).
const ERROR_SNIPPET: usize = 48;
/// Containers without a name render under this many Id characters
/// (the `docker ps` short-id convention).
const SHORT_ID_CHARS: usize = 12;

/// One container as observed on the polled host. `name` is `Names[0]`
/// with the leading `/` stripped (docker prefixes it); `state` is the
/// raw docker enum string (running/exited/paused/…); `status` is the
/// human-readable line ("Up 16 minutes (healthy)"); `health` is Some
/// only for real healthcheck states — healthy/unhealthy/starting —
/// while a missing Health field (old daemons) or "none" maps to None.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DockerContainer {
    pub name: String,
    pub state: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<String>,
}

/// A node's local docker snapshot as shared through gossip. Runtime-only
/// state: never persisted, never part of admin_hash (M3.3 policy). The
/// error field carries fetch/parse failures (e.g. permission denied on
/// hosts where the daemon user is not in the docker group) — an honest
/// report beats a missing row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DockerProbe {
    pub node_id: u32,
    pub measured_at: Ts,
    pub containers: Vec<DockerContainer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Latest local docker snapshot per node id. Each node writes ONLY its
/// own row; the merge keeps the freshest observation on every replica.
pub type DockerTable = HashMap<u32, DockerProbe>;

// ---------- parse ----------

/// Minimal projection of the docker list endpoint item: serde ignores
/// every other field (Image, Labels, Ports, Mounts, NetworkSettings…),
/// so API additions never break parsing. The wire keys are PascalCase
/// (`Id`, `Names`, `State`, …) and serde matching is case-sensitive —
/// without the rename every field silently falls back to its default
/// and every container renders as "unknown".
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawContainer {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    names: Option<Vec<String>>,
    #[serde(default)]
    state: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    health: Option<RawHealth>,
    // Kept to document the wire shape; not projected into DockerContainer.
    #[serde(default)]
    #[allow(dead_code)]
    created: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RawHealth {
    #[serde(default)]
    status: String,
}

/// "none" (and the empty string some daemons emit) is the absence of a
/// healthcheck — not a state worth gossiping.
fn normalize_health(raw: Option<RawHealth>) -> Option<String> {
    let status = raw?.status;
    match status.as_str() {
        "" | "none" => None,
        other => Some(other.to_string()),
    }
}

/// Name from `Names[0]` with the leading `/` stripped; when the daemon
/// reports no name, fall back to the conventional 12-char short Id.
fn container_name(raw: &RawContainer) -> String {
    if let Some(first) = raw.names.as_ref().and_then(|n| n.first()) {
        let trimmed = first.trim_start_matches('/');
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    raw.id
        .as_ref()
        .map(|id| id.chars().take(SHORT_ID_CHARS).collect())
        .unwrap_or_else(|| "unknown".into())
}

/// Pure parser for the `/containers/json?all=1` response body: no IO,
/// fully deterministic, fixture-testable. Errors on non-JSON bodies.
pub fn parse_docker_list(body: &str) -> Result<Vec<DockerContainer>> {
    let raw: Vec<RawContainer> =
        serde_json::from_str(body).map_err(|e| anyhow!("docker list JSON invalid: {e}"))?;
    Ok(raw
        .into_iter()
        .map(|c| DockerContainer {
            name: container_name(&c),
            state: c.state,
            status: c.status,
            health: normalize_health(c.health),
        })
        .collect())
}

// ---------- fetch ----------

/// One GET over the unix socket: HTTP/1.0 (no chunked — the daemon
/// closes after the body, EOF is the framing), 3s connect budget, 3s
/// whole-response budget. Returns the response body on status 200.
pub async fn fetch(sock_path: &str) -> Result<String> {
    let mut stream = tokio::time::timeout(CONNECT_BUDGET, UnixStream::connect(sock_path))
        .await
        .map_err(|_| anyhow!("docker socket {sock_path}: connect timeout after {}s", CONNECT_BUDGET.as_secs()))?
        .map_err(|e| anyhow!("docker socket {sock_path}: {e}"))?;

    let request = format!("GET {LIST_PATH} HTTP/1.0\r\nHost: localhost\r\n\r\n");
    tokio::time::timeout(CONNECT_BUDGET, stream.write_all(request.as_bytes()))
        .await
        .map_err(|_| anyhow!("docker socket {sock_path}: write timeout"))?
        .map_err(|e| anyhow!("docker socket {sock_path}: write failed: {e}"))?;

    let mut buf = Vec::new();
    // take() caps a runaway response; read_to_end stops at the daemon's
    // connection-close, which HTTP/1.0 framing guarantees after the body.
    let mut limited = stream.take(MAX_BODY_BYTES);
    tokio::time::timeout(READ_BUDGET, limited.read_to_end(&mut buf))
        .await
        .map_err(|_| anyhow!("docker socket {sock_path}: read timeout after {}s", READ_BUDGET.as_secs()))?
        .map_err(|e| anyhow!("docker socket {sock_path}: read failed: {e}"))?;

    let text = String::from_utf8_lossy(&buf);
    let (head, body) = text.split_once("\r\n\r\n").ok_or_else(|| {
        anyhow!("docker response: no header/body separator ({} bytes)", buf.len())
    })?;
    let status_code = head.split_whitespace().nth(1).unwrap_or("");
    if status_code != "200" {
        return Err(anyhow!("docker socket {sock_path}: HTTP status {status_code}"));
    }
    Ok(body.to_string())
}

// ---------- merge ----------

/// Merge incoming node snapshots: union of node ids, latest
/// `measured_at` wins per node. On an exact timestamp tie the
/// lexicographically larger serialized probe wins, making the merge
/// commutative and associative — both sides of an exchange converge to
/// the identical table in one round (same rules as sshmatrix).
pub fn merge_docker_probes(table: &std::sync::RwLock<DockerTable>, incoming: &[DockerProbe]) {
    let mut t = table.write().unwrap();
    for p in incoming {
        match t.get(&p.node_id) {
            None => {
                t.insert(p.node_id, p.clone());
            }
            Some(cur) => {
                let newer = p.measured_at.unix_ms() > cur.measured_at.unix_ms();
                let tie_break = p.measured_at.unix_ms() == cur.measured_at.unix_ms()
                    && serde_json::to_string(p).unwrap_or_default()
                        > serde_json::to_string(cur).unwrap_or_default();
                if newer || tie_break {
                    t.insert(p.node_id, p.clone());
                }
            }
        }
    }
}

/// Drop rows of node ids no longer present in the config view (a removed
/// node's snapshot must not render forever).
pub fn retain_known(table: &std::sync::RwLock<DockerTable>, known_ids: &HashSet<u32>) {
    table.write().unwrap().retain(|&id, _| known_ids.contains(&id));
}

// ---------- daemon loop ----------

/// The daemon's docker monitoring loop (production entry): polls the
/// standard socket every `net.docker_check_interval_secs`. See
/// `spawn_docker_loop_with_sock` for the tick shape.
pub fn spawn_docker_loop(state: Arc<NodeState>) -> Option<tokio::task::JoinHandle<()>> {
    spawn_docker_loop_with_sock(state, DOCKER_SOCK)
}

/// Injectable-socket variant for integration tests (a fake dockerd in a
/// tempdir, M3.5-c); production always goes through `spawn_docker_loop`.
/// `pub` because tests/ is a separate crate — `pub(crate)` would not
/// reach it; this is a pure test seam, no other callers expected.
///
/// Every tick: fetch + parse the local container list, record OUR OWN
/// snapshot into the shared table (it rides along with gossip), then
/// sweep rows of de-configured nodes. A host without the socket is NOT
/// unhealthy: the first miss logs one info line ("feature off on this
/// node"), later misses debug, and no row is ever written. Any other
/// error (socket present but daemon broken/permission denied) is a warn
/// plus an honest error row. 0 interval disables the loop (None + info).
pub fn spawn_docker_loop_with_sock(state: Arc<NodeState>, sock_path: &str) -> Option<tokio::task::JoinHandle<()>> {
    let (interval_secs, self_id) = {
        let g = state.cfg.read().unwrap();
        (g.net.docker_check_interval_secs, g.self_id)
    };
    if interval_secs == 0 {
        tracing::info!("docker monitoring disabled (net.docker_check_interval_secs = 0)");
        return None;
    }
    let sock = sock_path.to_string();
    Some(tokio::spawn(async move {
        tracing::info!(interval_secs, "docker loop starting");
        let mut tick = tokio::time::interval(Duration::from_secs(interval_secs.max(1)));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut missing_socket_announced = false;
        loop {
            tick.tick().await;
            let sock_present = std::path::Path::new(&sock).exists();
            if !sock_present {
                // feature not present on this host: stay quiet, no row
                if !missing_socket_announced {
                    tracing::info!("docker socket {sock} not found; container monitoring off on this node");
                    missing_socket_announced = true;
                } else {
                    tracing::debug!("docker socket {sock} still not found");
                }
            } else {
                let probe = match fetch(&sock).await {
                    Ok(body) => match parse_docker_list(&body) {
                        Ok(containers) => DockerProbe {
                            node_id: self_id,
                            measured_at: Ts::now(),
                            containers,
                            error: None,
                        },
                        Err(e) => {
                            tracing::warn!(error = %e, "docker list parse failed");
                            DockerProbe {
                                node_id: self_id,
                                measured_at: Ts::now(),
                                containers: Vec::new(),
                                error: Some(e.to_string()),
                            }
                        }
                    },
                    Err(e) => {
                        tracing::warn!(error = %e, "docker poll failed");
                        DockerProbe {
                            node_id: self_id,
                            measured_at: Ts::now(),
                            containers: Vec::new(),
                            error: Some(e.to_string()),
                        }
                    }
                };
                tracing::debug!(node = self_id, containers = probe.containers.len(), "docker poll done");
                state.record_own_docker_probe(probe);
            }
            // sweep rows of de-configured nodes (same as the ssh matrix)
            let known_ids: HashSet<u32> = {
                let g = state.cfg.read().unwrap();
                g.nodes.iter().map(|n| n.id).collect()
            };
            retain_known(&state.docker, &known_ids);
        }
    }))
}

// ---------- report ----------

fn age_str(now_ms: u64, at_ms: u64) -> String {
    let secs = now_ms.saturating_sub(at_ms) / 1000;
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else {
        format!("{}h ago", secs / 3600)
    }
}

fn error_snippet(r: &str) -> String {
    if r.chars().count() <= ERROR_SNIPPET {
        r.to_string()
    } else {
        let cut: String = r.chars().take(ERROR_SNIPPET).collect();
        format!("{cut}…")
    }
}

/// A container stands out with a `!` prefix when it is not running or
/// its healthcheck reports unhealthy — the two states a human scans for.
fn container_line(c: &DockerContainer) -> String {
    let mark = if c.state != "running" || c.health.as_deref() == Some("unhealthy") {
        "!"
    } else {
        ""
    };
    match &c.health {
        Some(h) => format!("{mark}{}: {} ({})", c.name, c.state, h),
        None => format!("{mark}{}: {}", c.name, c.state),
    }
}

/// Render one line per node that HAS a docker row, sorted by node id:
/// `  d1337: searxng: running, !old: exited (unhealthy) [45s ago]`.
/// A probe that failed outright renders its error instead of pretending
/// there are no containers; the age bracket is the honesty signal — a
/// dead node's row goes stale in place, like the ssh matrix.
/// Data-only; alerts are M3.7. Empty when no node reported anything.
pub fn build_docker_report(nodes: &[NodeEntry], table: &DockerTable, now_ms: u64) -> Vec<String> {
    if table.is_empty() {
        return Vec::new();
    }
    let name_of = |id: u32| -> String {
        nodes
            .iter()
            .find(|n| n.id == id)
            .map(|n| n.name.clone())
            .unwrap_or_else(|| format!("node-{id}"))
    };
    let mut ids: Vec<u32> = table.keys().copied().collect();
    ids.sort_unstable();
    ids.into_iter()
        .map(|id| {
            let p = &table[&id];
            let age = age_str(now_ms, p.measured_at.unix_ms());
            let summary = match (&p.containers, &p.error) {
                (containers, Some(err)) if containers.is_empty() => {
                    format!("error: {}", error_snippet(err))
                }
                (containers, _) => containers
                    .iter()
                    .map(container_line)
                    .collect::<Vec<_>>()
                    .join(", "),
            };
            format!("  {}: {summary} [{age}]", name_of(id))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::RwLock;

    // ---------- fixtures ----------

    /// Compact but faithful slice of the live d1337 answer (docker
    /// 29.7.2, API 1.55, captured 2026-11-14): real Ids/Names/States/
    /// Statuses/Healths of all 7 containers; the extra fields on the
    /// first element (Image, Ports, Labels) verify serde ignores them.
    const LIVE_BODY: &str = r#"[
      {"Id":"1453ab53b707112fdac5b110e5a125816f5d183cdb6a9e550a7f1e7aa6230b21","Names":["/searxng"],"Image":"searxng/searxng:latest","Ports":[{"IP":"127.0.0.1","PrivatePort":8080,"PublicPort":8888,"Type":"tcp"}],"Labels":{"com.docker.compose.project":"searxng"},"State":"running","Status":"Up 22 minutes","Health":{"Status":"none","FailingStreak":0},"Created":1794328855},
      {"Id":"8bd5ab5d1a7e5c96e143daaf7b2305b50cf99379914ecf4c67346773f45d58d7","Names":["/searxng-redis"],"State":"running","Status":"Up 22 minutes","Health":{"Status":"none","FailingStreak":0},"Created":1794328853},
      {"Id":"aef68c7693f19436849d84926969ffbd2d4f23d708de6729816500af28fabf61","Names":["/npm"],"State":"running","Status":"Up 22 minutes","Health":{"Status":"none","FailingStreak":0},"Created":1793491437},
      {"Id":"06e65d50894b5deaf8b4a9bf8ddafb421f90fd0d1f0157dfe1d7b4579180f758","Names":["/tuwunel"],"State":"running","Status":"Up 22 minutes (healthy)","Health":{"Status":"healthy","FailingStreak":0},"Created":1793490413},
      {"Id":"e5d8cb828b0c1d13cc32c1a9744288447e08978869993f130fd4ec9dc8a0ba9f","Names":["/samba"],"State":"running","Status":"Up 22 minutes (healthy)","Health":{"Status":"healthy","FailingStreak":0},"Created":1790116781},
      {"Id":"ebee0dd678c789b6656b2c6c89c3ee28e539516f6c7858c4190878ef07c3c0f2","Names":["/nextcloud-app"],"State":"running","Status":"Up 22 minutes","Health":{"Status":"none","FailingStreak":0},"Created":1788114634},
      {"Id":"63772a7bacef45a5a50da631735c8d530a6da0741530a1088da406a7371370fb","Names":["/nextcloud-db"],"State":"running","Status":"Up 22 minutes","Health":{"Status":"none","FailingStreak":0},"Created":1788114629}
    ]"#;

    fn node(id: u32, name: &str) -> NodeEntry {
        NodeEntry { id, name: name.into(), public_key: None, address: None, ssh: None }
    }

    fn probe_of(node_id: u32, at_ms: u64, names: &[&str]) -> DockerProbe {
        DockerProbe {
            node_id,
            measured_at: Ts(at_ms),
            containers: names
                .iter()
                .map(|n| DockerContainer {
                    name: (*n).into(),
                    state: "running".into(),
                    status: "Up 1 minute".into(),
                    health: None,
                })
                .collect(),
            error: None,
        }
    }

    // ---------- parse ----------

    #[test]
    fn parse_live_sample_all_seven_containers() {
        let cs = parse_docker_list(LIVE_BODY).unwrap();
        assert_eq!(cs.len(), 7, "d1337 fixture has 7 containers");
        // leading '/' stripped everywhere
        assert_eq!(cs[0].name, "searxng");
        assert_eq!(cs[4].name, "samba");
        assert_eq!(cs[6].name, "nextcloud-db");
        // health normalization: "none" -> None, "healthy" -> Some
        assert_eq!(cs[0].health, None);
        assert_eq!(cs[3].health.as_deref(), Some("healthy"));
        assert_eq!(cs[4].health.as_deref(), Some("healthy"));
        // raw fields kept as-is
        assert_eq!(cs[0].state, "running");
        assert_eq!(cs[3].status, "Up 22 minutes (healthy)");
        // deterministic order preserved (API order is stable per call)
        assert_eq!(cs.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), vec![
            "searxng", "searxng-redis", "npm", "tuwunel", "samba", "nextcloud-app", "nextcloud-db"
        ]);
    }

    #[test]
    fn parse_strips_slash_and_maps_health_states() {
        let body = r#"[
            {"Id":"aaaa00000000000000000000000000000000000000000000000000000000ffff","Names":["/web"],"State":"exited","Status":"Exited (1) 2 minutes ago","Health":{"Status":"unhealthy","FailingStreak":3}},
            {"Id":"bbbb00000000000000000000000000000000000000000000000000000000ffff","Names":["/booting"],"State":"running","Status":"Up 3 seconds","Health":{"Status":"starting","FailingStreak":0}}
        ]"#;
        let cs = parse_docker_list(body).unwrap();
        assert_eq!(cs[0].name, "web", "leading slash must be stripped");
        assert_eq!(cs[0].health.as_deref(), Some("unhealthy"));
        assert_eq!(cs[1].health.as_deref(), Some("starting"), "starting is a real state, kept");
        assert_eq!(cs[0].state, "exited");
    }

    #[test]
    fn parse_without_health_field_old_daemons() {
        // old docker omits Health entirely when no healthcheck is set
        let body = r#"[{"Id":"c1","Names":["/legacy"],"State":"running","Status":"Up 4 hours"}]"#;
        let cs = parse_docker_list(body).unwrap();
        assert_eq!(cs.len(), 1);
        assert_eq!(cs[0].health, None, "missing Health field -> None");
        assert_eq!(cs[0].name, "legacy");
    }

    #[test]
    fn parse_empty_array_is_ok() {
        assert!(parse_docker_list("[]").unwrap().is_empty());
    }

    #[test]
    fn parse_garbage_is_err() {
        assert!(parse_docker_list("<html>502 Bad Gateway</html>").is_err());
        assert!(parse_docker_list("{\"message\":\"page not found\"}").is_err(), "object, not array");
        assert!(parse_docker_list("").is_err());
    }

    #[test]
    fn parse_names_empty_falls_back_to_short_id() {
        let body = r#"[{"Id":"1453ab53b707112fdac5b110e5a125816f5d183cdb6a9e550a7f1e7aa6230b21","Names":[],"State":"paused","Status":"Up 2 hours (Paused)"}]"#;
        let cs = parse_docker_list(body).unwrap();
        assert_eq!(cs[0].name, "1453ab53b707", "docker ps short-id convention");
        // and with neither Names nor Id: not a crash, a placeholder
        let anon = parse_docker_list(r#"[{"State":"running","Status":"Up"}]"#).unwrap();
        assert_eq!(anon[0].name, "unknown");
    }

    // ---------- serde ----------

    #[test]
    fn docker_probe_serde_roundtrip() {
        let p = DockerProbe {
            node_id: 7,
            measured_at: Ts(1_700_000_123_456),
            containers: vec![DockerContainer {
                name: "searxng".into(),
                state: "running".into(),
                status: "Up 22 minutes".into(),
                health: Some("healthy".into()),
            }],
            error: Some("permission denied".into()),
        };
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(serde_json::from_str::<DockerProbe>(&json).unwrap(), p);
        // error omitted when None (smaller gossip payloads)
        let clean = serde_json::to_string(&probe_of(1, 5, &["a"])).unwrap();
        assert!(!clean.contains("error"), "got: {clean}");
        // legacy/foreign JSON without health parses to None
        let no_health = r#"{"name":"x","state":"running","status":"Up"}"#;
        assert_eq!(serde_json::from_str::<DockerContainer>(no_health).unwrap().health, None);
    }

    // ---------- merge ----------

    fn table_of(list: &[DockerProbe]) -> DockerTable {
        list.iter().map(|p| (p.node_id, p.clone())).collect()
    }

    fn sorted_rows(t: &RwLock<DockerTable>) -> Vec<DockerProbe> {
        let mut v: Vec<DockerProbe> = t.read().unwrap().values().cloned().collect();
        v.sort_by_key(|p| p.node_id);
        v
    }

    #[test]
    fn merge_docker_probes_commutative_lww() {
        let a = vec![
            probe_of(1, 1_000, &["searxng"]),
            probe_of(2, 900, &["npm"]),
        ];
        let b = vec![
            probe_of(1, 1_500, &["searxng", "samba"]), // newer wins
            probe_of(3, 1_200, &["tuwunel"]),          // new key: union
        ];
        let ta = RwLock::new(table_of(&a));
        let tb = RwLock::new(table_of(&b));
        merge_docker_probes(&ta, &b);
        merge_docker_probes(&tb, &a);

        let (va, vb) = (sorted_rows(&ta), sorted_rows(&tb));
        assert_eq!(va, vb, "merge must be commutative");
        assert_eq!(va.len(), 3, "union of node ids");
        let g = ta.read().unwrap();
        assert_eq!(g.get(&1).unwrap().measured_at.unix_ms(), 1_500, "latest wins");
        assert_eq!(g.get(&1).unwrap().containers.len(), 2, "content flips on newer data");
    }

    #[test]
    fn merge_docker_probes_tie_breaks_deterministically() {
        // same node, same timestamp, different content: the larger
        // serialized form wins on BOTH sides regardless of merge order
        let mut x = probe_of(1, 5_000, &["aaa"]);
        x.error = Some("aaa".into());
        let mut y = probe_of(1, 5_000, &["zzz"]);
        y.error = Some("zzz".into());
        let ta = RwLock::new(DockerTable::from([(1, x.clone())]));
        let tb = RwLock::new(DockerTable::from([(1, y.clone())]));
        merge_docker_probes(&ta, std::slice::from_ref(&y));
        merge_docker_probes(&tb, std::slice::from_ref(&x));
        assert_eq!(sorted_rows(&ta), sorted_rows(&tb), "tie must resolve identically");
    }

    #[test]
    fn retain_known_drops_removed_nodes() {
        let t = RwLock::new(DockerTable::from([
            (1, probe_of(1, 100, &["a"])),
            (2, probe_of(2, 100, &["b"])),
            (3, probe_of(3, 100, &["c"])),
        ]));
        retain_known(&t, &HashSet::from([1, 2]));
        let g = t.read().unwrap();
        assert_eq!(g.len(), 2, "only node 3 is unknown — rows 1 and 2 stay");
        assert!(g.contains_key(&1));
        assert!(g.contains_key(&2));
        assert!(!g.contains_key(&3), "rows of node 3 must be swept");
    }

    // ---------- report ----------

    const NOW: u64 = 1_700_000_000_000;

    #[test]
    fn docker_report_renders_state_health_and_age() {
        let mut probe = probe_of(1, NOW - 45_000, &["searxng", "npm"]);
        probe.containers[0].health = Some("healthy".into());
        probe.containers[1].state = "exited".into();
        probe.containers[1].status = "Exited (1) 5 minutes ago".into();
        let mut probe2 = probe_of(2, NOW - 5_000, &["tuwunel"]);
        probe2.containers[0].health = Some("unhealthy".into());
        let table = DockerTable::from([(2, probe2), (1, probe)]);
        let nodes = vec![node(1, "d1337"), node(2, "vps2")];
        let lines = build_docker_report(&nodes, &table, NOW);

        assert_eq!(lines.len(), 2, "one line per reporting node: {lines:?}");
        assert!(lines[0].starts_with("  d1337: searxng: running (healthy), !npm: exited [45s ago]"), "got: {lines:?}");
        assert!(
            lines[1].contains("vps2: !tuwunel: running (unhealthy)") && lines[1].contains("[5s ago]"),
            "unhealthy must stand out: {lines:?}"
        );
        // sorted by node id regardless of table iteration order
        assert!(lines[0].contains("d1337") && lines[1].contains("vps2"));
    }

    #[test]
    fn docker_report_error_row_and_empty_table() {
        let err_probe = DockerProbe {
            node_id: 2,
            measured_at: Ts(NOW - 3_000),
            containers: vec![],
            error: Some("docker socket /var/run/docker.sock: permission denied".into()),
        };
        let nodes = vec![node(1, "d1337"), node(2, "vps2"), node(3, "ghost")];
        let lines = build_docker_report(&nodes, &DockerTable::from([(2, err_probe)]), NOW);
        assert_eq!(lines.len(), 1, "only the reporting node renders: {lines:?}");
        assert!(
            lines[0].contains("vps2: error: docker socket /var/run/docker.sock: permission"),
            "got: {lines:?}"
        );
        assert!(lines[0].contains("[3s ago]"), "got: {lines:?}");

        // empty table renders nothing (the caller decides on "(no data)")
        assert!(build_docker_report(&nodes, &DockerTable::new(), NOW).is_empty());

        // unknown node id still renders with a stable fallback name
        let orphan = DockerTable::from([(9, probe_of(9, NOW, &["x"]))]);
        let lines = build_docker_report(&nodes, &orphan, NOW);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("node-9"), "got: {lines:?}");
    }

    // ---------- fetch (fake dockerd over a real unix socket) ----------

    fn sock_dir(tag: &str) -> std::path::PathBuf {
        // fresh dir per test run: a leftover socket file would make
        // UnixListener::bind fail with EADDRINUSE
        let d = std::env::temp_dir().join(format!("em-m35a-docker-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Fake dockerd: accepts one connection per loop turn, drains the
    /// request (a single read is enough — the GET arrives in one piece),
    /// answers with real d1337 headers + body, then drops the stream so
    /// the client sees the HTTP/1.0 EOF framing.
    async fn spawn_fake_dockerd(
        dir: &std::path::Path,
        tag: &str,
        status_line: &'static str,
        body: &'static str,
    ) -> std::path::PathBuf {
        let path = dir.join(format!("{tag}.sock"));
        let l = tokio::net::UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = l.accept().await {
                let mut req = [0u8; 1024];
                let _ = sock.read(&mut req).await;
                let resp = format!(
                    "{status_line}\r\nApi-Version: 1.55\r\nContent-Type: application/json\r\nServer: Docker/29.7.2 (linux)\r\n\r\n{body}"
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                // drop -> close -> EOF for the reader
            }
        });
        path
    }

    #[tokio::test]
    async fn fetch_reads_body_from_fake_dockerd() {
        let dir = sock_dir("ok");
        let body = r#"[{"Id":"deadbeef","Names":["/fake"],"State":"running","Status":"Up 1 second"}]"#;
        let sock = spawn_fake_dockerd(&dir, "ok", "HTTP/1.0 200 OK", body).await;
        let got = fetch(sock.to_str().unwrap()).await.unwrap();
        assert_eq!(got, body, "fetch must return exactly the response body");
        // and it feeds the parser end to end
        let cs = parse_docker_list(&got).unwrap();
        assert_eq!(cs[0].name, "fake");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn fetch_missing_socket_is_err() {
        // a temp path with NO listener: ENOENT must surface as Err
        // (the daemon loop turns this into "docker not present", M3.5-b)
        let dir = sock_dir("missing");
        let sock = dir.join("nope.sock");
        let err = fetch(sock.to_str().unwrap()).await.unwrap_err();
        assert!(
            err.to_string().contains("nope.sock"),
            "error must name the socket: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn fetch_non_200_is_err() {
        let dir = sock_dir("err500");
        let sock = spawn_fake_dockerd(&dir, "err500", "HTTP/1.0 500 Internal Server Error", "oops").await;
        let err = fetch(sock.to_str().unwrap()).await.unwrap_err();
        assert!(err.to_string().contains("500"), "got: {err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------- daemon loop ----------

    #[test]
    fn docker_loop_disabled_returns_none() {
        // 0 interval: the loop must not spawn at all (and this test must
        // never touch the real /var/run/docker.sock — the None branch
        // returns before any task exists).
        let mut cfg = crate::config::NetworkConfig::bootstrap("s".into(), "n1".into());
        cfg.net.docker_check_interval_secs = 0;
        let state = Arc::new(NodeState::new(cfg));
        assert!(spawn_docker_loop(state).is_none());
        // the default cadence is on, so a plain bootstrap would have spawned
        assert_eq!(crate::config::DEFAULT_DOCKER_CHECK_INTERVAL_SECS, 60);
    }
}
