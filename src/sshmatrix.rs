//! M3.2: directed SSH-availability matrix between mesh nodes.
//!
//! Every node probes the system sshd of every OTHER node that has an
//! `[[nodes]].ssh` dial config — a cheap TCP connect (3s budget) plus one
//! banner read (2s budget, the sshd speaks first per RFC 4253). No
//! authentication, no russh: fail2ban looks at auth failures, not at
//! connects, and one attempt per minute per pair is zero noise.
//!
//! Directionality is the point: the pair (from→to) is measured ONLY by
//! `from`, no coordinator, no assignment rule that breaks when a node
//! dies. A→B alive while B→A is cut is exactly the asymmetric-reachability
//! case this project exists for (TSPU-style filtering); a dead `from`
//! simply lets its rows go stale — an honest signal, rendered as [STALE].
//!
//! Results are runtime-only state shared through gossip, exactly like the
//! M3.3 site probes: latest per (from, to) in a table on every node, LWW
//! merge on `measured_at` (see merge_ssh_probes). Never persisted, never
//! part of admin_hash. Nodes configured with a jump
//! (`ssh.forward_host`/`forward_port`, M2.8) are skipped — a direct TCP
//! probe at their ssh.host is expected to fail by design; the report
//! marks them "via jump (not probed)". Probing through the tunnel is a
//! future milestone.

use crate::checks::{chrono_pseudo::Ts, CheckOutcome};
use crate::config::NodeEntry;
use crate::sitereport::STALE_FACTOR;
use crate::transport::NodeState;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// TCP connect budget per target (ABOUT.md "cheap frequent attempts").
pub const CONNECT_BUDGET: Duration = Duration::from_secs(3);
/// Banner read budget: the identification string must arrive within this.
pub const BANNER_BUDGET: Duration = Duration::from_secs(2);
/// Banner reads stop at this many bytes even without a newline.
const BANNER_MAX_BYTES: usize = 256;
/// Stored banners are truncated to this many characters.
const BANNER_MAX_CHARS: usize = 64;
/// Long fail reasons are truncated to this many characters in report lines.
const REASON_SNIPPET: usize = 48;

/// SSH-availability of node `to` as observed by node `from`. Runtime-only:
/// never persisted, never part of admin_hash (M3.3 policy).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SshProbe {
    pub from: u32,
    pub to: u32,
    pub measured_at: Ts,
    /// Ok{latency_ms} = TCP connect (+banner attempt) succeeded;
    /// Fail{reason} = refused / timeout / read error.
    pub outcome: CheckOutcome,
    /// First line the sshd sent (RFC 4253 identification string),
    /// truncated; None when the peer never sent one within budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
}

/// Latest probe per directed (from, to) pair.
pub type SshMatrix = HashMap<(u32, u32), SshProbe>;

/// Is this node entry a jump target (M2.8), i.e. NOT directly probeable?
fn is_jump(n: &NodeEntry) -> bool {
    n.ssh
        .as_ref()
        .is_some_and(|s| s.forward_host.is_some() || s.forward_port.is_some())
}

/// One probe: TCP connect + banner read, both under hard budgets.
/// Latency covers connect only (banner wait is not the sshd's fault).
pub async fn ssh_probe(from: u32, to: u32, host: &str, port: u16) -> SshProbe {
    let started = Instant::now();
    let (outcome, banner) = match tokio::time::timeout(CONNECT_BUDGET, TcpStream::connect((host, port))).await {
        Err(_) => (
            CheckOutcome::Fail { reason: format!("connect timeout after {}s to {host}:{port}", CONNECT_BUDGET.as_secs()) },
            None,
        ),
        Ok(Err(e)) => (CheckOutcome::Fail { reason: format!("connect {host}:{port} failed: {e}") }, None),
        Ok(Ok(mut stream)) => {
            let latency_ms = started.elapsed().as_millis() as u64;
            let mut buf = vec![0u8; BANNER_MAX_BYTES];
            match tokio::time::timeout(BANNER_BUDGET, stream.read(&mut buf)).await {
                // The sshd stayed silent: TCP works, that is already Ok.
                Err(_) => (CheckOutcome::Ok { latency_ms }, None),
                // EOF before any bytes: TCP accepted then closed. Still a
                // working TCP path; no banner to show.
                Ok(Ok(0)) => (CheckOutcome::Ok { latency_ms }, None),
                Ok(Ok(n)) => (CheckOutcome::Ok { latency_ms }, Some(banner_line(&buf[..n]))),
                Ok(Err(e)) => (CheckOutcome::Fail { reason: format!("banner read from {host}:{port} failed: {e}") }, None),
            }
        }
    };
    SshProbe { from, to, measured_at: Ts::now(), outcome, banner }
}

/// First line of the raw banner bytes, lossy-decoded, trimmed, truncated.
fn banner_line(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let first = text.lines().next().unwrap_or("").trim();
    first.chars().take(BANNER_MAX_CHARS).collect()
}

/// Merge incoming matrix rows: union of keys, latest `measured_at` wins
/// per (from, to). On an exact timestamp tie the lexicographically larger
/// serialized probe wins, making the merge commutative and associative —
/// both sides of an exchange converge to the identical table in one round
/// (same rules as transport::merge_probes).
pub fn merge_ssh_probes(table: &std::sync::RwLock<SshMatrix>, incoming: &[SshProbe]) {
    let mut t = table.write().unwrap();
    for p in incoming {
        match t.get(&(p.from, p.to)) {
            None => {
                t.insert((p.from, p.to), p.clone());
            }
            Some(cur) => {
                let newer = p.measured_at.unix_ms() > cur.measured_at.unix_ms();
                let tie_break = p.measured_at.unix_ms() == cur.measured_at.unix_ms()
                    && serde_json::to_string(p).unwrap_or_default()
                        > serde_json::to_string(cur).unwrap_or_default();
                if newer || tie_break {
                    t.insert((p.from, p.to), p.clone());
                }
            }
        }
    }
}

/// Drop rows referencing node ids no longer present in the config view
/// (a removed node's rows must not render forever).
pub fn retain_known(table: &std::sync::RwLock<SshMatrix>, known_ids: &HashSet<u32>) {
    table
        .write()
        .unwrap()
        .retain(|&(f, t), _| known_ids.contains(&f) && known_ids.contains(&t));
}

/// The daemon's directed-matrix loop: every `net.ssh_check_interval_secs`
/// (0 = disabled, returns None) probe every non-self, non-jump node that
/// has an ssh dial config, record the result in the shared state, and
/// sweep rows of de-configured nodes. Targets are snapshotted under a
/// short read lock each tick, so config changes apply on the next tick.
/// Aborting the returned task stops this node's probing — its rows go
/// stale on the survivors, which is the honest signal by design.
pub fn spawn_ssh_matrix_loop(state: Arc<NodeState>) -> Option<tokio::task::JoinHandle<()>> {
    let (interval_secs, self_id) = {
        let g = state.cfg.read().unwrap();
        (g.net.ssh_check_interval_secs, g.self_id)
    };
    if interval_secs == 0 {
        tracing::info!("ssh matrix disabled (net.ssh_check_interval_secs = 0)");
        return None;
    }
    Some(tokio::spawn(async move {
        tracing::info!(interval_secs, "ssh matrix loop starting");
        let mut tick = tokio::time::interval(Duration::from_secs(interval_secs.max(1)));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let (targets, known_ids) = {
                let g = state.cfg.read().unwrap();
                let known_ids: HashSet<u32> = g.nodes.iter().map(|n| n.id).collect();
                // (to, host, port): pair (from→to) is measured by `from` —
                // jump targets are excluded, the report marks them.
                let targets: Vec<(u32, String, u16)> = g
                    .nodes
                    .iter()
                    .filter(|n| n.id != self_id && n.ssh.is_some() && !is_jump(n))
                    .map(|n| {
                        let s = n.ssh.as_ref().expect("filtered above");
                        (n.id, s.host.clone(), s.port)
                    })
                    .collect();
                (targets, known_ids)
            };
            for (to, host, port) in targets {
                let probe = ssh_probe(self_id, to, &host, port).await;
                tracing::debug!(from = self_id, to, "ssh probe done");
                state.record_own_ssh_probe(probe);
            }
            retain_known(&state.ssh_matrix, &known_ids);
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

fn reason_snippet(r: &str) -> String {
    if r.chars().count() <= REASON_SNIPPET {
        r.to_string()
    } else {
        let cut: String = r.chars().take(REASON_SNIPPET).collect();
        format!("{cut}…")
    }
}

fn outcome_brief(p: &SshProbe) -> String {
    match &p.outcome {
        CheckOutcome::Ok { latency_ms } => match &p.banner {
            Some(b) => format!("OK {latency_ms}ms — {b}"),
            None => format!("OK {latency_ms}ms"),
        },
        CheckOutcome::Fail { reason } => format!("FAIL — {}", reason_snippet(reason)),
        CheckOutcome::Unknown { reason } => format!("UNKNOWN — {}", reason_snippet(reason)),
    }
}

/// Render the directed matrix, one line per (from→to) pair over nodes
/// that HAVE an ssh dial config, sorted by (from, to); plus an
/// ASYMMETRIC block for pairs where both directions are fresh and their
/// outcomes differ — the headline TSPU signal. Data-only; alerts are M3.7.
/// Pairs whose target is behind a jump render "via jump (not probed)"
/// straight from the config. Rows for pairs absent from the config view
/// (removed nodes) never render. Empty when no node has ssh config.
pub fn build_ssh_report(
    nodes: &[NodeEntry],
    matrix: &SshMatrix,
    now_ms: u64,
    interval_secs: u64,
) -> Vec<String> {
    let stale_after_ms = interval_secs.max(1) * 1000 * STALE_FACTOR;
    let targets: Vec<&NodeEntry> = nodes.iter().filter(|n| n.ssh.is_some()).collect();
    if targets.is_empty() {
        return Vec::new();
    }
    let name_of = |id: u32| -> String {
        nodes
            .iter()
            .find(|n| n.id == id)
            .map(|n| n.name.clone())
            .unwrap_or_else(|| format!("node-{id}"))
    };
    // iterate deterministically regardless of config order
    let mut froms: Vec<&NodeEntry> = nodes.iter().collect();
    froms.sort_by_key(|n| n.id);
    let mut sorted_targets = targets.clone();
    sorted_targets.sort_by_key(|n| n.id);

    let mut out = Vec::new();
    for from in &froms {
        for to in &sorted_targets {
            if to.id == from.id {
                continue;
            }
            let s = to.ssh.as_ref().expect("filtered above");
            let label = format!("  {} -> {} ({}:{})", from.name, to.name, s.host, s.port);
            if is_jump(to) {
                out.push(format!("{label}: via jump (not probed)"));
                continue;
            }
            match matrix.get(&(from.id, to.id)) {
                None => out.push(format!("{label}: no data yet")),
                Some(p) => {
                    let stale = now_ms.saturating_sub(p.measured_at.unix_ms()) > stale_after_ms;
                    let tag = if stale { " STALE" } else { "" };
                    out.push(format!(
                        "{label}: {} [{}{}]",
                        outcome_brief(p),
                        age_str(now_ms, p.measured_at.unix_ms()),
                        tag
                    ));
                }
            }
        }
    }

    // ASYMMETRIC: both directions fresh, outcome classes differ.
    for a in &sorted_targets {
        for b in &sorted_targets {
            if b.id <= a.id {
                continue;
            }
            let ab = matrix.get(&(a.id, b.id));
            let ba = matrix.get(&(b.id, a.id));
            let (Some(ab), Some(ba)) = (ab, ba) else { continue };
            let fresh = |p: &SshProbe| now_ms.saturating_sub(p.measured_at.unix_ms()) <= stale_after_ms;
            if !fresh(ab) || !fresh(ba) {
                continue;
            }
            let differs = matches!(
                (&ab.outcome, &ba.outcome),
                (CheckOutcome::Ok { .. }, CheckOutcome::Fail { .. })
                    | (CheckOutcome::Fail { .. }, CheckOutcome::Ok { .. })
            );
            if differs {
                out.push(format!(
                    "! {} <-> {} ASYMMETRIC: {}->{}, {}->{}",
                    name_of(a.id),
                    name_of(b.id),
                    a.id,
                    short_class(ab),
                    b.id,
                    short_class(ba),
                ));
            }
        }
    }
    out
}

/// One-word outcome class for the ASYMMETRIC line ("OK"/"FAIL"/"UNKNOWN").
fn short_class(p: &SshProbe) -> &'static str {
    match p.outcome {
        CheckOutcome::Ok { .. } => "OK",
        CheckOutcome::Fail { .. } => "FAIL",
        CheckOutcome::Unknown { .. } => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SshDial;
    use std::sync::RwLock;
    use tokio::io::AsyncWriteExt;

    fn node(id: u32, name: &str, ssh: Option<SshDial>) -> NodeEntry {
        NodeEntry { id, name: name.into(), public_key: None, address: None, ssh }
    }

    fn dial(host: &str, port: u16) -> Option<SshDial> {
        Some(SshDial { host: host.into(), port, user: "op".into(), forward_host: None, forward_port: None })
    }

    /// Fake sshd: accepts connections and writes one banner line, then
    /// closes. With `banner = None` it accepts and stays silent (holding
    /// the connection open until the prober gives up) — the
    /// banner-timeout case.
    async fn spawn_fake_sshd(banner: Option<&'static str>) -> u16 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = l.accept().await else { return };
                if let Some(b) = banner {
                    let _ = sock.write_all(b.as_bytes()).await;
                } else {
                    // hold the connection open in silence until the
                    // peer closes (a truly mute endpoint)
                    let _ = sock.read(&mut [0u8; 1]).await;
                }
            }
        });
        port
    }

    fn probe_of(from: u32, to: u32, at_ms: u64, outcome: CheckOutcome) -> SshProbe {
        SshProbe { from, to, measured_at: Ts(at_ms), outcome, banner: None }
    }

    fn matrix_of(list: &[SshProbe]) -> SshMatrix {
        list.iter().map(|p| ((p.from, p.to), p.clone())).collect()
    }

    // ---------- probe ----------

    #[tokio::test]
    async fn ssh_probe_ok_captures_banner() {
        let port = spawn_fake_sshd(Some("SSH-2.0-FAKE_1.0\r\n")).await;
        let p = ssh_probe(1, 2, "127.0.0.1", port).await;
        assert_eq!((p.from, p.to), (1, 2));
        assert_eq!(p.banner.as_deref(), Some("SSH-2.0-FAKE_1.0"), "banner: {:?}", p.banner);
        match p.outcome {
            CheckOutcome::Ok { latency_ms } => assert!(latency_ms < 1000, "loopback connect must be fast"),
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn ssh_probe_fail_refused() {
        // bind then drop = connection refused
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        let p = ssh_probe(1, 2, "127.0.0.1", port).await;
        match &p.outcome {
            CheckOutcome::Fail { reason } => assert!(reason.contains("connect"), "got: {reason}"),
            other => panic!("expected Fail, got {other:?}"),
        }
        assert!(p.banner.is_none());
    }

    #[tokio::test]
    async fn ssh_probe_connect_timeout_budget() {
        // unroutable TEST-NET address: must fail within the connect budget
        let started = Instant::now();
        let p = ssh_probe(1, 2, "192.0.2.1", 1).await;
        assert!(matches!(p.outcome, CheckOutcome::Fail { .. }), "got: {:?}", p.outcome);
        assert!(
            started.elapsed() < Duration::from_secs(6),
            "connect budget must hold (elapsed {:?})",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn ssh_probe_banner_timeout_still_ok() {
        // peer accepts but never speaks: TCP works -> Ok, banner None
        let port = spawn_fake_sshd(None).await;
        let started = Instant::now();
        let p = ssh_probe(1, 2, "127.0.0.1", port).await;
        assert!(matches!(p.outcome, CheckOutcome::Ok { .. }), "got: {:?}", p.outcome);
        assert!(p.banner.is_none());
        assert!(
            started.elapsed() >= BANNER_BUDGET,
            "the banner wait must actually be awaited"
        );
    }

    // ---------- merge ----------

    fn sorted_rows(t: &RwLock<SshMatrix>) -> Vec<SshProbe> {
        let mut v: Vec<SshProbe> = t.read().unwrap().values().cloned().collect();
        v.sort_by_key(|p| (p.from, p.to));
        v
    }

    #[test]
    fn merge_ssh_probes_commutative_lww() {
        let a = vec![
            probe_of(1, 2, 1_000, CheckOutcome::Ok { latency_ms: 10 }),
            probe_of(1, 3, 900, CheckOutcome::Ok { latency_ms: 20 }),
            probe_of(2, 1, 800, CheckOutcome::Fail { reason: "old".into() }),
        ];
        let b = vec![
            probe_of(1, 2, 1_500, CheckOutcome::Ok { latency_ms: 11 }), // newer wins
            probe_of(3, 1, 1_200, CheckOutcome::Ok { latency_ms: 30 }), // new key: union
            probe_of(2, 1, 900, CheckOutcome::Ok { latency_ms: 40 }),   // newer flips outcome
        ];
        let ta = RwLock::new(matrix_of(&a));
        let tb = RwLock::new(matrix_of(&b));
        merge_ssh_probes(&ta, &b);
        merge_ssh_probes(&tb, &a);

        let (va, vb) = (sorted_rows(&ta), sorted_rows(&tb));
        assert_eq!(va, vb, "merge must be commutative");
        assert_eq!(va.len(), 4, "union of keys: 1->2, 1->3, 2->1, 3->1");
        let t = ta.read().unwrap();
        assert_eq!(t.get(&(1, 2)).unwrap().measured_at.unix_ms(), 1_500, "latest wins");
        assert!(matches!(t.get(&(2, 1)).unwrap().outcome, CheckOutcome::Ok { .. }), "outcome flips on newer data");
    }

    #[test]
    fn merge_ssh_probes_tie_breaks_deterministically() {
        // same key, same timestamp, different content: larger serialized
        // form wins on BOTH sides regardless of merge order
        let x = probe_of(1, 2, 5_000, CheckOutcome::Fail { reason: "aaa".into() });
        let y = probe_of(1, 2, 5_000, CheckOutcome::Fail { reason: "zzz".into() });
        let ta = RwLock::new(matrix_of(std::slice::from_ref(&x)));
        let tb = RwLock::new(matrix_of(std::slice::from_ref(&y)));
        merge_ssh_probes(&ta, std::slice::from_ref(&y));
        merge_ssh_probes(&tb, std::slice::from_ref(&x));
        assert_eq!(sorted_rows(&ta), sorted_rows(&tb), "tie must resolve identically");
    }

    #[test]
    fn retain_known_drops_removed_nodes() {
        let m = matrix_of(&[
            probe_of(1, 2, 100, CheckOutcome::Ok { latency_ms: 1 }),
            probe_of(1, 3, 100, CheckOutcome::Ok { latency_ms: 1 }),
            probe_of(3, 1, 100, CheckOutcome::Ok { latency_ms: 1 }),
        ]);
        let t = RwLock::new(m);
        retain_known(&t, &HashSet::from([1, 2]));
        let g = t.read().unwrap();
        assert_eq!(g.len(), 1, "rows touching node 3 must be swept");
        assert!(g.contains_key(&(1, 2)));
    }

    // ---------- report ----------

    const NOW: u64 = 1_700_000_000_000;

    #[test]
    fn ssh_report_renders_pairs_stale_and_missing() {
        // interval 60s -> stale after 180s
        let nodes = vec![
            node(1, "a", dial("10.0.0.1", 22)),
            node(2, "b", dial("10.0.0.2", 22)),
            node(3, "c", dial("10.0.0.3", 2222)),
        ];
        let mut m = SshMatrix::new();
        m.insert(
            (1, 2),
            SshProbe {
                from: 1,
                to: 2,
                measured_at: Ts(NOW - 5_000),
                outcome: CheckOutcome::Ok { latency_ms: 23 },
                banner: Some("SSH-2.0-OpenSSH_9.2".into()),
            },
        );
        m.insert(
            (1, 3),
            SshProbe {
                from: 1,
                to: 3,
                measured_at: Ts(NOW - 300_000),
                outcome: CheckOutcome::Fail { reason: "connect timeout after 3s to 10.0.0.3:2222".into() },
                banner: None,
            },
        );
        // (2,1), (2,3), (3,x): no rows at all
        let lines = build_ssh_report(&nodes, &m, NOW, 60);
        assert!(lines.iter().any(|l| l.contains("a -> b (10.0.0.2:22): OK 23ms — SSH-2.0-OpenSSH_9.2 [5s ago]")), "got: {lines:?}");
        assert!(lines.iter().any(|l| l.contains("a -> c") && l.contains("FAIL") && l.contains("STALE")), "got: {lines:?}");
        assert!(lines.iter().any(|l| l.contains("b -> a") && l.contains("no data yet")), "got: {lines:?}");
        // order: sorted by (from, to)
        let pos = |frag: &str| lines.iter().position(|l| l.contains(frag)).unwrap();
        assert!(pos("a -> b") < pos("a -> c") && pos("a -> c") < pos("b -> a"));
        // no asymmetric block: the only both-directions pair has no data
        assert!(!lines.iter().any(|l| l.contains("ASYMMETRIC")), "got: {lines:?}");
    }

    #[test]
    fn ssh_report_marks_asymmetric_pair() {
        let nodes = vec![node(1, "a", dial("10.0.0.1", 22)), node(2, "b", dial("10.0.0.2", 22))];
        let mut m = SshMatrix::new();
        m.insert((1, 2), probe_of(1, 2, NOW - 5_000, CheckOutcome::Ok { latency_ms: 23 }));
        m.insert(
            (2, 1),
            probe_of(2, 1, NOW - 4_000, CheckOutcome::Fail { reason: "connect refused".into() }),
        );
        let lines = build_ssh_report(&nodes, &m, NOW, 60);
        assert_eq!(
            lines.iter().filter(|l| l.starts_with("!")).count(),
            1,
            "exactly one asymmetric line: {lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("a <-> b ASYMMETRIC: 1->OK, 2->FAIL")),
            "got: {lines:?}"
        );

        // both directions OK -> no asymmetric block
        let mut m2 = m.clone();
        m2.insert((2, 1), probe_of(2, 1, NOW - 3_000, CheckOutcome::Ok { latency_ms: 30 }));
        assert!(!build_ssh_report(&nodes, &m2, NOW, 60).iter().any(|l| l.contains("ASYMMETRIC")));

        // one direction stale -> no asymmetric block (cannot compare)
        let mut m3 = m.clone();
        m3.insert((2, 1), probe_of(2, 1, NOW - 1_000_000, CheckOutcome::Fail { reason: "x".into() }));
        assert!(!build_ssh_report(&nodes, &m3, NOW, 60).iter().any(|l| l.contains("ASYMMETRIC")));
    }

    #[test]
    fn ssh_report_jump_and_no_ssh_nodes() {
        let jump = Some(SshDial {
            host: "10.9.9.9".into(),
            port: 22,
            user: "op".into(),
            forward_host: Some("vps2.example.org".into()),
            forward_port: Some(8687),
        });
        let nodes = vec![
            node(1, "a", dial("10.0.0.1", 22)),
            node(2, "b", jump),               // jump target: never probed
            node(3, "plain", None),           // no sshd cfg: not a target
        ];
        let lines = build_ssh_report(&nodes, &SshMatrix::new(), NOW, 60);
        assert!(lines.iter().any(|l| l.contains("a -> b (10.9.9.9:22): via jump (not probed)")), "got: {lines:?}");
        // node-3 is neither target nor renders rows towards itself; node-3
        // as an OBSERVER still renders its row towards target b
        assert!(lines.iter().any(|l| l.contains("plain -> b") && l.contains("via jump")), "got: {lines:?}");
        // no pair towards node-3 (no sshd cfg) renders at all
        assert!(!lines.iter().any(|l| l.contains("-> plain")), "got: {lines:?}");
        // nobody has ssh -> empty report
        let no_ssh = vec![node(1, "a", None), node(2, "b", None)];
        assert!(build_ssh_report(&no_ssh, &SshMatrix::new(), NOW, 60).is_empty());
    }
}
