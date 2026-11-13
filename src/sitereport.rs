//! Consolidated site report (M3.3).
//!
//! Takes the configured check specs, the mesh node list and the gossip-shared
//! probe table, and renders a compact per-check report:
//! - all nodes agree (fresh OK results, same status, same IP) → one line;
//! - anything else (status differs, failures, stale results, missing nodes)
//!   → a deviation block with one line per node.
//!
//! The report is data-only: alerting/flap decisions are M3.7 (out of scope here).

use crate::checks::{chrono_pseudo::Ts, CheckOutcome, HttpCheckSpec, SiteProbe};
use crate::config::NodeEntry;
use std::collections::HashMap;

/// A probe older than `STALE_FACTOR` × check interval counts as stale.
pub const STALE_FACTOR: u64 = 3;
/// Long error reasons are truncated to this many characters in report lines.
const REASON_SNIPPET: usize = 48;

/// Type of the shared probe table: latest result per (check_id, node_id).
pub type ProbeTable = HashMap<(String, u32), SiteProbe>;

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

fn outcome_class(o: &CheckOutcome) -> &'static str {
    match o {
        CheckOutcome::Ok { .. } => "ok",
        CheckOutcome::Fail { .. } => "fail",
        CheckOutcome::Unknown { .. } => "unknown",
    }
}

/// One rendered line of the report for a single node's result.
struct NodeLine {
    node_id: u32,
    text: String,
    class: String,
    ok_latency: Option<u64>,
}

fn node_line(node: &NodeEntry, probe: Option<&SiteProbe>, stale_after_ms: u64, now_ms: u64, expect: u16) -> NodeLine {
    let label = format!("{} ({})", node.name, node.id);
    let Some(p) = probe else {
        return NodeLine { node_id: node.id, text: format!("{label}: no data"), class: "missing".into(), ok_latency: None };
    };
    let age = age_str(now_ms, p.measured_at.unix_ms());
    let stale = now_ms.saturating_sub(p.measured_at.unix_ms()) > stale_after_ms;
    let stale_tag = if stale { " [STALE]" } else { "" };
    let text = match (&p.outcome, p.status) {
        (CheckOutcome::Ok { latency_ms }, code) => {
            let code = code.map(|c| c.to_string()).unwrap_or_else(|| "OK".into());
            match &p.ip {
                Some(ip) => format!("{label}: {code} OK {latency_ms}ms, ip {ip}, {age}{stale_tag}"),
                None => format!("{label}: {code} OK {latency_ms}ms, {age}{stale_tag}"),
            }
        }
        (CheckOutcome::Fail { reason }, Some(code)) => {
            format!("{label}: {code} (expected {expect}) FAIL {age}{stale_tag} — {}", reason_snippet(reason))
        }
        (CheckOutcome::Fail { reason }, None) | (CheckOutcome::Unknown { reason }, _) => {
            format!("{label}: FAIL {age}{stale_tag} — {}", reason_snippet(reason))
        }
    };
    let mut class = outcome_class(&p.outcome).to_string();
    if stale {
        class = format!("{class}+stale");
    }
    let ok_latency = match &p.outcome {
        CheckOutcome::Ok { latency_ms } if !stale => Some(*latency_ms),
        _ => None,
    };
    NodeLine { node_id: node.id, text, class, ok_latency }
}

/// Build the consolidated report, one entry per configured check, in config
/// order. Lines are returned pre-indented; empty input yields an empty vec.
pub fn build_site_report(
    specs: &[HttpCheckSpec],
    nodes: &[NodeEntry],
    probes: &ProbeTable,
    now_ms: u64,
) -> Vec<String> {
    let mut out = Vec::new();
    for spec in specs {
        let stale_after_ms = spec.interval().as_millis() as u64 * STALE_FACTOR;
        let mut lines: Vec<NodeLine> = nodes
            .iter()
            .map(|n| node_line(n, probes.get(&(spec.name.clone(), n.id)), stale_after_ms, now_ms, spec.expect()))
            .collect();
        lines.sort_by_key(|l| l.node_id);

        let expected = lines.len();
        let fresh_ok: Vec<&NodeLine> = lines.iter().filter(|l| l.class == "ok").collect();
        let agree = expected > 0
            && fresh_ok.len() == expected
            && fresh_ok.iter().all(|l| fresh_ok[0].class == l.class)
            && all_same_status_and_ip(&fresh_ok.iter().map(|l| probes.get(&(spec.name.clone(), l.node_id))).collect::<Vec<_>>());

        if agree {
            let any = probes.get(&(spec.name.clone(), lines[0].node_id)).expect("fresh_ok implies a probe");
            let avg = fresh_ok.iter().filter_map(|l| l.ok_latency).sum::<u64>() / fresh_ok.len().max(1) as u64;
            let body = match &any.ip {
                Some(ip) => format!("{} ({ip})", spec.name),
                None => spec.name.clone(),
            };
            let code = any.status.map(|c| c.to_string()).unwrap_or_else(|| "OK".into());
            out.push(format!("  {body}: {code} OK ({}/{} nodes, {avg}ms avg)", fresh_ok.len(), expected));
        } else if lines.iter().all(|l| l.class == "missing") {
            out.push(format!("  {} ({}): no data yet (0/{expected} nodes)", spec.name, spec.url));
        } else {
            // compact form for uniform non-OK agreement (e.g. everyone sees the same failure)
            let classes: Vec<&str> = lines.iter().map(|l| l.class.as_str()).collect();
            let uniform_fail = !classes.is_empty()
                && classes.iter().all(|c| *c == classes[0])
                && classes[0] != "ok";
            if uniform_fail {
                let first = probes
                    .get(&(spec.name.clone(), lines[0].node_id))
                    .map(|p| reason_snippet(match &p.outcome {
                        CheckOutcome::Fail { reason } | CheckOutcome::Unknown { reason } => reason,
                        CheckOutcome::Ok { .. } => "",
                    }))
                    .unwrap_or_default();
                out.push(format!("  ! {} ({}): {} on {}/{} nodes — {first}", spec.name, spec.url, classes[0].to_uppercase(), expected - classes.iter().filter(|c| **c == "missing").count(), expected));
            } else {
                out.push(format!("  ! {} ({}) — DEVIATION", spec.name, spec.url));
                for l in &lines {
                    out.push(format!("      {}", l.text));
                }
            }
        }
    }
    out
}

/// Agreement requires the same observed status code and the same IP across
/// nodes (different IPs = split DNS / geo routing = worth a deviation block).
fn all_same_status_and_ip(probes: &[Option<&SiteProbe>]) -> bool {
    let mut status: Option<u16> = None;
    let mut ip: Option<&str> = None;
    for p in probes.iter().flatten() {
        match (status, p.status) {
            (None, s) => status = s,
            (Some(a), Some(b)) if a == b => {}
            _ => return false,
        }
        match (ip, p.ip.as_deref()) {
            (None, i) => ip = i,
            (Some(a), Some(b)) if a == b => {}
            _ => return false,
        }
    }
    true
}

/// Convenience wrapper for callers holding the current clock.
pub fn report_now(specs: &[HttpCheckSpec], nodes: &[NodeEntry], probes: &ProbeTable) -> Vec<String> {
    build_site_report(specs, nodes, probes, Ts::now().unix_ms())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(name: &str, url: &str, interval: Option<u64>) -> HttpCheckSpec {
        HttpCheckSpec { name: name.into(), url: url.into(), expect: None, interval, timeout: None }
    }

    fn node(id: u32, name: &str) -> NodeEntry {
        NodeEntry { id, name: name.into(), public_key: None, address: None, ssh: None }
    }

    fn ok_probe(check: &str, node: u32, ms_ago: u64, latency: u64, ip: &str, now: u64) -> SiteProbe {
        SiteProbe {
            check_id: check.into(),
            node_id: node,
            measured_at: Ts(now - ms_ago * 1000),
            outcome: CheckOutcome::Ok { latency_ms: latency },
            status: Some(200),
            ip: Some(ip.into()),
        }
    }

    fn fail_probe(check: &str, node: u32, ms_ago: u64, status: Option<u16>, reason: &str, now: u64) -> SiteProbe {
        SiteProbe {
            check_id: check.into(),
            node_id: node,
            measured_at: Ts(now - ms_ago * 1000),
            outcome: CheckOutcome::Fail { reason: reason.into() },
            status,
            ip: None,
        }
    }

    const NOW: u64 = 1_700_000_000_000;

    #[test]
    fn all_agree_ok_single_line() {
        let specs = vec![spec("web", "https://example.com", None)];
        let nodes = vec![node(1, "a"), node(2, "b"), node(3, "c")];
        let mut probes = ProbeTable::new();
        for (n, lat) in [(1, 80), (2, 90), (3, 91)] {
            probes.insert(("web".into(), n), ok_probe("web", n, 3, lat, "93.184.216.34", NOW));
        }
        let lines = build_site_report(&specs, &nodes, &probes, NOW);
        assert_eq!(lines.len(), 1, "one line, no duplicates: {lines:?}");
        assert!(lines[0].contains("web (93.184.216.34): 200 OK (3/3 nodes"), "got: {}", lines[0]);
        assert!(lines[0].contains("87ms avg"), "avg of 80+90+91 = 87: {}", lines[0]);
    }

    #[test]
    fn deviation_lists_each_node() {
        let specs = vec![spec("web", "https://example.com", Some(60))];
        let nodes = vec![node(1, "a"), node(2, "b"), node(3, "c")];
        let mut probes = ProbeTable::new();
        probes.insert(("web".into(), 1), ok_probe("web", 1, 5, 80, "1.2.3.4", NOW));
        probes.insert(("web".into(), 2), fail_probe("web", 2, 5, Some(503), "status 503, expected 200", NOW));
        // node 3: no data at all
        let lines = build_site_report(&specs, &nodes, &probes, NOW);
        assert_eq!(lines.len(), 4, "header + 3 node lines + nothing else: {lines:?}");
        assert!(lines[0].contains("DEVIATION"), "got: {}", lines[0]);
        assert!(lines.iter().any(|l| l.contains("200 OK")), "ok node listed");
        assert!(lines.iter().any(|l| l.contains("503 (expected 200)")), "fail node listed: {lines:?}");
        assert!(lines.iter().any(|l| l.contains("c (3): no data")), "missing node listed: {lines:?}");
    }

    #[test]
    fn stale_result_counts_as_missing() {
        let specs = vec![spec("web", "https://example.com", Some(10))]; // stale after 30s
        let nodes = vec![node(1, "a"), node(2, "b")];
        let mut probes = ProbeTable::new();
        probes.insert(("web".into(), 1), ok_probe("web", 1, 5, 80, "1.2.3.4", NOW)); // fresh
        probes.insert(("web".into(), 2), ok_probe("web", 2, 600, 80, "1.2.3.4", NOW)); // 10 min old
        let lines = build_site_report(&specs, &nodes, &probes, NOW);
        assert!(lines[0].contains("DEVIATION"), "stale node breaks agreement: {lines:?}");
        assert!(lines.iter().any(|l| l.contains("[STALE]")), "stale is marked: {lines:?}");
    }

    #[test]
    fn different_ip_is_a_deviation() {
        let specs = vec![spec("web", "https://example.com", None)];
        let nodes = vec![node(1, "a"), node(2, "b")];
        let mut probes = ProbeTable::new();
        probes.insert(("web".into(), 1), ok_probe("web", 1, 5, 80, "1.2.3.4", NOW));
        probes.insert(("web".into(), 2), ok_probe("web", 2, 5, 80, "5.6.7.8", NOW));
        let lines = build_site_report(&specs, &nodes, &probes, NOW);
        assert!(lines[0].contains("DEVIATION"), "split DNS must surface: {lines:?}");
    }

    #[test]
    fn uniform_failure_is_compact_not_deviation_block() {
        let specs = vec![spec("dead", "http://127.0.0.1:9/", Some(60))];
        let nodes = vec![node(1, "a"), node(2, "b")];
        let mut probes = ProbeTable::new();
        probes.insert(("dead".into(), 1), fail_probe("dead", 1, 5, None, "error sending request", NOW));
        probes.insert(("dead".into(), 2), fail_probe("dead", 2, 5, None, "error sending request", NOW));
        let lines = build_site_report(&specs, &nodes, &probes, NOW);
        assert_eq!(lines.len(), 1, "single compact line: {lines:?}");
        assert!(lines[0].contains("FAIL on 2/2 nodes"), "got: {}", lines[0]);
    }

    #[test]
    fn no_data_at_all_is_one_line() {
        let specs = vec![spec("web", "https://example.com", None)];
        let nodes = vec![node(1, "a")];
        let lines = build_site_report(&specs, &nodes, &ProbeTable::new(), NOW);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("no data yet (0/1 nodes)"), "got: {}", lines[0]);
    }
}
