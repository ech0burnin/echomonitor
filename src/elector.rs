//! Deterministic parent election (M2.5).
//!
//! The mesh has no leader protocol: every node recomputes the same pure
//! function over replicated inputs (topology from the config, liveness from
//! the gossip-shared evidence table) and arrives at an identical parent one
//! gossip round after any change. Lowest id wins; the two-neighbor rule from
//! ABOUT.md applies only when three or more nodes are alive (a 2-node mesh
//! has a single neighbor per node — the rule is waived).
//!
//! `parent_id` is runtime-only: computed, never persisted into
//! `network.toml`, never hashed, no revision bump (same policy as latencies
//! in M2.4 and probes in M3.3).
//!
//! Liveness evidence uses observer wall clocks with a generous dead
//! threshold; fine on NTP-synced boxes (documented trade-off).

use crate::config::{EdgeEntry, NodeEntry};
use std::collections::HashMap;

/// A node is dead once its last successful gossip is older than this.
/// 3 × default gossip interval (15s); margins dwarf typical NTP skew.
pub const T_DEAD_MS: u64 = 45_000;
/// A desired-parent change must hold this many consecutive rounds before
/// the node switches (flap guard). Worst-case failover ≈ T_DEAD + 2 rounds.
pub const ELECT_STABILITY: u32 = 2;

/// id -> unix ms of the last successful direct gossip with that node
/// (self seeded at boot). Runtime-only, replicated via `GossipMessage::seen`.
pub type Evidence = HashMap<u32, u64>;

/// Set of node ids with fresh evidence (self always alive).
pub fn alive_set(evidence: &Evidence, now_ms: u64) -> Vec<u32> {
    let mut v: Vec<u32> = evidence
        .iter()
        .filter(|(_, &at)| now_ms.saturating_sub(at) < T_DEAD_MS)
        .map(|(&id, _)| id)
        .collect();
    v.sort_unstable();
    v
}

fn alive_neighbors(node: u32, edges: &[EdgeEntry], alive: &[u32]) -> usize {
    edges
        .iter()
        .filter(|e| e.a == node || e.b == node)
        .filter(|e| {
            let other = if e.a == node { e.b } else { e.a };
            alive.contains(&other)
        })
        .count()
}

/// Pure elector: min-by-id over candidates that are alive and (when the
/// alive set is large enough) have at least two alive neighbors.
/// Self is expected to be present in `evidence` (seeded at boot); callers
/// pass the full replicated state so every node computes the same result.
pub fn elect(
    nodes: &[NodeEntry],
    edges: &[EdgeEntry],
    evidence: &Evidence,
    now_ms: u64,
) -> Option<u32> {
    let alive = alive_set(evidence, now_ms);
    if alive.is_empty() {
        return None;
    }
    // Degraded fallback: when >=3 alive but nobody has 2 alive neighbors
    // (e.g. the chain is broken), still elect the lowest alive id rather
    // than running parentless — better than no coordinator.
    let strict = alive.len() >= 3;
    nodes
        .iter()
        .filter(|n| alive.contains(&n.id))
        .filter(|n| !strict || alive_neighbors(n.id, edges, &alive) >= 2)
        .map(|n| n.id)
        .min()
        .or_else(|| {
            if strict {
                tracing::warn!("no candidate with 2 alive neighbors: degraded fallback to lowest alive id");
                alive.first().copied()
            } else {
                None
            }
        })
}

/// One step of the stability gate: feed the freshly desired parent, get
/// back the parent that should be reported/acted on. Switches only after
/// the same desired value held for `ELECT_STABILITY` consecutive calls.
#[derive(Debug)]
pub struct StabilityGate {
    current: Option<u32>,
    desired: Option<u32>,
    held_rounds: u32,
}

impl StabilityGate {
    pub fn new() -> Self {
        Self { current: None, desired: None, held_rounds: 0 }
    }

    /// Returns (effective_parent, changed) — `changed` is true on the call
    /// where the effective parent actually switches.
    pub fn observe(&mut self, desired: Option<u32>) -> (Option<u32>, bool) {
        if desired == self.desired {
            if self.held_rounds < ELECT_STABILITY && self.desired != self.current {
                self.held_rounds += 1;
                if self.held_rounds >= ELECT_STABILITY {
                    self.current = self.desired;
                    return (self.current, true);
                }
            }
        } else {
            self.desired = desired;
            self.held_rounds = 1;
            if self.held_rounds >= ELECT_STABILITY && self.desired != self.current {
                self.current = self.desired;
                return (self.current, true);
            }
        }
        (self.current, false)
    }
}

impl Default for StabilityGate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nodes(ids: &[u32]) -> Vec<NodeEntry> {
        ids.iter()
            .map(|&id| NodeEntry { id, name: format!("n{id}"), public_key: None, address: None })
            .collect()
    }

    fn edge(a: u32, b: u32) -> EdgeEntry {
        EdgeEntry { a, b, latency_ms: None }
    }

    fn evidence(fresh: &[(u32, u64)], now: u64) -> Evidence {
        fresh.iter().map(|&(id, off)| (id, now - off)).collect()
    }

    const NOW: u64 = 1_000_000;

    #[test]
    fn two_nodes_alive_parent_is_lowest_id() {
        // neighbor rule waived below 3 alive nodes
        let n = nodes(&[1, 2]);
        let e = vec![edge(1, 2)];
        let ev = evidence(&[(1, 0), (2, 0)], NOW);
        assert_eq!(elect(&n, &e, &ev, NOW), Some(1));
    }

    #[test]
    fn three_line_middle_wins() {
        // 1-2-3 line: endpoints have 1 alive neighbor -> 2 elected
        let n = nodes(&[1, 2, 3]);
        let e = vec![edge(1, 2), edge(2, 3)];
        let ev = evidence(&[(1, 0), (2, 0), (3, 0)], NOW);
        assert_eq!(elect(&n, &e, &ev, NOW), Some(2));
    }

    #[test]
    fn three_star_hub_wins() {
        // 1<->2, 1<->3: node 1 has two alive neighbors
        let n = nodes(&[1, 2, 3]);
        let e = vec![edge(1, 2), edge(1, 3)];
        let ev = evidence(&[(1, 0), (2, 0), (3, 0)], NOW);
        assert_eq!(elect(&n, &e, &ev, NOW), Some(1));
    }

    #[test]
    fn dead_parent_falls_to_next_id() {
        let n = nodes(&[1, 2, 3]);
        let e = vec![edge(1, 2), edge(2, 3)];
        // node 1 evidence stale past T_DEAD
        let ev = evidence(&[(1, T_DEAD_MS), (2, 0), (3, 0)], NOW);
        assert_eq!(elect(&n, &e, &ev, NOW), Some(2));
    }

    #[test]
    fn t_dead_boundary_exact() {
        let n = nodes(&[1, 2]);
        let e = vec![edge(1, 2)];
        let ev_dead = evidence(&[(1, T_DEAD_MS), (2, 0)], NOW);
        assert_eq!(elect(&n, &e, &ev_dead, NOW), Some(2));
        let ev_alive = evidence(&[(1, T_DEAD_MS - 1), (2, 0)], NOW);
        assert_eq!(elect(&n, &e, &ev_alive, NOW), Some(1));
    }

    #[test]
    fn no_candidate_with_two_neighbors_falls_back_to_lowest_alive() {
        // chain 1-2-3-4-5 with 2,3,4 dead: alive 1 and 5 have no alive
        // neighbors at all -> degraded fallback to lowest alive id
        let n = nodes(&[1, 2, 3, 4, 5]);
        let e = vec![edge(1, 2), edge(2, 3), edge(3, 4), edge(4, 5)];
        let ev = evidence(&[(1, 0), (5, 0)], NOW);
        assert_eq!(elect(&n, &e, &ev, NOW), Some(1));
    }

    #[test]
    fn empty_evidence_no_parent() {
        let n = nodes(&[1, 2]);
        let ev = Evidence::new();
        assert_eq!(elect(&n, &[], &ev, NOW), None);
    }

    #[test]
    fn stability_gate_requires_two_rounds() {
        let mut g = StabilityGate::new();
        // first observation of Some(1): held=1, not yet effective
        assert_eq!(g.observe(Some(1)), (None, false));
        // same desired again: held=2 -> switches now
        assert_eq!(g.observe(Some(1)), (Some(1), true));
        // flapping to Some(2) once must not switch immediately
        assert_eq!(g.observe(Some(2)), (Some(1), false));
        assert_eq!(g.observe(Some(2)), (Some(2), true));
        // flap back to 1 for a single round keeps 2
        assert_eq!(g.observe(Some(1)), (Some(2), false));
        assert_eq!(g.observe(Some(1)), (Some(1), true));
    }
}
