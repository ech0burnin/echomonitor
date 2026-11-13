//! Routing over the replicated topology graph.
//! Gossip gives every node a full link-state view, so plain Dijkstra
//! (equivalent to a converged distance-vector, without the count-to-infinity)
//! yields next-hop + cost for every destination.

use crate::config::{EdgeEntry, NodeEntry};
use std::collections::{BinaryHeap, HashMap, HashSet};

#[derive(Debug, Clone, PartialEq)]
pub struct RouteInfo {
    pub next_hop: u32,
    pub cost_ms: u64,
    /// Full path including self and target (debug/UI aid).
    pub path: Vec<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct RoutingTable {
    routes: HashMap<u32, RouteInfo>,
}

#[derive(PartialEq, Eq)]
struct HeapItem {
    cost: u64,
    node: u32,
}

impl Ord for HeapItem {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.cost.cmp(&self.cost).then_with(|| other.node.cmp(&self.node))
    }
}
impl PartialOrd for HeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl RoutingTable {
    /// Build routes from `self_id` over the given topology.
    /// Edges without measured latency count as weight 1 (reachable, unknown cost).
pub fn build(self_id: u32, nodes: &[NodeEntry], edges: &[EdgeEntry]) -> Self {
        let mut adj: HashMap<u32, Vec<(u32, u64)>> = HashMap::new();
        for n in nodes {
            adj.entry(n.id).or_default();
        }
        for e in edges {
            let w = e.latency_ms.unwrap_or(1).max(1);
            adj.entry(e.a).or_default().push((e.b, w));
            adj.entry(e.b).or_default().push((e.a, w));
        }

        let mut dist: HashMap<u32, u64> = HashMap::new();
        let mut prev: HashMap<u32, u32> = HashMap::new();
        let mut done: HashSet<u32> = HashSet::new();
        let mut heap = BinaryHeap::new();

        dist.insert(self_id, 0);
        heap.push(HeapItem { cost: 0, node: self_id });

        while let Some(HeapItem { cost, node }) = heap.pop() {
            if !done.insert(node) {
                continue;
            }
            if let Some(neigh) = adj.get(&node) {
                for &(next, w) in neigh {
                    let nd = cost + w;
                    if nd < *dist.get(&next).unwrap_or(&u64::MAX) {
                        dist.insert(next, nd);
                        prev.insert(next, node);
                        heap.push(HeapItem { cost: nd, node: next });
                    }
                }
            }
        }

        let mut routes = HashMap::new();
        for (&target, &cost) in &dist {
            if target == self_id {
                continue;
            }
            // walk prev-chain back to self to recover path + first hop
            let mut path = vec![target];
            let mut cur = target;
            while let Some(&p) = prev.get(&cur) {
                path.push(p);
                cur = p;
            }
            path.reverse(); // now starts at self_id
            if path.first() != Some(&self_id) {
                continue; // unreachable shouldn't happen if dist exists, but be safe
            }
            let next_hop = path[1];
            routes.insert(
                target,
                RouteInfo {
                    next_hop,
                    cost_ms: cost,
                    path,
                },
            );
        }

        RoutingTable { routes }
    }

    /// Next hop toward target. Will be used by the ping layer (M3).
    #[allow(dead_code)]
    pub fn next_hop(&self, target: u32) -> Option<u32> {
        self.routes.get(&target).map(|r| r.next_hop)
    }

    pub fn route(&self, target: u32) -> Option<&RouteInfo> {
        self.routes.get(&target)
    }

    pub fn all(&self) -> &HashMap<u32, RouteInfo> {
        &self.routes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: u32) -> NodeEntry {
        NodeEntry { id, name: format!("n{id}"), public_key: None, address: None, ssh: None }
    }

    fn edge(a: u32, b: u32, ms: u64) -> EdgeEntry {
        EdgeEntry { a: a.min(b), b: a.max(b), latency_ms: Some(ms) }
    }

    #[test]
    fn line_topology_routes_through_middle() {
        let nodes = vec![node(1), node(2), node(3)];
        let edges = vec![edge(1, 2, 5), edge(2, 3, 7)];
        let t = RoutingTable::build(1, &nodes, &edges);
        assert_eq!(t.next_hop(2), Some(2));
        assert_eq!(t.next_hop(3), Some(2), "1→3 must go via 2");
        assert_eq!(t.route(3).unwrap().cost_ms, 12);
        assert_eq!(t.route(3).unwrap().path, vec![1, 2, 3]);
    }

    #[test]
    fn cheaper_indirect_path_wins() {
        let nodes = vec![node(1), node(2), node(3)];
        // direct 1-3 is expensive (100), via 2 is 5+7=12
        let edges = vec![edge(1, 2, 5), edge(2, 3, 7), edge(1, 3, 100)];
        let t = RoutingTable::build(1, &nodes, &edges);
        assert_eq!(t.next_hop(3), Some(2));
        assert_eq!(t.route(3).unwrap().cost_ms, 12);
    }

    #[test]
    fn disconnected_target_has_no_route() {
        let nodes = vec![node(1), node(2), node(9)];
        let edges = vec![edge(1, 2, 5)];
        let t = RoutingTable::build(1, &nodes, &edges);
        assert_eq!(t.next_hop(2), Some(2));
        assert_eq!(t.next_hop(9), None, "no edge to 9 → no route");
    }

    #[test]
    fn edge_without_latency_still_reachable() {
        let nodes = vec![node(1), node(2)];
        let edges = vec![EdgeEntry { a: 1, b: 2, latency_ms: None }];
        let t = RoutingTable::build(1, &nodes, &edges);
        assert_eq!(t.next_hop(2), Some(2));
        assert_eq!(t.route(2).unwrap().cost_ms, 1);
    }

    #[test]
    fn symmetric_build_from_other_end() {
        let nodes = vec![node(1), node(2), node(3)];
        let edges = vec![edge(1, 2, 5), edge(2, 3, 7)];
        let t = RoutingTable::build(3, &nodes, &edges);
        assert_eq!(t.next_hop(1), Some(2), "3→1 must go via 2");
    }
}
