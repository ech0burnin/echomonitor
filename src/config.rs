//! Network-wide configuration, replicated to every node.
//! TOML with strict deserialization: unknown fields are an error,
//! so a stale binary never silently ignores fields written by a newer one.
//!
//! M2.4: `content_hash` covers admin-level content only (revision + nodes +
//! edges WITHOUT latencies). Latencies are runtime measurements: they must not
//! trigger admin conflicts or bump revisions when they churn.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

pub const DEFAULT_LISTEN_PORT: u16 = 8687;
pub const DEFAULT_GOSSIP_INTERVAL_SECS: u64 = 15;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// Monotonic config revision, bumped on every admin change.
    pub revision: u64,
    /// Canonical admin hash; nodes refuse configs whose hash mismatches.
    #[serde(rename = "content-hash")]
    pub content_hash: String,
    /// This node's numeric id within the mesh.
    pub self_id: u32,
    /// Human-readable name shown in the web UI.
    pub self_name: String,
    pub net: NetSection,
    pub auth: AuthSection,
    #[serde(default)]
    pub nodes: Vec<NodeEntry>,
    #[serde(default)]
    pub edges: Vec<EdgeEntry>,
    /// Scheduled HTTP checks ([[checks]] table). Optional, default none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checks: Vec<crate::checks::HttpCheckSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetSection {
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    #[serde(default = "default_gossip_interval")]
    pub gossip_interval_secs: u64,
}

fn default_listen_port() -> u16 {
    DEFAULT_LISTEN_PORT
}

fn default_gossip_interval() -> u64 {
    DEFAULT_GOSSIP_INTERVAL_SECS
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthSection {
    /// Shared network secret for HMAC-based periodic tokens.
    pub network_secret: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeEntry {
    pub id: u32,
    pub name: String,
    /// Hex-encoded ed25519 public key (absent until the node registers).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// Reachable address (host:port), absent for nodes behind NAT.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// M2.6: how to reach this node's system sshd for the fallback tunnel.
    /// Absent = no tunnel (current behavior, bit-for-bit).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh: Option<SshDial>,
}

/// SSH dial parameters for the M2.6 fallback tunnel (peer's system sshd,
/// authenticated with our node key). The tunnel always targets the peer's
/// own loopback HTTP port, so no http port is needed here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshDial {
    pub host: String,
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    #[serde(default = "default_ssh_user")]
    pub user: String,
}

fn default_ssh_port() -> u16 {
    crate::tunnel::DEFAULT_SSH_PORT
}

fn default_ssh_user() -> String {
    crate::tunnel::DEFAULT_SSH_USER.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeEntry {
    pub a: u32,
    pub b: u32,
    /// Measured RTT; runtime data, excluded from the admin hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
}

/// Canonical admin-level hash over (revision, nodes, edges-without-latency).
/// Order-independent: nodes sorted by id, edges sorted and normalized,
/// so two configs describing the same network hash identically.
/// M2.6: the node's `ssh` dial info is admin-level addressing metadata
/// (same class as `address`) and IS hashed.
/// Canonical per-node tuple for hashing: (id, name, public_key, address, ssh-dial).
type NodeCanon<'a> = (u32, &'a str, Option<&'a str>, Option<&'a str>, Option<String>);

pub fn admin_hash(revision: u64, nodes: &[NodeEntry], edges: &[EdgeEntry]) -> String {
    let mut nodes_canon: Vec<NodeCanon> = nodes
        .iter()
        .map(|n| {
            (
                n.id,
                n.name.as_str(),
                n.public_key.as_deref(),
                n.address.as_deref(),
                n.ssh.as_ref().map(|s| format!("{}:{}:{}", s.host, s.port, s.user)),
            )
        })
        .collect();
    nodes_canon.sort_by(|x, y| x.0.cmp(&y.0).then(x.1.cmp(y.1)));
    let mut edges_canon: Vec<(u32, u32)> = edges
        .iter()
        .map(|e| (e.a.min(e.b), e.a.max(e.b)))
        .collect();
    edges_canon.sort();
    let canonical =
        serde_json::to_string(&(revision, nodes_canon, edges_canon)).unwrap_or_default();
    let digest = Sha256::digest(canonical.as_bytes());
    hex::encode(&digest[..12])
}

impl NetworkConfig {
    /// Fresh config for the very first node of a new network.
    pub fn bootstrap(network_secret: String, self_name: String) -> Self {
        let mut cfg = Self {
            revision: 1,
            content_hash: String::new(),
            self_id: 1,
            self_name: self_name.clone(),
            net: NetSection {
                listen_port: DEFAULT_LISTEN_PORT,
                gossip_interval_secs: DEFAULT_GOSSIP_INTERVAL_SECS,
            },
            auth: AuthSection { network_secret },
            nodes: vec![NodeEntry {
                id: 1,
                name: self_name.clone(),
                public_key: None,
                address: None,
                ssh: None,
            }],
            edges: Vec::new(),
            checks: Vec::new(),
        };
        cfg.recompute_hash();
        cfg
    }

    /// Recompute the canonical admin hash from current content.
    pub fn recompute_hash(&mut self) {
        self.content_hash = admin_hash(self.revision, &self.nodes, &self.edges);
    }

    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read config {}", path.display()))?;
        let cfg: NetworkConfig = toml::from_str(&raw)
            .with_context(|| format!("invalid config {}", path.display()))?;
        Ok(cfg)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let raw = toml::to_string_pretty(self)?;
        std::fs::write(path, raw)
            .with_context(|| format!("cannot write config {}", path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_save_load_roundtrip() {
        let dir = std::env::temp_dir().join("em-config-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("network.toml");
        let cfg = NetworkConfig::bootstrap("secret-тест".into(), "node-1".into());
        cfg.save(&path).unwrap();
        let loaded = NetworkConfig::load(&path).unwrap();
        assert_eq!(cfg.revision, loaded.revision);
        assert_eq!(cfg.content_hash, loaded.content_hash);
        assert_eq!(cfg.nodes.len(), loaded.nodes.len());
        assert_eq!(cfg.self_name, loaded.self_name);
    }

    #[test]
    fn unknown_field_is_rejected() {
        let raw = r#"
revision = 1
content-hash = "abc"
self_id = 1
self_name = "n1"
[auth]
network_secret = "s"
bogus_field = 1
"#;
        assert!(toml::from_str::<NetworkConfig>(raw).is_err());
    }

    #[test]
    fn hash_changes_with_content() {
        let mut a = NetworkConfig::bootstrap("s".into(), "n".into());
        let h1 = a.content_hash.clone();
        a.revision += 1;
        a.recompute_hash();
        assert_ne!(h1, a.content_hash);
    }

    #[test]
    fn latency_is_not_part_of_admin_hash() {
        let mut a = NetworkConfig::bootstrap("s".into(), "n".into());
        let mut b = a.clone();
        a.edges.push(EdgeEntry { a: 1, b: 2, latency_ms: None });
        b.edges.push(EdgeEntry { a: 2, b: 1, latency_ms: Some(999) });
        a.recompute_hash();
        b.recompute_hash();
        assert_eq!(
            a.content_hash, b.content_hash,
            "latency and edge direction must not affect the admin hash"
        );
    }

    #[test]
    fn hash_is_order_independent() {
        let mut a = NetworkConfig::bootstrap("s".into(), "n".into());
        let mut b = a.clone();
        a.nodes.push(NodeEntry { id: 2, name: "x".into(), public_key: None, address: None, ssh: None });
        a.nodes.push(NodeEntry { id: 3, name: "y".into(), public_key: None, address: None, ssh: None });
        // same nodes, pushed in reverse order
        b.nodes.push(NodeEntry { id: 3, name: "y".into(), public_key: None, address: None, ssh: None });
        b.nodes.push(NodeEntry { id: 2, name: "x".into(), public_key: None, address: None, ssh: None });
        a.recompute_hash();
        b.recompute_hash();
        assert_eq!(a.content_hash, b.content_hash);
    }

    // ---------- M2.6: ssh dial surface ----------

    #[test]
    fn ssh_dial_roundtrip_with_defaults() {
        let mut cfg = NetworkConfig::bootstrap("s".into(), "n1".into());
        cfg.nodes.push(NodeEntry {
            id: 2,
            name: "nat-child".into(),
            public_key: None,
            address: None,
            ssh: Some(SshDial { host: "203.0.113.5".into(), port: 22, user: "root".into() }),
        });
        let dir = std::env::temp_dir().join("em-m26-config");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("network.toml");
        cfg.save(&path).unwrap();
        let loaded = NetworkConfig::load(&path).unwrap();
        assert_eq!(
            loaded.nodes[1].ssh,
            Some(SshDial { host: "203.0.113.5".into(), port: 22, user: "root".into() })
        );
        // defaults apply when port/user are omitted
        let raw = r#"
[[nodes]]
id = 3
name = "defaults"
[nodes.ssh]
host = "10.0.0.9"
"#;
        let parsed: NetworkConfig = toml::from_str(&format!(
            "revision = 1\ncontent-hash = \"x\"\nself_id = 1\nself_name = \"n\"\n[net]\nlisten_port = 8687\n[auth]\nnetwork_secret = \"s\"\n{}",
            raw
        ))
        .unwrap();
        assert_eq!(
            parsed.nodes[0].ssh,
            Some(SshDial { host: "10.0.0.9".into(), port: 22, user: "root".into() })
        );
    }

    #[test]
    fn pre_m26_config_loads_unchanged() {
        // a config written by an older binary: no ssh anywhere
        let raw = r#"
revision = 4
content-hash = "abc123"
self_id = 1
self_name = "legacy"
[net]
listen_port = 8687
[auth]
network_secret = "s"
[[nodes]]
id = 1
name = "legacy"
[[nodes]]
id = 2
name = "peer"
address = "10.1.1.2:8687"
[[edges]]
a = 1
b = 2
"#;
        let cfg: NetworkConfig = toml::from_str(raw).unwrap();
        assert!(cfg.nodes.iter().all(|n| n.ssh.is_none()));
    }

    #[test]
    fn ssh_unknown_field_rejected() {
        let raw = r#"
revision = 1
content-hash = "x"
self_id = 1
self_name = "n"
[auth]
network_secret = "s"
[[nodes]]
id = 1
name = "n"
[nodes.ssh]
host = "10.0.0.9"
bogus = true
"#;
        assert!(toml::from_str::<NetworkConfig>(raw).is_err());
    }

    #[test]
    fn admin_hash_is_sensitive_to_ssh() {
        let mut a = NetworkConfig::bootstrap("s".into(), "n".into());
        let mut b = a.clone();
        a.nodes.push(NodeEntry {
            id: 2,
            name: "x".into(),
            public_key: None,
            address: None,
            ssh: None,
        });
        b.nodes.push(NodeEntry {
            id: 2,
            name: "x".into(),
            public_key: None,
            address: None,
            ssh: Some(SshDial { host: "10.0.0.9".into(), port: 22, user: "root".into() }),
        });
        a.recompute_hash();
        b.recompute_hash();
        assert_ne!(a.content_hash, b.content_hash);
        // and ssh detail differences matter too
        let mut c = b.clone();
        c.nodes[1].ssh = Some(SshDial { host: "10.0.0.9".into(), port: 2222, user: "op".into() });
        c.recompute_hash();
        assert_ne!(b.content_hash, c.content_hash);
    }
}
