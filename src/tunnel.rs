//! M2.6: SSH fallback tunnel.
//!
//! When direct HTTP gossip to a peer is impossible (connection refused,
//! NAT/firewall, or the peer has no `address` at all), we dial the peer's
//! system sshd with the SAME ed25519 identity used for the node keypair
//! (`node.key` raw hex seed) and forward a local TCP listener through
//! `direct-tcpip` channels to the peer's `127.0.0.1:<net.listen_port>`.
//! Gossip then talks plain HTTP to `127.0.0.1:<ephemeral>` — the NodeClient
//! is completely unaware of the tunnel.
//!
//! Host keys are verified TOFU-style (trust on first use) against a local
//! `ssh_known_hosts` pin file: first contact pins the key with a loud warn,
//! any later mismatch is a HARD FAIL (suspected MITM).
//!
//! The peer side needs exactly one thing: our authorized_keys line (see
//! `openssh_public_line`) in the target user's `~/.ssh/authorized_keys`.
//! The same line will serve the M5.1 SSH deploy story.

use crate::config::SshDial;
use anyhow::{anyhow, Context, Result};

/// Default remote sshd port (`SshDial.port`, matches CLI Deploy precedent).
pub const DEFAULT_SSH_PORT: u16 = 22;
/// Default remote user (`SshDial.user`, matches CLI Deploy precedent).
pub const DEFAULT_SSH_USER: &str = "root";
use russh::keys::PublicKeyOrCertificate;
use russh::client::{self, Handle};
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::ssh_key::public::{Ed25519PublicKey, KeyData, PublicKey as OpensshPublic};
use russh::keys::{HashAlg, PrivateKey, PrivateKeyWithHashAlg};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

/// Budget for one SSH connect+auth attempt (TCP + KEX + auth ≈ 2 RTT).
/// Never blocks a gossip round longer than this.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
/// Idle keepalive: consumer NAT/firewalls silently drop idle TCP flows.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
/// After 3 unanswered keepalives (~90 s) russh drops the connection;
/// the next gossip round rebuilds the tunnel.
const KEEPALIVE_MAX: usize = 3;

/// Where a peer's sshd lives (derived from `NodeEntry.ssh`).
pub struct TunnelSpec {
    /// `host:port` of the peer's sshd.
    pub ssh_addr: String,
    /// Remote user to authenticate as.
    pub user: String,
}

impl TunnelSpec {
    pub fn from_dial(dial: &SshDial) -> Self {
        Self {
            ssh_addr: format!("{}:{}", dial.host, dial.port),
            user: dial.user.clone(),
        }
    }
}

/// One established tunnel: an SSH session plus the local listener that
/// pumps accepted connections through `direct-tcpip` channels.
struct Tunnel {
    /// Local endpoint gossip dials (`127.0.0.1:<ephemeral>`).
    local: SocketAddr,
    /// Shared session handle; `is_closed()` is our dead-detector.
    handle: Arc<Handle<TofuHandler>>,
    /// Accept-loop forwarding task. Aborted when the tunnel is dropped
    /// (dead/rebuild) so the listener socket is released — otherwise every
    /// rebuild would leak one parked task + ephemeral port until exit.
    fwd_task: tokio::task::JoinHandle<()>,
}

/// Owns one tunnel per peer id. Reuses live sessions, rebuilds dead ones.
/// Build attempts happen at most once per gossip round per peer (callers
/// invoke `endpoint()` once per round; direct HTTP is always tried first).
pub struct TunnelManager {
    key: Arc<PrivateKey>,
    /// TOFU pin file (`<node-dir>/ssh_known_hosts`). Local trust only:
    /// never replicated, never part of admin_hash.
    pins_path: PathBuf,
    tunnels: HashMap<u32, Tunnel>,
}

/// Convert our `node.key` (64-hex ed25519 seed) into a russh private key.
/// Raw bytes only — our tree pins ed25519-dalek v2 while russh/ssh-key use
/// v3; passing bytes avoids any cross-crate type conversion.
pub fn private_key_from_seed_hex(seed_hex: &str) -> Result<PrivateKey> {
    let seed = hex::decode(seed_hex.trim()).context("node.key is not valid hex")?;
    let arr: &[u8; 32] = seed
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("node.key must hold a 32-byte ed25519 seed (64 hex chars)"))?;
    let kp = Ed25519Keypair::from_seed(arr);
    PrivateKey::new(KeypairData::Ed25519(kp), "echomonitor").context("cannot build ssh key")
}

/// The OpenSSH authorized_keys line for our node identity (`node.pub`,
/// 64-hex public half). Wire format: `ssh-ed25519 base64("ssh-ed25519"
/// string + 32-byte key)` plus a comment identifying the tool. Paste this
/// line into the peer user's `~/.ssh/authorized_keys` — it serves both the
/// M2.6 tunnel and the M5.1 deploy. Encoded by ssh-key itself (the exact
/// encoder OpenSSH parses).
pub fn openssh_public_line(public_hex: &str) -> Result<String> {
    let raw = hex::decode(public_hex.trim()).context("node.pub is not valid hex")?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow!("node.pub must hold a 32-byte ed25519 public key (64 hex chars)"))?;
    let pk = OpensshPublic::from(KeyData::Ed25519(Ed25519PublicKey(bytes)));
    Ok(format!("{} echomonitor", pk.to_openssh()?))
}

impl TunnelManager {
    /// Build a manager from the node key seed hex and a TOFU pin file path.
    pub fn new(seed_hex: &str, pins_path: PathBuf) -> Result<Self> {
        Ok(Self {
            key: Arc::new(private_key_from_seed_hex(seed_hex)?),
            pins_path,
            tunnels: HashMap::new(),
        })
    }

    /// Local endpoint for the peer's tunnel. Returns the existing one when
    /// the session is alive; rebuilds (connect + auth + rebind listener)
    /// when missing or dead. One build attempt per call.
    pub async fn endpoint(
        &mut self,
        peer: u32,
        spec: &TunnelSpec,
        peer_http_port: u16,
    ) -> Result<SocketAddr> {
        if let Some(t) = self.tunnels.get(&peer) {
            if !t.handle.is_closed() {
                return Ok(t.local);
            }
            tracing::warn!(peer, "ssh tunnel connection lost; rebuilding");
        }
        self.drop_tunnel(peer);
        let t = self.build(peer, spec, peer_http_port).await?;
        let local = t.local;
        self.tunnels.insert(peer, t);
        Ok(local)
    }

    /// Drop the peer's tunnel (abort the forward task, release the local
    /// port) so the next round rebuilds it from scratch.
    pub fn note_dead(&mut self, peer: u32) {
        if self.drop_tunnel(peer) {
            tracing::debug!(peer, "ssh tunnel marked dead");
        }
    }

    fn drop_tunnel(&mut self, peer: u32) -> bool {
        if let Some(t) = self.tunnels.remove(&peer) {
            t.fwd_task.abort();
            true
        } else {
            false
        }
    }

    /// Number of live-or-parked tunnels (tests/diagnostics).
    #[allow(dead_code)] // bin-build never calls these; tests do
    pub fn len(&self) -> usize {
        self.tunnels.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.tunnels.is_empty()
    }

    async fn build(
        &self,
        peer: u32,
        spec: &TunnelSpec,
        peer_http_port: u16,
    ) -> Result<Tunnel> {
        let config = Arc::new(client::Config {
            keepalive_interval: Some(KEEPALIVE_INTERVAL),
            keepalive_max: KEEPALIVE_MAX,
            ..Default::default()
        });
        let handler = TofuHandler {
            pins_path: self.pins_path.clone(),
            host: spec.ssh_addr.clone(),
        };
        let mut handle = tokio::time::timeout(
            CONNECT_TIMEOUT,
            client::connect(config, spec.ssh_addr.clone(), handler),
        )
        .await
        .map_err(|_| anyhow!("ssh connect to {} timed out", spec.ssh_addr))?
        .map_err(|e| anyhow!("ssh connect to {} failed: {e}", spec.ssh_addr))?;

        let key = PrivateKeyWithHashAlg::new(self.key.clone(), None);
        let auth = tokio::time::timeout(
            CONNECT_TIMEOUT,
            handle.authenticate_publickey(spec.user.clone(), key),
        )
        .await
        .map_err(|_| anyhow!("ssh auth to {} timed out", spec.ssh_addr))?
        .map_err(|e| anyhow!("ssh auth error: {e}"))?;
        if !auth.success() {
            return Err(anyhow!(
                "ssh pubkey auth rejected for user '{}' at {} \
                 (is our authorized_keys line installed on the peer?)",
                spec.user,
                spec.ssh_addr
            ));
        }

        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .context("cannot bind tunnel listener")?;
        let local = listener.local_addr()?;
        let handle = Arc::new(handle);
        let fwd = handle.clone();
        let fwd_task = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut sock, _)) => {
                        let fwd = fwd.clone();
                        tokio::spawn(async move {
                            // The tunnel always targets the peer's own HTTP
                            // port on ITS loopback: net.listen_port is
                            // network-global, so the peer's port is known.
                            match fwd
                                .channel_open_direct_tcpip(
                                    "127.0.0.1",
                                    peer_http_port as u32,
                                    "127.0.0.1",
                                    0,
                                )
                                .await
                            {
                                Ok(channel) => {
                                    let mut stream = channel.into_stream();
                                    if let Err(e) =
                                        tokio::io::copy_bidirectional(&mut sock, &mut stream).await
                                    {
                                        tracing::debug!(error = %e, "tunnel pump ended");
                                    }
                                }
                                Err(e) => tracing::warn!(
                                    error = %e,
                                    "tunnel channel open failed (peer sshd refuses TCP forwarding?)"
                                ),
                            }
                        });
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "tunnel listener closed");
                        break;
                    }
                }
            }
        });

        tracing::info!(
            peer,
            ssh = %spec.ssh_addr,
            local = %local,
            "ssh tunnel established"
        );
        Ok(Tunnel { local, handle, fwd_task })
    }
}

// ---------- TOFU host-key verification ----------

/// Check (and on first contact, pin) a host fingerprint. Returns true when
/// the presented key matches the pin (or was just pinned), false on mismatch
/// or when the pin file is unwritable (fail closed).
fn verify_or_pin(pins_path: &Path, host: &str, fingerprint: &str) -> bool {
    if let Ok(raw) = std::fs::read_to_string(pins_path) {
        for line in raw.lines().filter(|l| !l.trim().is_empty()) {
            let mut it = line.split_whitespace();
            if it.next() == Some(host) {
                return match it.next() {
                    Some(pinned) if pinned == fingerprint => true,
                    Some(pinned) => {
                        tracing::error!(
                            host,
                            pinned,
                            presented = fingerprint,
                            "SSH HOST KEY MISMATCH for echomonitor peer — possible MITM, refusing"
                        );
                        false
                    }
                    None => false,
                };
            }
        }
    }
    // First use: pin and warn.
    let entry = format!("{host} {fingerprint}\n");
    let write = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(pins_path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, entry.as_bytes()));
    match write {
        Ok(()) => {
            tracing::warn!(
                host,
                fingerprint,
                pins = %pins_path.display(),
                "first ssh contact: pinned host key (trust-on-first-use)"
            );
            true
        }
        Err(e) => {
            tracing::error!(error = %e, "cannot write ssh_known_hosts pin; refusing");
            false
        }
    }
}

/// russh client handler implementing the TOFU policy.
struct TofuHandler {
    pins_path: PathBuf,
    host: String,
}

impl client::Handler for TofuHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let fp = match server_public_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => {
                key.fingerprint(HashAlg::Sha256).to_string()
            }
            PublicKeyOrCertificate::Certificate(_) => {
                tracing::warn!(
                    host = %self.host,
                    "peer presented an ssh host CERTIFICATE: not supported by TOFU pinning, refusing"
                );
                return Ok(false);
            }
        };
        Ok(verify_or_pin(&self.pins_path, &self.host, &fp))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- key material ----------

    #[test]
    fn openssh_line_is_structurally_valid() {
        let kp = crate::crypto::KeyPair::generate();
        let line = openssh_public_line(&kp.public_hex).unwrap();
        // wire format: algo + space + base64(algo-string + u32-len + 32 bytes)
        // u32 length 32 (0x00000020) encodes to "AAAAI" in base64
        assert!(line.starts_with("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"));
        let b64 = line.split(' ').nth(1).unwrap();
        // blob = u32 len + "ssh-ed25519"(11) + u32 len + 32-byte key = 51 bytes
        // -> 68 unpadded base64 chars (51 = 17*3, no padding)
        assert_eq!(b64.len(), 68);
        assert!(!b64.contains('='));
    }

    #[test]
    fn openssh_line_matches_private_key_derivation() {
        // Cross-check: our public half (computed with ed25519-dalek v2 from
        // the node seed) must produce the identical authorized_keys line as
        // ssh-key's own encoder applied to the russh private key (built from
        // the same seed, pubkey computed by ed25519-dalek v3).
        let kp = crate::crypto::KeyPair::generate();
        let sk = private_key_from_seed_hex(&kp.secret_hex).unwrap();
        assert_eq!(openssh_public_line(&kp.public_hex).unwrap(), sk.public_key().to_openssh().unwrap());
    }

    #[test]
    fn key_helpers_reject_garbage() {
        assert!(private_key_from_seed_hex("zzzz").is_err());
        assert!(private_key_from_seed_hex(&"ab".repeat(16)).is_err()); // 16 bytes, not 32
        assert!(openssh_public_line("nothex!").is_err());
        assert!(openssh_public_line(&"ab".repeat(16)).is_err());
    }

    // ---------- tunnel addr bookkeeping ----------

    #[test]
    fn tunnel_spec_from_dial_formats_addr() {
        let spec = TunnelSpec::from_dial(&SshDial {
            host: "203.0.113.5".into(),
            port: 2222,
            user: "op".into(),
        });
        assert_eq!(spec.ssh_addr, "203.0.113.5:2222");
        assert_eq!(spec.user, "op");
        // defaults land on the documented constants
        let d = TunnelSpec::from_dial(&SshDial { host: "h".into(), port: DEFAULT_SSH_PORT, user: DEFAULT_SSH_USER.into() });
        assert_eq!(d.ssh_addr, "h:22");
        assert_eq!(d.user, "root");
    }

    #[test]
    fn manager_starts_with_no_tunnels_and_notes_dead_silently() {
        let kp = crate::crypto::KeyPair::generate();
        let dir = pin_dir("bookkeeping");
        let mut tm = TunnelManager::new(&kp.secret_hex, dir.join("ssh_known_hosts")).unwrap();
        assert!(tm.is_empty());
        // noting a nonexistent peer dead is a no-op, not an error
        tm.note_dead(7);
        assert!(tm.is_empty());
    }

    // ---------- TOFU pin store ----------

    fn pin_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("em-m26-tofu-{tag}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn tofu_pins_on_first_use_then_accepts() {
        let d = pin_dir("pin");
        let pins = d.join("ssh_known_hosts");
        assert!(verify_or_pin(&pins, "h:22", "SHA256:aaa"));
        let raw = std::fs::read_to_string(&pins).unwrap();
        assert_eq!(raw, "h:22 SHA256:aaa\n");
        // same key again: accepted, file unchanged
        assert!(verify_or_pin(&pins, "h:22", "SHA256:aaa"));
        assert_eq!(std::fs::read_to_string(&pins).unwrap(), raw);
        // different host: separate pin
        assert!(verify_or_pin(&pins, "other:22", "SHA256:bbb"));
        assert_eq!(std::fs::read_to_string(&pins).unwrap().lines().count(), 2);
    }

    #[test]
    fn tofu_mismatch_is_hard_fail() {
        let d = pin_dir("mismatch");
        let pins = d.join("ssh_known_hosts");
        assert!(verify_or_pin(&pins, "h:22", "SHA256:real"));
        assert!(!verify_or_pin(&pins, "h:22", "SHA256:evil"));
        // and the pin must NOT have been overwritten
        assert!(std::fs::read_to_string(&pins)
            .unwrap()
            .contains("h:22 SHA256:real"));
    }

    // ---------- integration against a disposable sshd ----------
    //
    // Spawned per test on an ephemeral port with its own host key and
    // authorized_keys. NEVER touches the system sshd (port 2222 here).
    // Skipped (with a note) when /usr/sbin/sshd or ssh-keygen is absent.

    use crate::config::{NetworkConfig, NodeEntry, SshDial};
    use std::sync::Arc;

    struct DisposableSshd {
        child: std::process::Child,
        #[allow(dead_code)]
        port: u16,
        log: PathBuf,
    }

    impl Drop for DisposableSshd {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn sshd_available() -> bool {
        Path::new("/usr/sbin/sshd").exists() && which("ssh-keygen")
    }

    fn which(bin: &str) -> bool {
        let path = std::env::var("PATH").unwrap_or_default();
        path.split(':').any(|p| Path::new(&format!("{p}/{bin}")).exists())
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn fixture_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("em-m26-it-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn current_user() -> String {
        std::env::var("USER").unwrap_or_else(|_| "root".into())
    }

    fn spawn_sshd(dir: &Path, authorized_line: &str, port: u16) -> std::io::Result<DisposableSshd> {
        let host_key = dir.join("host_key");
        let st = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&host_key)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        if !st.success() {
            return Err(std::io::Error::other("ssh-keygen failed"));
        }
        std::fs::write(dir.join("authorized_keys"), format!("{authorized_line}\n"))?;
        let log = dir.join("sshd.log");
        let child = std::process::Command::new("/usr/sbin/sshd")
            .arg("-D")
            .arg("-p")
            .arg(port.to_string())
            .arg("-h")
            .arg(&host_key)
            .args(["-o", "StrictModes=no"])
            .args(["-o", "UsePAM=no"])
            .args(["-o", "PasswordAuthentication=no"])
            .args(["-o", "AllowTcpForwarding=yes"])
            .args(["-o", "ListenAddress=127.0.0.1"])
            .arg("-o")
            .arg(format!("AuthorizedKeysFile={}", dir.join("authorized_keys").display()))
            .arg("-E")
            .arg(&log)
            .spawn()?;
        Ok(DisposableSshd { child, port, log })
    }

    /// Wait until the sshd accepts TCP (or died — report its log tail).
    async fn wait_sshd(sshd: &mut DisposableSshd) {
        for _ in 0..50 {
            if let Ok(Some(status)) = sshd.child.try_wait() {
                let log = std::fs::read_to_string(&sshd.log).unwrap_or_default();
                panic!("disposable sshd exited early ({status}); log tail: {}", log.lines().rev().take(5).collect::<Vec<_>>().join(" | "));
            }
            if std::net::TcpStream::connect(("127.0.0.1", sshd.port)).is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("disposable sshd never became reachable");
    }

    /// Spawn the "NAT peer": plain echomonitor router on an ephemeral port.
    /// Returns (state, http_port).
    async fn spawn_nat_peer(secret: &str) -> (Arc<crate::transport::NodeState>, u16) {
        let mut cfg = NetworkConfig::bootstrap(secret.into(), "node-2".into());
        cfg.self_id = 2;
        cfg.nodes[0].id = 2;
        let lb = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = lb.local_addr().unwrap().port();
        cfg.net.listen_port = port; // network-global: the tunnel targets this
        cfg.recompute_hash();
        let state = Arc::new(crate::transport::NodeState::new(cfg));
        let s = state.clone();
        tokio::spawn(async move { axum::serve(lb, crate::transport::router(s)).await.unwrap() });
        (state, port)
    }

    #[tokio::test]
    async fn tunnel_gossip_reaches_ssh_only_peer() {
        if !sshd_available() {
            eprintln!("skipping: no /usr/sbin/sshd or ssh-keygen");
            return;
        }
        let dir = fixture_dir("nat");
        let keys = crate::crypto::KeyPair::generate();
        let auth_line = openssh_public_line(&keys.public_hex).unwrap();
        let port = free_port();
        let mut sshd = spawn_sshd(&dir, &auth_line, port).expect("spawn sshd");
        wait_sshd(&mut sshd).await;

        let (_state_b, b_port) = spawn_nat_peer("test-secret").await;

        // node A: B is reachable ONLY via ssh (address absent — NAT child)
        let mut cfg_a = NetworkConfig::bootstrap("test-secret".into(), "node-1".into());
        cfg_a.net.listen_port = b_port;
        cfg_a.nodes.push(NodeEntry {
            id: 2,
            name: "node-2".into(),
            public_key: None,
            address: None,
            ssh: Some(SshDial { host: "127.0.0.1".into(), port, user: current_user() }),
        });
        cfg_a.recompute_hash();
        let state_a = Arc::new(crate::transport::NodeState::new(cfg_a));
        *state_a.tunnels.lock().await = Some(
            TunnelManager::new(&keys.secret_hex, dir.join("ssh_known_hosts")).unwrap(),
        );

        let client = crate::transport::NodeClient::new("test-secret".into(), 1);
        let res = crate::transport::gossip_round(&state_a, &client).await;
        assert_eq!(res.len(), 1);
        assert!(res[0].1.is_some(), "gossip must succeed through the ssh tunnel");

        // push-pull through the tunnel: A adopted B's snapshot (2 nodes known)
        assert_eq!(state_a.cfg.read().unwrap().nodes.len(), 2);
        // tunnel contact counts as direct liveness evidence (M2.6 decision:
        // else a NAT-only mesh never converges on a parent)
        assert!(
            state_a.evidence.read().unwrap().contains_key(&2),
            "tunnel gossip must refresh liveness evidence for the peer"
        );
        // honest edge latency recorded
        assert!(state_a
            .cfg
            .read()
            .unwrap()
            .edges
            .iter()
            .any(|e| e.a == 1 && e.b == 2 && e.latency_ms.is_some()));
        // TOFU pin: exactly one line, for this sshd
        let pins = std::fs::read_to_string(dir.join("ssh_known_hosts")).unwrap();
        assert_eq!(pins.lines().count(), 1, "one pin: {pins}");
        assert!(pins.starts_with(&format!("127.0.0.1:{port} SHA256:")));

        // round 2: live tunnel is REUSED (no new pin, no rebuild), still ok
        let res2 = crate::transport::gossip_round(&state_a, &client).await;
        assert!(res2[0].1.is_some());
        assert_eq!(
            std::fs::read_to_string(dir.join("ssh_known_hosts")).unwrap().lines().count(),
            1
        );
        assert_eq!(state_a.tunnels.lock().await.as_ref().unwrap().len(), 1);

        drop(sshd);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn tunnel_used_when_direct_http_fails() {
        if !sshd_available() {
            eprintln!("skipping: no /usr/sbin/sshd or ssh-keygen");
            return;
        }
        let dir = fixture_dir("fallback");
        let keys = crate::crypto::KeyPair::generate();
        let auth_line = openssh_public_line(&keys.public_hex).unwrap();
        let port = free_port();
        let mut sshd = spawn_sshd(&dir, &auth_line, port).expect("spawn sshd");
        wait_sshd(&mut sshd).await;

        let (_state_b, b_port) = spawn_nat_peer("test-secret").await;

        // B's "direct" address is a black hole (nothing on port 1):
        // refused instantly, then the tunnel must carry the round.
        let mut cfg_a = NetworkConfig::bootstrap("test-secret".into(), "node-1".into());
        cfg_a.net.listen_port = b_port;
        cfg_a.nodes.push(NodeEntry {
            id: 2,
            name: "node-2".into(),
            public_key: None,
            address: Some("127.0.0.1:1".into()),
            ssh: Some(SshDial { host: "127.0.0.1".into(), port, user: current_user() }),
        });
        cfg_a.recompute_hash();
        let state_a = Arc::new(crate::transport::NodeState::new(cfg_a));
        *state_a.tunnels.lock().await = Some(
            TunnelManager::new(&keys.secret_hex, dir.join("ssh_known_hosts")).unwrap(),
        );

        let client = crate::transport::NodeClient::new("test-secret".into(), 1);
        let res = crate::transport::gossip_round(&state_a, &client).await;
        assert!(res[0].1.is_some(), "direct fails, tunnel must deliver gossip");
        assert_eq!(state_a.cfg.read().unwrap().nodes.len(), 2);

        drop(sshd);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn tofu_host_key_mismatch_is_hard_fail() {
        if !sshd_available() {
            eprintln!("skipping: no /usr/sbin/sshd or ssh-keygen");
            return;
        }
        let dir = fixture_dir("tofu");
        let keys = crate::crypto::KeyPair::generate();
        let auth_line = openssh_public_line(&keys.public_hex).unwrap();
        let port = free_port();
        let mut sshd = spawn_sshd(&dir, &auth_line, port).expect("spawn sshd");
        wait_sshd(&mut sshd).await;
        let (_state_b, b_port) = spawn_nat_peer("test-secret").await;

        // pre-pin a DIFFERENT host key for this host:port (simulated MITM)
        std::fs::write(
            dir.join("ssh_known_hosts"),
            format!("127.0.0.1:{port} SHA256:FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFA=\n"),
        )
        .unwrap();

        let mut cfg_a = NetworkConfig::bootstrap("test-secret".into(), "node-1".into());
        cfg_a.net.listen_port = b_port;
        cfg_a.nodes.push(NodeEntry {
            id: 2,
            name: "node-2".into(),
            public_key: None,
            address: None,
            ssh: Some(SshDial { host: "127.0.0.1".into(), port, user: current_user() }),
        });
        cfg_a.recompute_hash();
        let state_a = Arc::new(crate::transport::NodeState::new(cfg_a));
        *state_a.tunnels.lock().await = Some(
            TunnelManager::new(&keys.secret_hex, dir.join("ssh_known_hosts")).unwrap(),
        );

        let client = crate::transport::NodeClient::new("test-secret".into(), 1);
        let res = crate::transport::gossip_round(&state_a, &client).await;
        assert!(res[0].1.is_none(), "host key mismatch must fail the round");
        assert!(state_a.tunnels.lock().await.as_ref().unwrap().is_empty());
        // pin untouched
        let pins = std::fs::read_to_string(dir.join("ssh_known_hosts")).unwrap();
        assert!(pins.contains("SHA256:FAKEFAKE"));

        drop(sshd);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn tunnel_auth_rejection_fails_closed() {
        if !sshd_available() {
            eprintln!("skipping: no /usr/sbin/sshd or ssh-keygen");
            return;
        }
        let dir = fixture_dir("authrej");
        let keys = crate::crypto::KeyPair::generate();
        // sshd whose authorized_keys does NOT know our key
        let port = free_port();
        let mut sshd = spawn_sshd(&dir, "", port).expect("spawn sshd");
        wait_sshd(&mut sshd).await;
        let (_state_b, b_port) = spawn_nat_peer("test-secret").await;

        let mut cfg_a = NetworkConfig::bootstrap("test-secret".into(), "node-1".into());
        cfg_a.net.listen_port = b_port;
        cfg_a.nodes.push(NodeEntry {
            id: 2,
            name: "node-2".into(),
            public_key: None,
            address: None,
            ssh: Some(SshDial { host: "127.0.0.1".into(), port, user: current_user() }),
        });
        cfg_a.recompute_hash();
        let state_a = Arc::new(crate::transport::NodeState::new(cfg_a));
        *state_a.tunnels.lock().await = Some(
            TunnelManager::new(&keys.secret_hex, dir.join("ssh_known_hosts")).unwrap(),
        );

        let client = crate::transport::NodeClient::new("test-secret".into(), 1);
        let res = crate::transport::gossip_round(&state_a, &client).await;
        assert!(res[0].1.is_none(), "rejected pubkey auth must fail the round");
        assert!(state_a.tunnels.lock().await.as_ref().unwrap().is_empty());

        drop(sshd);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
