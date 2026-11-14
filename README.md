# Echoeye

**Self-hosted distributed mesh monitoring. One static binary. Zero dependencies on the target host.**

> 🦇 Named after echo — a bat that finds its way by listening to the network.

## What is this?

Echoeye is a lightweight, self-hosted monitoring system for small fleets of servers:

- **Mesh network of nodes** — gossip topology discovery, latency-based routing, automatic parent (leader) election. No single point of failure: the network config is replicated to every node.
- **One static binary** (musl, x86_64 + aarch64) — the web UI is embedded, nothing to install on target servers.
- **SSH-based auto-deploy** — the parent node generates a keypair; you drop the public key into `authorized_keys`, and the parent ships the binary + systemd unit + config to a new node by itself.
- **Checks**: SSH connectivity matrix between all node pairs, HTTP probes from every node (consolidated reports, deviation-focused), RAM/DISK/LOAD self-monitoring, Docker containers, systemd units, alert-channel health.
- **Alert channels**: ntfy (critical only), Telegram and Matrix (full monitoring) — with channel diversification across nodes and automatic bot migration if a channel becomes unreachable.
- **Passbot**: scheduled delivery of KeePass databases via Telegram/Matrix.

## Addressing

Node `address` and `ssh.host` accept **domains as well as IPs** (`host:port`; IPv6 literals need `[::1]:8687` brackets). Domains are the canonical way to address a node — fleet IPs drift, DNS does not. Names are resolved at dial time, and the SSH TOFU pin is keyed on the configured `host:port` string, so a domain-keyed pin survives IP rotation.

## Status

**Work in progress.** Architecture settled, implementation ongoing.

## Building

```bash
cargo build --release
```

Requires Rust 1.75+.

## License

[MIT](LICENSE)
