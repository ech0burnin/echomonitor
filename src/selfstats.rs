//! Self-observation: local RAM/LOAD/DISK stats (M3.4) and systemd unit
//! liveness (M3.6).
//!
//! Pure parsers take `&str` so they are testable on fixtures without
//! touching the real `/proc`. Only [`SelfStats::collect`] and
//! [`collect_units`] read live data. Stats are local-only; unit statuses
//! additionally ride in the node's `/api/state` reply (runtime data,
//! ignored by peers during gossip merges). Surfaced through `cli status`.

use anyhow::{anyhow, Context, Result};
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Filesystem mount observed by default. Hardcoded on purpose: no config
/// surface for self stats (config schema is frozen by the owner).
pub const DISK_PATH: &str = "/";

/// Kernel memory snapshot, straight from `/proc/meminfo` (values in KiB).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MemStats {
    pub total_kb: u64,
    pub available_kb: u64,
    /// used = total - available, as a percentage of total.
    pub used_pct: f64,
}

/// Run queue averages from `/proc/loadavg`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LoadStats {
    pub one: f64,
    pub five: f64,
    pub fifteen: f64,
    pub running: u32,
    pub total_procs: u32,
}

/// Filesystem usage via statvfs(3).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DiskStats {
    pub total_bytes: u64,
    /// Free for unprivileged users (f_bavail, not f_bfree).
    pub free_bytes: u64,
    pub used_pct: f64,
}

/// Everything [`SelfStats::collect`] gathers in one shot.
#[derive(Debug, Clone, Copy)]
pub struct SelfStats {
    pub mem: MemStats,
    pub load: LoadStats,
    pub disk: DiskStats,
    /// Unix timestamp (seconds) of the moment this snapshot was taken.
    pub collected_at: u64,
}

/// Percentage of `total` that `used` occupies; 0.0 when total is 0
/// (statvfs on a weird mount) instead of NaN.
fn pct_used(total: u64, used: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    used as f64 / total as f64 * 100.0
}

/// Parse `/proc/meminfo` contents.
///
/// `available` = `MemAvailable` when present (kernels >= 3.14), otherwise
/// the classic estimate `MemFree + Buffers + Cached` for old kernels.
/// Lines that don't look like `Key: 123 kB` are skipped; a missing
/// `MemTotal` (or missing fallback inputs) is an error.
pub fn parse_meminfo(content: &str) -> Result<MemStats> {
    let mut total_kb = None;
    let mut mem_available = None;
    let mut mem_free = None;
    let mut buffers = None;
    let mut cached = None;

    for line in content.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        // Values look like "  16265984 kB" — take the number, ignore the unit.
        let Some(first) = rest.split_whitespace().next() else {
            continue;
        };
        let Ok(num) = first.parse::<u64>() else {
            continue;
        };
        match key.trim() {
            "MemTotal" => total_kb = Some(num),
            "MemAvailable" => mem_available = Some(num),
            "MemFree" => mem_free = Some(num),
            "Buffers" => buffers = Some(num),
            "Cached" => cached = Some(num),
            _ => {}
        }
    }

    let total_kb = total_kb.context("meminfo: MemTotal missing")?;
    let available_kb = match mem_available {
        Some(a) => a,
        None => {
            // Old kernel fallback: MemFree + Buffers + Cached. All three
            // are required — a partial estimate would silently lie.
            let f = mem_free.context("meminfo: MemAvailable missing, MemFree missing")?;
            let b = buffers.context("meminfo: MemAvailable missing, Buffers missing")?;
            let c = cached.context("meminfo: MemAvailable missing, Cached missing")?;
            f + b + c
        }
    };

    let used = total_kb.saturating_sub(available_kb);
    Ok(MemStats {
        total_kb,
        available_kb,
        used_pct: pct_used(total_kb, used),
    })
}

/// Parse `/proc/loadavg` contents: `"0.20 0.18 0.12 1/389 12345"`.
///
/// Fields: 1m 5m 15m running/total last_pid. The last_pid tail is ignored.
pub fn parse_loadavg(content: &str) -> Result<LoadStats> {
    let mut fields = content.split_whitespace();
    let mut parse_field = |name: &str| -> Result<f64> {
        let raw = fields
            .next()
            .with_context(|| format!("loadavg: {name} missing"))?;
        raw.parse::<f64>()
            .with_context(|| format!("loadavg: bad {name} value {raw:?}"))
    };
    let one = parse_field("1min")?;
    let five = parse_field("5min")?;
    let fifteen = parse_field("15min")?;

    let procs = fields
        .next()
        .context("loadavg: running/total field missing")?;
    let (running, total) = procs
        .split_once('/')
        .context("loadavg: running/total field has no '/'")?;
    let running = running
        .parse::<u32>()
        .with_context(|| format!("loadavg: bad running count {running:?}"))?;
    let total_procs = total
        .parse::<u32>()
        .with_context(|| format!("loadavg: bad total procs count {total:?}"))?;

    Ok(LoadStats {
        one,
        five,
        fifteen,
        running,
        total_procs,
    })
}

/// statvfs-based usage for any path (use [`DISK_PATH`] for the root fs).
///
/// `free_bytes` uses `f_bavail` (what an unprivileged process can still
/// write), which is what monitoring dashboards usually mean by "free".
pub fn disk_stats(path: &str) -> io::Result<DiskStats> {
    let st = nix::sys::statvfs::statvfs(Path::new(path)).map_err(io::Error::other)?;
    let block = st.block_size();
    let total_bytes = st.blocks().saturating_mul(block);
    let free_bytes = st.blocks_available().saturating_mul(block);
    let used = total_bytes.saturating_sub(free_bytes);
    Ok(DiskStats {
        total_bytes,
        free_bytes,
        used_pct: pct_used(total_bytes, used),
    })
}

impl SelfStats {
    /// Gather a live snapshot from `/proc/meminfo`, `/proc/loadavg` and
    /// `statvfs("/")` on this host. Never panics; any failure is an error.
    pub fn collect() -> Result<SelfStats> {
        let mem_raw = std::fs::read_to_string("/proc/meminfo")
            .context("cannot read /proc/meminfo")?;
        let mem = parse_meminfo(&mem_raw)?;

        let load_raw = std::fs::read_to_string("/proc/loadavg")
            .context("cannot read /proc/loadavg")?;
        let load = parse_loadavg(&load_raw)?;

        let disk =
            disk_stats(DISK_PATH).map_err(|e| anyhow!("statvfs({DISK_PATH}): {e}"))?;

        let collected_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(SelfStats {
            mem,
            load,
            disk,
            collected_at,
        })
    }
}

// ---------- M3.6: systemd unit liveness ----------

/// One systemd unit's liveness, as observed via `systemctl is-active`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct UnitStatus {
    pub name: String,
    pub active: bool,
}

/// Per-unit wall-clock budget for one `systemctl is-active` probe.
pub const UNIT_CHECK_TIMEOUT_SECS: u64 = 2;

/// Map a child's exit code to `active`.
///
/// `systemctl is-active <unit> --quiet` exits 0 only for an active unit;
/// any other code (3 = inactive/dead, 4 = missing unit, signals, spawn
/// failure rendered as `None`) means "not active". Keeping this a pure
/// function makes the mapping unit-testable without systemd.
pub fn exit_code_to_active(code: Option<i32>) -> bool {
    code == Some(0)
}

/// Probe every configured unit with `systemctl is-active --quiet`.
///
/// Units are probed concurrently, each capped at
/// [`UNIT_CHECK_TIMEOUT_SECS`]; results come back in input order. Errors
/// of any kind (missing systemctl binary, timeout, unit gone, signal)
/// yield `active: false` for that unit and never abort the round.
pub async fn collect_units(names: &[String]) -> Vec<UnitStatus> {
    use std::process::Stdio;
    use tokio::task::JoinSet;

    let mut set: JoinSet<(usize, UnitStatus)> = JoinSet::new();
    for (idx, name) in names.iter().enumerate() {
        let name = name.clone();
        set.spawn(async move {
            let probe = tokio::process::Command::new("systemctl")
                .arg("is-active")
                .arg(&name)
                .arg("--quiet")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            // Probe outcome only matters for the exit code; output is noise.
            let active = match tokio::time::timeout(
                std::time::Duration::from_secs(UNIT_CHECK_TIMEOUT_SECS),
                probe,
            )
            .await
            {
                Ok(Ok(st)) => exit_code_to_active(st.code()),
                _ => false,
            };
            (idx, UnitStatus { name, active })
        });
    }

    let mut slots: Vec<Option<UnitStatus>> = (0..names.len()).map(|_| None).collect();
    while let Some(joined) = set.join_next().await {
        // A panicked task is an error like any other: leave the slot
        // empty; it becomes active:false below. The round never aborts.
        if let Ok((idx, us)) = joined {
            slots[idx] = Some(us);
        }
    }
    slots
        .into_iter()
        .zip(names)
        .map(|(slot, name)| {
            slot.unwrap_or(UnitStatus {
                name: name.clone(),
                active: false,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MEMINFO_FULL: &str = "MemTotal:       16265984 kB
\
        MemFree:         2468152 kB
\
        MemAvailable:    9876543 kB
\
        Buffers:          512340 kB
\
        Cached:          6400234 kB
\
        SwapTotal:             0 kB
\
        SwapFree:              0 kB
";

    const MEMINFO_OLD_KERNEL: &str = "MemTotal:       8000000 kB
\
        MemFree:         1000000 kB
\
        Buffers:          200000 kB
\
        Cached:           800000 kB
\
        Active:          4000000 kB
";

    fn assert_close(actual: f64, expected: f64) {
        assert!(
            (actual - expected).abs() < 1e-9,
            "actual {actual} != expected {expected}"
        );
    }

    #[test]
    fn meminfo_full_with_mem_available() {
        let m = parse_meminfo(MEMINFO_FULL).expect("full fixture must parse");
        assert_eq!(m.total_kb, 16_265_984);
        assert_eq!(m.available_kb, 9_876_543);
        // used = 16265984 - 9876543 = 6389441
        assert_close(m.used_pct, 6_389_441.0 / 16_265_984.0 * 100.0);
    }

    #[test]
    fn meminfo_fallback_without_mem_available() {
        let m = parse_meminfo(MEMINFO_OLD_KERNEL).expect("fallback fixture must parse");
        assert_eq!(m.total_kb, 8_000_000);
        // available = MemFree + Buffers + Cached = 1000000 + 200000 + 800000
        assert_eq!(m.available_kb, 2_000_000);
        assert_close(m.used_pct, 75.0);
    }

    #[test]
    fn meminfo_garbage_is_error() {
        assert!(parse_meminfo("this is not procfs").is_err());
    }

    #[test]
    fn meminfo_missing_total_is_error() {
        let no_total = "MemFree: 123 kB\nMemAvailable: 100 kB\n";
        assert!(parse_meminfo(no_total).is_err());
    }

    #[test]
    fn meminfo_fallback_partial_inputs_is_error() {
        // No MemAvailable, has MemFree but no Buffers/Cached: refuse to
        // silently underestimate availability.
        let partial = "MemTotal: 1000 kB\nMemFree: 500 kB\n";
        assert!(parse_meminfo(partial).is_err());
    }

    #[test]
    fn loadavg_valid() {
        let l = parse_loadavg("0.20 0.18 0.12 1/389 12345").expect("valid loadavg");
        assert_close(l.one, 0.20);
        assert_close(l.five, 0.18);
        assert_close(l.fifteen, 0.12);
        assert_eq!(l.running, 1);
        assert_eq!(l.total_procs, 389);
    }

    #[test]
    fn loadavg_garbage_is_error() {
        assert!(parse_loadavg("garbage").is_err());
    }

    #[test]
    fn loadavg_missing_procs_field_is_error() {
        assert!(parse_loadavg("0.5 0.4 0.3").is_err());
    }

    #[test]
    fn pct_used_arithmetic() {
        assert_close(pct_used(1000, 750), 75.0);
        assert_close(pct_used(1000, 0), 0.0);
        assert_close(pct_used(1000, 1000), 100.0);
        // Degenerate mounts must not produce NaN.
        assert_close(pct_used(0, 0), 0.0);
    }

    #[test]
    fn live_collect_works_on_linux() {
        // Not a /proc-independent test, but a smoke check that the real
        // files on this host parse; keeps collect() honest.
        let s = SelfStats::collect().expect("live collect on linux host");
        assert!(s.mem.total_kb > 0);
        assert!(s.mem.used_pct >= 0.0 && s.mem.used_pct <= 100.0);
        assert!(s.load.total_procs > 0);
        assert!(s.disk.total_bytes > 0);
        assert!(s.collected_at > 0);
    }

    // ---------- M3.6: systemd units ----------

    #[test]
    fn exit_code_to_active_mapping() {
        // exit 0 (is-active --quiet on an active unit) -> active
        assert!(exit_code_to_active(Some(0)));
        // 3 = inactive, 4 = missing unit, anything else nonzero -> dead
        assert!(!exit_code_to_active(Some(3)));
        assert!(!exit_code_to_active(Some(4)));
        assert!(!exit_code_to_active(Some(1)));
        // killed by signal / never spawned -> dead
        assert!(!exit_code_to_active(None));
    }

    #[test]
    fn unit_status_serde_roundtrip() {
        let us = UnitStatus {
            name: "zeroclaw.service".into(),
            active: true,
        };
        let j = serde_json::to_string(&us).unwrap();
        assert_eq!(j, r#"{"name":"zeroclaw.service","active":true}"#);
        let back: UnitStatus = serde_json::from_str(&j).unwrap();
        assert_eq!(back, us);
    }

    #[tokio::test]
    async fn collect_units_empty_input_is_empty_output() {
        assert!(collect_units(&[]).await.is_empty());
    }

    #[tokio::test]
    async fn collect_units_bad_units_report_dead_in_order() {
        // Units that cannot be active (they do not exist) must come back
        // dead, in input order, one entry per input — never an error and
        // never a dropped entry. Works with or without systemd present:
        // a missing systemctl binary is a spawn error -> dead too.
        let names: Vec<String> = ["no-such-unit-a.service", "no-such-unit-b.service"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let out = collect_units(&names).await;
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].name, "no-such-unit-a.service");
        assert_eq!(out[1].name, "no-such-unit-b.service");
        assert!(!out[0].active);
        assert!(!out[1].active);
    }
}
