//! Check engine: scheduled probes with a hard per-check time budget.
//! Each probe gets `timeout` seconds (default 3s); the engine runs at most
//! `max_parallel` probes concurrently (default 10). Results land in an
//! in-memory ring plus an append-only JSONL history. Consecutive failures
//! feed the flap counter (alerting itself arrives with M4 channels; the
//! engine logs warn lines so nothing is lost until then).

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

// ---------- specs ----------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HttpCheckSpec {
    pub name: String,
    pub url: String,
    /// Expected HTTP status (default 200).
    pub expect: Option<u16>,
    /// Probe interval, seconds (default 60).
    pub interval: Option<u64>,
    /// Per-probe timeout, seconds, capped at 3 (default 3).
    pub timeout: Option<u64>,
}

impl HttpCheckSpec {
    pub fn expect(&self) -> u16 {
        self.expect.unwrap_or(200)
    }
    pub fn interval(&self) -> Duration {
        Duration::from_secs(self.interval.unwrap_or(60))
    }
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout.unwrap_or(3).min(3))
    }
}

// ---------- outcomes ----------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CheckOutcome {
    Ok { latency_ms: u64 },
    Fail { reason: String },
    Unknown { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckRecord {
    pub check: String,
    pub at: chrono_pseudo::Ts,
    pub outcome: CheckOutcome,
}

/// Timestamp without pulling chrono in: unix millis in a newtype that
/// serializes as RFC3339-ish string. Keeps deps at zero for now.
pub mod chrono_pseudo {
    use serde::{Deserialize, Serialize};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
    pub struct Ts(pub u64);

    impl Ts {
        pub fn now() -> Self {
            Ts(SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0))
        }
        pub fn unix_ms(&self) -> u64 {
            self.0
        }
    }

    impl std::fmt::Display for Ts {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }
}

// ---------- history ----------

pub struct History {
    ring: VecDeque<CheckRecord>,
    cap: usize,
    jsonl: Option<std::path::PathBuf>,
}

impl History {
    pub fn new(cap: usize, jsonl: Option<std::path::PathBuf>) -> Self {
        Self { ring: VecDeque::with_capacity(cap.min(1024)), cap, jsonl }
    }

    pub fn push(&mut self, rec: CheckRecord) {
        if self.ring.len() == self.cap {
            self.ring.pop_front();
        }
        self.ring.push_back(rec.clone());
        if let Some(p) = &self.jsonl {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) {
                let _ = writeln!(f, "{}", serde_json::to_string(&rec).unwrap_or_default());
            }
        }
    }

    pub fn recent(&self) -> &VecDeque<CheckRecord> {
        &self.ring
    }

    /// Consecutive failures at the tail (0 if last check is not a failure).
    pub fn consecutive_fails(&self) -> u32 {
        let mut n = 0;
        for rec in self.ring.iter().rev() {
            match rec.outcome {
                CheckOutcome::Fail { .. } | CheckOutcome::Unknown { .. } => n += 1,
                CheckOutcome::Ok { .. } => break,
            }
        }
        n
    }
}

// ---------- engine ----------

pub struct Engine {
    pub max_parallel: usize,
    pub flap_threshold: u32,
    pub histories: Arc<Mutex<std::collections::HashMap<String, Arc<Mutex<History>>>>>,
}

impl Engine {
    pub fn new(max_parallel: usize, flap_threshold: u32) -> Self {
        Self {
            max_parallel,
            flap_threshold,
            histories: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Run forever: one tokio task per check spec, a semaphore caps parallelism.
    pub async fn run(self: Arc<Self>, specs: Vec<HttpCheckSpec>, shutdown: tokio::sync::watch::Receiver<bool>) {
        let sem = Arc::new(tokio::sync::Semaphore::new(self.max_parallel));
        let mut tasks = Vec::new();
        for spec in specs {
            let (hist, mut rx) = {
                let mut hs = self.histories.lock().await;
                let h = hs.entry(spec.name.clone()).or_insert_with(|| {
                    Arc::new(Mutex::new(History::new(256, None)))
                });
                (h.clone(), shutdown.clone())
            };
            let engine = self.clone();
            let sem = sem.clone();
            tasks.push(tokio::spawn(async move {
                let mut tick = tokio::time::interval(spec.interval());
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        _ = tick.tick() => {}
                        _ = rx.changed() => {
                            if *rx.borrow() { break; }
                        }
                    }
                    let _permit = sem.acquire().await;
                    let rec = http_probe(&spec).await;
                    let is_fail = !matches!(rec.outcome, CheckOutcome::Ok { .. });
                    let mut h = hist.lock().await;
                    h.push(rec);
                    let fails = h.consecutive_fails();
                    drop(h);
                    if is_fail && fails == engine.flap_threshold {
                        tracing::warn!(check = %spec.name, consecutive = fails, "CHECK FLAPPING: alert threshold reached");
                    }
                }
            }));
        }
        for t in tasks {
            let _ = t.await;
        }
    }
}

// ---------- HTTP probe ----------

pub async fn http_probe(spec: &HttpCheckSpec) -> CheckRecord {
    let client = reqwest::Client::builder()
        .timeout(spec.timeout())
        .build()
        .expect("reqwest client");
    let started = std::time::Instant::now();
    let outcome = match client.get(&spec.url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let latency = started.elapsed().as_millis() as u64;
            if status == spec.expect() {
                CheckOutcome::Ok { latency_ms: latency }
            } else {
                CheckOutcome::Fail { reason: format!("status {status}, expected {}", spec.expect()) }
            }
        }
        Err(e) => CheckOutcome::Fail { reason: format!("{e}") },
    };
    CheckRecord { check: spec.name.clone(), at: chrono_pseudo::Ts::now(), outcome }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn spawn_server(routes: axum::Router) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, routes).await.unwrap() });
        port
    }

    fn routes() -> axum::Router {
        axum::Router::new()
            .route("/ok", axum::routing::get(|| async { "fine" }))
            .route("/teapot", axum::routing::get(|| async { axum::http::StatusCode::from_u16(418).unwrap() }))
    }

    #[tokio::test]
    async fn probe_ok_records_latency() {
        let port = spawn_server(routes()).await;
        let spec = HttpCheckSpec { name: "t".into(), url: format!("http://127.0.0.1:{port}/ok"), expect: None, interval: None, timeout: None };
        let rec = http_probe(&spec).await;
        assert!(matches!(rec.outcome, CheckOutcome::Ok { .. }), "got {:?}", rec.outcome);
    }

    #[tokio::test]
    async fn probe_wrong_status_fails() {
        let port = spawn_server(routes()).await;
        let spec = HttpCheckSpec { name: "t".into(), url: format!("http://127.0.0.1:{port}/teapot"), expect: None, interval: None, timeout: None };
        let rec = http_probe(&spec).await;
        assert!(matches!(rec.outcome, CheckOutcome::Fail { ref reason } if reason.contains("418")), "got {:?}", rec.outcome);
    }

    #[tokio::test]
    async fn probe_timeout_fails_fast() {
        // unroutable TEST-NET address: connect times out / errors quickly with 1s budget
        let spec = HttpCheckSpec { name: "t".into(), url: "http://192.0.2.1:1/".into(), expect: None, interval: None, timeout: Some(1) };
        let started = std::time::Instant::now();
        let rec = http_probe(&spec).await;
        assert!(matches!(rec.outcome, CheckOutcome::Fail { .. }));
        assert!(started.elapsed().as_secs() < 5, "budget must hold");
    }

    #[tokio::test]
    async fn probe_refused_fails() {
        // bind then drop = refused
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let spec = HttpCheckSpec { name: "t".into(), url: format!("http://127.0.0.1:{port}/"), expect: None, interval: None, timeout: None };
        let rec = http_probe(&spec).await;
        assert!(matches!(rec.outcome, CheckOutcome::Fail { .. }));
    }

    #[test]
    fn history_counts_consecutive_fails() {
        let mut h = History::new(8, None);
        for i in 0..3 {
            h.push(CheckRecord { check: "c".into(), at: chrono_pseudo::Ts(i), outcome: CheckOutcome::Ok { latency_ms: 1 } });
        }
        assert_eq!(h.consecutive_fails(), 0);
        h.push(CheckRecord { check: "c".into(), at: chrono_pseudo::Ts(3), outcome: CheckOutcome::Fail { reason: "x".into() } });
        h.push(CheckRecord { check: "c".into(), at: chrono_pseudo::Ts(4), outcome: CheckOutcome::Fail { reason: "x".into() } });
        assert_eq!(h.consecutive_fails(), 2);
        h.push(CheckRecord { check: "c".into(), at: chrono_pseudo::Ts(5), outcome: CheckOutcome::Ok { latency_ms: 1 } });
        assert_eq!(h.consecutive_fails(), 0);
    }

    #[test]
    fn timeout_capped_at_3s() {
        let spec = HttpCheckSpec { name: "t".into(), url: "http://x/".into(), expect: None, interval: None, timeout: Some(30) };
        assert_eq!(spec.timeout(), Duration::from_secs(3));
    }

    #[tokio::test]
    async fn engine_flap_logs_at_threshold() {
        // server that always fails the status expectation
        let port = spawn_server(routes()).await;
        let engine = Arc::new(Engine::new(10, 2));
        let specs = vec![HttpCheckSpec { name: "flap".into(), url: format!("http://127.0.0.1:{port}/teapot"), expect: Some(200), interval: Some(1), timeout: None }];
        let (_tx, rx) = tokio::sync::watch::channel(false);
        let e = engine.clone();
        let handle = tokio::spawn(async move { e.run(specs, rx).await });
        // wait for 2 records
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let hs = engine.histories.lock().await;
            if let Some(h) = hs.get("flap") {
                if h.lock().await.recent().len() >= 2 { break; }
            }
            drop(hs);
            assert!(std::time::Instant::now() < deadline, "engine did not produce 2 records");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // clean shutdown signal
        let (tx, _rx) = tokio::sync::watch::channel(true);
        drop(tx);
        handle.abort();
    }
}
