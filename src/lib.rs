//! echomonitor library root. The daemon modules live here so the binary
//! (`src/main.rs`) and integration tests (`tests/`) share one code path —
//! M2.7's failover test drives the same gossip/election loop as `run`.

pub mod checks;
pub mod cli;
pub mod config;
pub mod crypto;
pub mod elector;
pub mod logging;
pub mod routing;
pub mod selfstats;
pub mod sitereport;
pub mod transport;
pub mod tunnel;
