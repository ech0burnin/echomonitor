//! Dual logging: human-readable `.log` + machine-readable `.jsonl`,
//! both size-rotated (rename to `.1` when the file outgrows the limit).

use std::fs::{File, OpenOptions};
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, Once};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::prelude::*;

const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024; // 10 MiB per file
static INIT: Once = Once::new();

pub struct SizeRotatingWriter {
    path: PathBuf,
    max_bytes: u64,
    state: Mutex<Option<File>>,
}

impl SizeRotatingWriter {
    fn new(path: PathBuf, max_bytes: u64) -> Self {
        Self {
            path,
            max_bytes,
            state: Mutex::new(None),
        }
    }

    fn rotate_if_needed(&self) {
        if let Ok(md) = std::fs::metadata(&self.path) {
            if md.len() >= self.max_bytes {
                let mut rotated = self.path.clone().into_os_string();
                rotated.push(".1");
                let _ = std::fs::rename(&self.path, rotated);
            }
        }
    }

    fn open(&self) -> std::io::Result<File> {
        OpenOptions::new().create(true).append(true).open(&self.path)
    }
}

/// Cloneable shared handle to a `&'static` rotating writer.
/// Implementing `MakeWriter` on a plain owned handle (not a reference)
/// is what satisfies the higher-ranked bound `with_writer` demands.
#[derive(Clone, Copy)]
pub struct SharedWriter(&'static SizeRotatingWriter);

impl SharedWriter {
    fn leak(path: PathBuf, max_bytes: u64) -> Self {
        Self(Box::leak(Box::new(SizeRotatingWriter::new(path, max_bytes))))
    }
}

impl<'a> MakeWriter<'a> for SharedWriter {
    type Writer = SizeWriter<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        SizeWriter(self.0)
    }
}

pub struct SizeWriter<'a>(&'a SizeRotatingWriter);

impl IoWrite for SizeWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.rotate_if_needed();
        let mut guard = self.0.state.lock().expect("log writer lock poisoned");
        if guard.is_none() {
            *guard = Some(self.0.open()?);
        }
        if let Some(f) = guard.as_mut() {
            f.write_all(buf)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut guard = self.0.state.lock().expect("log writer lock poisoned");
        if let Some(f) = guard.as_mut() {
            f.flush()?;
        }
        Ok(())
    }
}

/// Initialise global tracing with two sinks (human `.log` + json `.jsonl`),
/// one shared `EnvFilter` for both. Safe to call multiple times (first wins).
pub fn init(logs_dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(logs_dir)?;

    INIT.call_once(|| {
        let human = SharedWriter::leak(logs_dir.join("echomonitor.log"), MAX_LOG_BYTES);
        let jsonl = SharedWriter::leak(logs_dir.join("echomonitor.jsonl"), MAX_LOG_BYTES);

        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

        let human_layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(human);

        let json_layer = tracing_subscriber::fmt::layer()
            .json()
            .with_ansi(false)
            .with_writer(jsonl);

        tracing_subscriber::registry()
            .with(filter)
            .with(human_layer)
            .with(json_layer)
            .init();
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotates_when_over_limit() {
        let dir = std::env::temp_dir().join("em-log-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.log");
        std::fs::write(&path, vec![b'x'; 64]).unwrap();
        let w = SizeRotatingWriter::new(path.clone(), 64);
        w.rotate_if_needed();
        assert!(dir.join("t.log.1").exists());
        assert!(!path.exists());
    }
}
