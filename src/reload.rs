use crate::policy::CompiledPolicy;
use anyhow::{Context, Result};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Condvar, Mutex, RwLock},
    thread::{self, JoinHandle},
    time::Duration,
};

struct Shared {
    path: PathBuf,
    active: RwLock<Arc<CompiledPolicy>>,
    // Serializes reloads so an older concurrent reload cannot overwrite a newer one.
    source: Mutex<Vec<u8>>,
}

/// Cheap, read-only handle for future proxy components.
#[derive(Clone)]
pub struct PolicyReader(Arc<Shared>);

impl PolicyReader {
    /// Readers keep a consistent snapshot even if a reload occurs mid-request.
    pub fn snapshot(&self) -> Arc<CompiledPolicy> {
        Arc::clone(&self.0.active.read().expect("policy lock poisoned"))
    }
}

/// Owns the polling worker. Dropping it wakes and joins the worker.
pub struct PolicyManager {
    reader: PolicyReader,
    stop: Arc<(Mutex<bool>, Condvar)>,
    worker: Option<JoinHandle<()>>,
}

impl PolicyManager {
    pub fn start(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let source = fs::read(&path).context("cannot read initial policy")?;
        let policy = parse(&source).context("initial policy rejected")?;
        let reader = PolicyReader(Arc::new(Shared {
            path,
            active: RwLock::new(Arc::new(policy)),
            source: Mutex::new(source),
        }));
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let worker_reader = reader.clone();
        let worker_stop = Arc::clone(&stop);
        let worker = thread::Builder::new().name("policy-reload".into()).spawn(move || {
            let mut last_error = None;
            loop {
                let snapshot = worker_reader.snapshot();
                let interval = Duration::from_millis(snapshot.engine().hot_reload.watch_interval_ms);
                let (lock, wake) = &*worker_stop;
                let (stopped, _) = wake.wait_timeout_while(
                    lock.lock().expect("stop lock poisoned"), interval, |stop| !*stop,
                ).expect("stop lock poisoned");
                if *stopped { break; }
                drop(stopped);
                if !snapshot.engine().hot_reload.enabled { continue; }
                match reload(&worker_reader.0, true) {
                    Ok(changed) => {
                        last_error = None;
                        if changed {
                            let active = worker_reader.snapshot();
                            eprintln!("policy activated: id={} last_updated={} rules={} sinks={} reload_enabled={} interval_ms={}",
                                active.policy_id(), active.last_updated(), active.rules().len(), active.sinks().len(),
                                active.engine().hot_reload.enabled, active.engine().hot_reload.watch_interval_ms);
                        }
                    }
                    Err(error) => {
                        let message = format!("{error:#}");
                        if last_error.as_ref() != Some(&message) {
                            eprintln!("policy reload rejected; retaining last valid policy: {message}");
                            last_error = Some(message);
                        }
                    }
                }
            }
        }).context("cannot start policy reload worker")?;
        Ok(Self {
            reader,
            stop,
            worker: Some(worker),
        })
    }

    pub fn reader(&self) -> PolicyReader {
        self.reader.clone()
    }

    /// Explicit reload is available even when automatic reloading is disabled.
    /// Returns true only when new validated content replaces the active snapshot.
    pub fn reload_now(&self) -> Result<bool> {
        reload(&self.reader.0, false)
    }
}

impl Drop for PolicyManager {
    fn drop(&mut self) {
        let (lock, wake) = &*self.stop;
        *lock.lock().expect("stop lock poisoned") = true;
        wake.notify_all();
        if let Some(worker) = self.worker.take() {
            // A panic is diagnostic; never replace configuration with a fallback.
            if worker.join().is_err() {
                eprintln!("policy reload worker panicked");
            }
        }
    }
}

fn parse(bytes: &[u8]) -> Result<CompiledPolicy> {
    CompiledPolicy::from_yaml(std::str::from_utf8(bytes).context("policy must be UTF-8")?)
}

fn reload(shared: &Shared, automatic: bool) -> Result<bool> {
    let mut source = shared.source.lock().expect("reload lock poisoned");
    if automatic
        && !shared
            .active
            .read()
            .expect("policy lock poisoned")
            .engine()
            .hot_reload
            .enabled
    {
        return Ok(false);
    }
    // Compare content rather than mtime: supports atomic file replacement and rapid edits.
    let candidate = fs::read(&shared.path).context("cannot read updated policy")?;
    if *source == candidate {
        return Ok(false);
    }
    let policy = Arc::new(parse(&candidate)?);
    *shared.active.write().expect("policy lock poisoned") = policy;
    *source = candidate;
    Ok(true)
}
