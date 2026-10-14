use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};

use crate::config::state_dir;

/// Health status of a proxy
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// Not yet checked
    #[default]
    Unknown,
    /// Passing health checks
    Healthy,
    /// Slow but working
    Degraded,
    /// Failing health checks
    Unhealthy,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => write!(f, "unknown"),
            Self::Healthy => write!(f, "healthy"),
            Self::Degraded => write!(f, "degraded"),
            Self::Unhealthy => write!(f, "unhealthy"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct ProxyStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub last_active: Option<DateTime<Utc>>,
    pub activated_at: Option<DateTime<Utc>>,
    pub ping_avg_ms: Option<f64>,
    pub ping_samples: u64,
    pub last_ping_at: Option<DateTime<Utc>>,
    /// Current health status
    #[serde(default)]
    pub health_status: HealthStatus,
    /// Number of consecutive health check failures
    #[serde(default)]
    pub consecutive_failures: u32,
    /// When the last health check was performed
    #[serde(default)]
    pub last_health_check: Option<DateTime<Utc>>,
    /// When the proxy was last known to be healthy
    #[serde(default)]
    pub last_healthy: Option<DateTime<Utc>>,
    /// Reason for the last health check failure
    #[serde(default)]
    pub last_failure_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct State {
    pub proxies: HashMap<String, ProxyStats>,
}

impl State {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default())
            }
            Err(error) => return Err(error).context("Failed reading persisted state"),
        };
        if let Ok(state) = serde_json::from_slice(&bytes) {
            return Ok(state);
        }
        // A good publication may have replaced what this reader saw. Re-read
        // under the writer lock before quarantining any canonical file.
        let _lock = crate::util::PersistenceLock::acquire(path)?;
        Self::load_locked(path)
    }

    fn load_locked(path: &Path) -> Result<Self> {
        use std::os::unix::ffi::OsStrExt;
        let path = crate::util::publication_path(path)?;
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default())
            }
            Err(error) => return Err(error).context("Failed reading persisted state"),
        };
        match serde_json::from_slice(&bytes) {
            Ok(state) => Ok(state),
            Err(error) => {
                let from = std::ffi::CString::new(path.as_os_str().as_bytes())?;
                for _ in 0..128 {
                    let sidecar = crate::util::unique_sibling(&path, "corrupt");
                    let to = std::ffi::CString::new(sidecar.as_os_str().as_bytes())?;
                    // SAFETY: both live CStrings are NUL-terminated paths; Linux
                    // RENAME_NOREPLACE prevents overwriting any earlier evidence.
                    if unsafe {
                        libc::renameat2(
                            libc::AT_FDCWD,
                            from.as_ptr(),
                            libc::AT_FDCWD,
                            to.as_ptr(),
                            libc::RENAME_NOREPLACE,
                        )
                    } == 0
                    {
                        tracing::warn!(path = %path.display(), %error, "Corrupt state quarantined; using default state");
                        return Ok(Self::default());
                    }
                    let failure = std::io::Error::last_os_error();
                    if failure.kind() != std::io::ErrorKind::AlreadyExists {
                        return Err(failure)
                            .context("Cannot quarantine corrupt state without losing its bytes");
                    }
                }
                anyhow::bail!("No unused corrupt-state quarantine filename available");
            }
        }
    }

    #[cfg(test)]
    fn save(&self, path: &Path) -> Result<()> {
        let _lock = crate::util::PersistenceLock::acquire(path)?;
        self.save_locked(path)
    }

    fn save_locked(&self, path: &Path) -> Result<()> {
        crate::util::atomic_write(path, serde_json::to_string_pretty(self)?.as_bytes())
    }

    pub fn update(path: &Path, mutate: impl FnOnce(&mut Self)) -> Result<Self> {
        let _lock = crate::util::PersistenceLock::acquire(path)?;
        let mut latest = Self::load_locked(path)?;
        mutate(&mut latest);
        latest.save_locked(path)?;
        Ok(latest)
    }
}

/// Counters and ping samples are additive deltas. Activity/activation use the
/// newest timestamp; only a newly recorded health observation owns health fields.
/// Unchanged cache fields never replace independent disk mutations.
fn merge_state_delta(latest: &mut State, current: &State, baseline: &State) {
    let empty = ProxyStats::default();
    for (id, update) in &current.proxies {
        let before = baseline.proxies.get(id).unwrap_or(&empty);
        let destination = latest.proxies.entry(id.clone()).or_default();
        destination.bytes_sent = destination
            .bytes_sent
            .saturating_add(update.bytes_sent.saturating_sub(before.bytes_sent));
        destination.bytes_received = destination
            .bytes_received
            .saturating_add(update.bytes_received.saturating_sub(before.bytes_received));
        destination.last_active = destination.last_active.max(update.last_active);
        if update.activated_at != before.activated_at {
            destination.activated_at = destination.activated_at.max(update.activated_at);
        }
        let samples = update.ping_samples.saturating_sub(before.ping_samples);
        if samples > 0 {
            let count = destination.ping_samples.saturating_add(samples);
            if let Some(average) = update.ping_avg_ms {
                let previous_average = before.ping_avg_ms.unwrap_or(average);
                let delta_average = average
                    + (average - previous_average) * (before.ping_samples as f64 / samples as f64);
                destination.ping_avg_ms = Some(match destination.ping_avg_ms {
                    Some(existing) => {
                        existing + (delta_average - existing) * (samples as f64 / count as f64)
                    }
                    None => delta_average,
                });
            }
            destination.ping_samples = count;
            destination.last_ping_at = destination.last_ping_at.max(update.last_ping_at);
        }
        if update.last_health_check != before.last_health_check
            && update.last_health_check >= destination.last_health_check
        {
            destination.health_status = update.health_status;
            destination.consecutive_failures = update.consecutive_failures;
            destination.last_health_check = update.last_health_check;
            destination.last_failure_reason = update.last_failure_reason.clone();
        }
        destination.last_healthy = destination.last_healthy.max(update.last_healthy);
    }
}

pub fn state_path() -> Result<PathBuf> {
    let dir = state_dir()?;
    Ok(dir.join("state.json"))
}

/// A display projection of the applied configuration. Credentials are never
/// published, and this projection must never be used to restart the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliedRoutingSnapshot {
    pub config: crate::config::AppConfig,
    pub config_generation: u64,
    pub routing_generation: u64,
    pub pending_restart_fields: Vec<String>,
    pub last_reload_result: String,
    pub last_reload_at: Option<DateTime<Utc>>,
    pub ipset_entry_count: usize,
    pub sources: Vec<RoutingSourceSnapshot>,
}

fn display_health_origin(raw: &str) -> String {
    url::Url::parse(raw)
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_else(|_| "[invalid health URL]".into())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingSourceSnapshot {
    pub source: String,
    pub entry_count: usize,
    pub last_success_at: Option<DateTime<Utc>>,
    pub stale: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_ticks: u64,
    pub boot_id: String,
}

impl ProcessIdentity {
    pub fn current() -> Result<Self> {
        Ok(Self {
            pid: std::process::id(),
            start_ticks: process_start_ticks(std::process::id())?,
            boot_id: fs::read_to_string("/proc/sys/kernel/random/boot_id")?
                .trim()
                .into(),
        })
    }

    fn matches_live_process(&self) -> Result<bool> {
        if fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim() != self.boot_id {
            return Ok(false);
        }
        match process_start_ticks(self.pid) {
            Ok(ticks) => Ok(ticks == self.start_ticks),
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }
}

fn process_start_ticks(pid: u32) -> Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    // comm may contain spaces and parentheses. Fields following its final ')'
    // begin at field3; starttime is field22, hence index19 in this suffix.
    stat.rsplit_once(')')
        .context("Process stat has no command delimiter")?
        .1
        .split_whitespace()
        .nth(19)
        .context("Process stat has no start time")?
        .parse()
        .context("Invalid process start time")
}

pub fn boot_time_nanos() -> Result<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: time is a valid writable timespec; CLOCK_BOOTTIME is monotonic
    // across these processes and includes suspend, unlike wall-clock time.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    u64::try_from(time.tv_sec)?
        .checked_mul(1_000_000_000)
        .and_then(|secs| secs.checked_add(u64::try_from(time.tv_nsec).ok()?))
        .context("Boot clock exceeds representable snapshot age")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveRuntimeSnapshot {
    pub schema_version: u32,
    pub identity: ProcessIdentity,
    pub config_path: PathBuf,
    pub sequence: u64,
    pub captured_at: DateTime<Utc>,
    pub captured_boot_nanos: u64,
    pub ready: bool,
    pub test_mode: bool,
    pub applied: AppliedRoutingSnapshot,
    pub runtime: RuntimeStateSnapshot,
    pub proxy_health: HashMap<String, ProxyStats>,
    pub selections: crate::load_balancer::SelectionStats,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeObservation {
    pub status: String,
    pub age_ms: Option<u64>,
    pub snapshot: Option<LiveRuntimeSnapshot>,
}

impl RuntimeObservation {
    pub fn ready(&self) -> bool {
        self.status == "ready"
    }
}

pub fn runtime_snapshot_path() -> Result<PathBuf> {
    Ok(state_dir()?.join("runtime.json"))
}

pub fn publish_runtime_snapshot(path: &Path, snapshot: &LiveRuntimeSnapshot) -> Result<()> {
    let _lock = crate::util::PersistenceLock::acquire(path)?;
    if let Ok(bytes) = fs::read(path) {
        if let Ok(previous) = serde_json::from_slice::<LiveRuntimeSnapshot>(&bytes) {
            // A cancelled old worker must not overwrite a newer process or a
            // stopped snapshot. Process start ticks and sequence are ordered
            // within one boot; wall-clock corrections cannot invert them.
            if previous.identity.boot_id == snapshot.identity.boot_id
                && (previous.identity.start_ticks > snapshot.identity.start_ticks
                    || previous.identity == snapshot.identity
                        && previous.sequence >= snapshot.sequence)
            {
                return Ok(());
            }
        }
    }
    crate::util::atomic_write(path, serde_json::to_string_pretty(snapshot)?.as_bytes())
}

pub fn observe_runtime(config_path: &Path) -> RuntimeObservation {
    match runtime_snapshot_path() {
        Ok(path) => observe_runtime_at(config_path, &path),
        Err(_) => RuntimeObservation {
            status: "unavailable".into(),
            age_ms: None,
            snapshot: None,
        },
    }
}

fn observe_runtime_at(config_path: &Path, runtime_path: &Path) -> RuntimeObservation {
    let observation = || -> Result<RuntimeObservation> {
        let bytes = match fs::read(runtime_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(RuntimeObservation {
                    status: "absent".into(),
                    age_ms: None,
                    snapshot: None,
                });
            }
            Err(error) => return Err(error.into()),
        };
        let snapshot: LiveRuntimeSnapshot = serde_json::from_slice(&bytes)?;
        let expected = crate::util::publication_path(config_path)?;
        if snapshot.schema_version != 1 || snapshot.config_path != expected {
            return Ok(RuntimeObservation {
                status: "foreign".into(),
                age_ms: None,
                snapshot: None,
            });
        }
        if !snapshot.identity.matches_live_process()? {
            return Ok(RuntimeObservation {
                status: "dead".into(),
                age_ms: None,
                snapshot: Some(snapshot),
            });
        }
        let age = boot_time_nanos()?.checked_sub(snapshot.captured_boot_nanos);
        let status = if age.is_none_or(|age| age > 5_000_000_000) {
            "stale"
        } else if !snapshot.ready {
            "stopped"
        } else if process_owns_listener(
            snapshot.identity.pid,
            snapshot.applied.config.settings.listen_port,
        )? {
            "ready"
        } else {
            "listener_missing"
        };
        Ok(RuntimeObservation {
            status: status.into(),
            age_ms: age.map(|age| age / 1_000_000),
            snapshot: Some(snapshot),
        })
    };
    observation().unwrap_or(RuntimeObservation {
        status: "unavailable".into(),
        age_ms: None,
        snapshot: None,
    })
}

fn process_owns_listener(pid: u32, port: u16) -> Result<bool> {
    let mut sockets = std::collections::HashSet::new();
    for entry in fs::read_dir(format!("/proc/{pid}/fd"))? {
        let entry = entry?;
        // A concurrently closing descriptor can disappear after enumeration.
        let link = match fs::read_link(entry.path()) {
            Ok(link) => link,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        {
            if let Some(inode) = link
                .to_str()
                .and_then(|link| link.strip_prefix("socket:["))
                .and_then(|link| link.strip_suffix(']'))
            {
                sockets.insert(inode.to_owned());
            }
        }
    }
    let local = format!("0100007F:{port:04X}");
    Ok(fs::read_to_string(format!("/proc/{pid}/net/tcp"))?
        .lines()
        .skip(1)
        .any(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            fields.len() > 9
                && fields[1].eq_ignore_ascii_case(&local)
                && fields[3] == "0A"
                && sockets.contains(fields[9])
        }))
}

fn add_ping_sample(stats: &mut ProxyStats, ms: f64, at: DateTime<Utc>) {
    let count = stats.ping_samples.saturating_add(1);
    stats.ping_avg_ms = Some(
        stats
            .ping_avg_ms
            .map_or(ms, |avg| avg + (ms - avg) / count as f64),
    );
    stats.ping_samples = count;
    stats.last_ping_at = Some(at);
}

#[derive(Clone)]
pub struct StateStore {
    inner: Arc<RwLock<State>>,
    // Routing observations belong to this daemon/configuration, rather than
    // to persisted historical counters that a flush can merge back in.
    live: Arc<RwLock<HashMap<String, ProxyStats>>>,
    persisted: Arc<tokio::sync::Mutex<State>>,
    flush_task: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<Result<()>>>>>,
    path: PathBuf,
}

impl StateStore {
    pub async fn load() -> Result<Self> {
        let path = state_path()?;
        let read_path = path.clone();
        let state = tokio::task::spawn_blocking(move || State::load(&read_path)).await??;
        Ok(Self {
            live: Arc::new(RwLock::new(HashMap::new())),
            persisted: Arc::new(tokio::sync::Mutex::new(state.clone())),
            flush_task: Arc::new(tokio::sync::Mutex::new(None)),
            inner: Arc::new(RwLock::new(state)),
            path,
        })
    }

    /// Create an in-memory StateStore for testing (no file persistence)
    #[cfg(test)]
    pub fn new_for_testing() -> Self {
        Self {
            live: Arc::new(RwLock::new(HashMap::new())),
            inner: Arc::new(RwLock::new(State::default())),
            persisted: Arc::new(tokio::sync::Mutex::new(State::default())),
            flush_task: Arc::new(tokio::sync::Mutex::new(None)),
            path: PathBuf::from("/tmp/test-state.json"),
        }
    }

    pub async fn record_activated(&self, proxy_id: &str, at: DateTime<Utc>) {
        let mut state = self.inner.write().await;
        let stats = state.proxies.entry(proxy_id.to_string()).or_default();
        stats.activated_at = Some(at);
        stats.last_active = Some(at);
    }

    pub async fn record_traffic(&self, proxy_id: &str, sent: u64, received: u64) {
        let now = Utc::now();
        let mut state = self.inner.write().await;
        let stats = state.proxies.entry(proxy_id.to_string()).or_default();
        stats.bytes_sent = stats.bytes_sent.saturating_add(sent);
        stats.bytes_received = stats.bytes_received.saturating_add(received);
        stats.last_active = Some(now);
    }

    pub async fn record_ping(&self, proxy_id: &str, ms: f64) {
        let now = Utc::now();
        let mut live = self.live.write().await;
        add_ping_sample(live.entry(proxy_id.to_string()).or_default(), ms, now);
        let mut state = self.inner.write().await;
        let stats = state.proxies.entry(proxy_id.to_string()).or_default();
        add_ping_sample(stats, ms, now);
    }

    /// Record the result of a health check for a proxy
    #[allow(dead_code)]
    pub async fn record_health_check(
        &self,
        proxy_id: &str,
        success: bool,
        latency_ms: Option<f64>,
        failure_reason: Option<String>,
        threshold: u32,
    ) {
        let now = Utc::now();
        let mut live = self.live.write().await;
        let stats = live.entry(proxy_id.to_string()).or_default();

        stats.last_health_check = Some(now);

        if success {
            stats.consecutive_failures = 0;
            stats.last_healthy = Some(now);
            stats.last_failure_reason = None;
            stats.health_status = HealthStatus::Healthy;

            // Also record ping if latency was measured
            if let Some(ms) = latency_ms {
                add_ping_sample(stats, ms, now);
            }
        } else {
            stats.consecutive_failures = stats.consecutive_failures.saturating_add(1);
            stats.last_failure_reason = failure_reason;

            if stats.consecutive_failures >= threshold {
                stats.health_status = HealthStatus::Unhealthy;
            }
        }
        let mut state = self.inner.write().await;
        let history = state.proxies.entry(proxy_id.to_string()).or_default();
        history.last_health_check = stats.last_health_check;
        history.health_status = stats.health_status;
        history.consecutive_failures = stats.consecutive_failures;
        history
            .last_failure_reason
            .clone_from(&stats.last_failure_reason);
        history.last_healthy = history.last_healthy.max(stats.last_healthy);
        if success {
            if let Some(ms) = latency_ms {
                add_ping_sample(history, ms, now);
            }
        }
    }

    /// Get the current health status of a proxy
    #[allow(dead_code)]
    pub async fn get_health_status(&self, proxy_id: &str) -> HealthStatus {
        let state = self.live.read().await;
        state
            .get(proxy_id)
            .map(|s| s.health_status)
            .unwrap_or(HealthStatus::Unknown)
    }

    /// Get a list of proxy IDs that are currently healthy
    #[allow(dead_code)]
    pub async fn get_healthy_proxies(&self) -> Vec<String> {
        let state = self.live.read().await;
        state
            .iter()
            .filter(|(_, stats)| stats.health_status == HealthStatus::Healthy)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Get all proxy stats for display
    #[allow(dead_code)]
    pub async fn get_all_stats(&self) -> HashMap<String, ProxyStats> {
        let state = self.inner.read().await;
        state.proxies.clone()
    }

    /// Get the average latency for a proxy (used by LeastLatency load balancing)
    #[allow(dead_code)]
    pub async fn get_latency(&self, proxy_id: &str) -> Option<f64> {
        let state = self.live.read().await;
        state.get(proxy_id).and_then(|s| s.ping_avg_ms)
    }

    /// Get the proxy ID that was most recently healthy (used by UseLast degradation policy)
    pub async fn get_last_healthy_proxy(&self) -> Option<String> {
        let state = self.live.read().await;
        state
            .iter()
            .filter_map(|(id, stats)| stats.last_healthy.map(|ts| (id.clone(), ts)))
            .max_by_key(|(_, ts)| *ts)
            .map(|(id, _)| id)
    }

    /// Forget endpoint-specific eligibility while preserving all historical
    /// byte, activation and ping records. Persisted merges cannot resurrect it.
    pub async fn invalidate_observations(&self, proxy_ids: &[String]) {
        let mut live = self.live.write().await;
        for id in proxy_ids {
            live.remove(id);
        }
    }

    /// A connection keeps the observations from its admitted generation.
    /// Traffic still updates the shared durable counters through inner.
    pub async fn routing_snapshot(&self) -> Self {
        let mut snapshot = self.clone();
        snapshot.live = Arc::new(RwLock::new(self.live.read().await.clone()));
        snapshot
    }

    pub async fn flush(&self) -> Result<()> {
        let mut task = self.flush_task.lock().await;
        if let Some(pending) = task.as_mut() {
            // A cancelled caller leaves the owned worker intact. Adopt its
            // completion and bookkeeping before taking another dirty snapshot.
            let result = pending.await;
            *task = None;
            result.context("Pending persistence worker failed")??;
        }
        let store = self.clone();
        *task = Some(tokio::spawn(async move { store.flush_snapshot().await }));
        let result = task.as_mut().context("Persistence worker missing")?.await;
        *task = None;
        result.context("Persistence worker failed")?
    }

    async fn flush_snapshot(&self) -> Result<()> {
        // Serialize this store's commits; traffic/health can keep updating inner
        // while filesystem work runs on the blocking pool.
        let mut persisted = self.persisted.lock().await;
        let before = persisted.clone();
        let snapshot = self.inner.read().await.clone();
        let published_snapshot = snapshot.clone();
        let path = self.path.clone();
        let published = tokio::task::spawn_blocking(move || {
            State::update(&path, |latest| {
                merge_state_delta(latest, &snapshot, &before)
            })
        })
        .await??;
        let mut current = self.inner.write().await;
        let mut combined = published.clone();
        // Keep every update recorded while the snapshot was being committed.
        merge_state_delta(&mut combined, &current, &published_snapshot);
        *current = combined;
        *persisted = published;
        Ok(())
    }

    pub fn start_flush_loop(self: Arc<Self>, interval: Duration) -> tokio::task::JoinHandle<()> {
        let store = self.clone();
        tokio::spawn(async move {
            let mut next = Instant::now() + interval;
            loop {
                tokio::time::sleep_until(next).await;
                if let Err(err) = store.flush().await {
                    tracing::warn!("State flush failed: {err}");
                }
                next += interval;
            }
        })
    }
}

/// Runtime state that can change during daemon operation.
/// Separate from Config (user intent) and StateStore (persistent stats).
/// This manages dynamic proxy switching for failover/failback.
#[derive(Debug, Clone)]
struct RuntimeStateInner {
    applied: Option<AppliedRoutingSnapshot>,
    ready: bool,
    observation_sequence: u64,
    /// Currently effective proxy (may differ from config during failover)
    effective_proxy: Option<String>,
    /// Original active proxy from config (for failback)
    original_proxy: Option<String>,
    /// When current failover state began (None if no active failover)
    failover_at: Option<DateTime<Utc>>,
    /// When last failover/failback occurred (for min interval check)
    last_switch_at: Option<DateTime<Utc>>,
    /// Recovery detection timestamp (for failback delay)
    recovery_detected_at: Option<DateTime<Utc>>,
    /// When all proxies first became unhealthy
    all_unhealthy_since: Option<DateTime<Utc>>,
    /// Whether degradation policy is currently active
    degradation_active: bool,
    /// True once the daemon has applied live ipset/iptables rules. Test-mode
    /// daemons leave this false so policy paths skip firewall-coupled guards.
    firewall_active: bool,
    /// Firewall mark exempting the daemon's own direct-connect sockets from
    /// the REDIRECT rule (see iptables::SelfExemption::Mark). None means no
    /// self-exemption is installable and Direct fallback must be refused.
    direct_bypass_mark: Option<u32>,
}

/// Thread-safe runtime state for dynamic proxy management
#[derive(Clone)]
pub struct RuntimeState {
    inner: Arc<RwLock<RuntimeStateInner>>,
    configuration_gate: Arc<RwLock<()>>,
}

impl RuntimeState {
    /// Create from the active proxy ID on daemon startup
    pub fn new(active_proxy: Option<String>) -> Self {
        Self {
            configuration_gate: Arc::new(RwLock::new(())),
            inner: Arc::new(RwLock::new(RuntimeStateInner {
                applied: None,
                ready: false,
                observation_sequence: 0,
                effective_proxy: active_proxy.clone(),
                original_proxy: active_proxy,
                failover_at: None,
                last_switch_at: None,
                recovery_detected_at: None,
                all_unhealthy_since: None,
                degradation_active: false,
                firewall_active: false,
                direct_bypass_mark: None,
            })),
        }
    }

    pub fn configuration_gate(&self) -> Arc<RwLock<()>> {
        self.configuration_gate.clone()
    }

    pub async fn record_applied_config(
        &self,
        config: &crate::config::AppConfig,
        pending_restart_fields: Vec<String>,
        sources: Vec<RoutingSourceSnapshot>,
        ipset_entry_count: usize,
        reload: bool,
    ) {
        let mut projected = config.clone();
        for proxy in &mut projected.proxies {
            *proxy = proxy.redacted();
            proxy.auth = crate::config::ProxyAuth::default();
            proxy.health_check_url = proxy.health_check_url.as_deref().map(display_health_origin);
        }
        if let crate::config::HealthCheckTarget::Get { url } =
            &mut projected.settings.health_check_target
        {
            *url = display_health_origin(url);
        }
        let mut inner = self.inner.write().await;
        let previous = inner.applied.as_ref();
        let first = previous.is_none();
        inner.applied = Some(AppliedRoutingSnapshot {
            config: projected,
            config_generation: previous
                .map_or(0, |previous| previous.config_generation)
                .saturating_add(u64::from(first || reload)),
            routing_generation: previous
                .map_or(0, |previous| previous.routing_generation)
                .saturating_add(1),
            pending_restart_fields,
            last_reload_result: if reload {
                "applied".into()
            } else {
                previous.map_or_else(
                    || "never".into(),
                    |previous| previous.last_reload_result.clone(),
                )
            },
            last_reload_at: if reload {
                Some(Utc::now())
            } else {
                previous.and_then(|previous| previous.last_reload_at)
            },
            ipset_entry_count,
            sources,
        });
    }

    pub async fn record_reload_rejected(&self) {
        if let Some(applied) = &mut self.inner.write().await.applied {
            applied.last_reload_result = "rejected".into();
            applied.last_reload_at = Some(Utc::now());
        }
    }

    pub async fn set_ready(&self, ready: bool) {
        self.inner.write().await.ready = ready;
    }

    pub async fn pending_restart_fields(&self) -> Vec<String> {
        self.inner
            .read()
            .await
            .applied
            .as_ref()
            .map(|applied| applied.pending_restart_fields.clone())
            .unwrap_or_default()
    }

    pub async fn capture_live_snapshot(
        &self,
        identity: ProcessIdentity,
        config_path: PathBuf,
        state: &StateStore,
        selections: crate::load_balancer::SelectionStats,
        test_mode: bool,
    ) -> Result<LiveRuntimeSnapshot> {
        let mut health = state.live.read().await.clone();
        let mut inner = self.inner.write().await;
        let applied = inner
            .applied
            .clone()
            .context("Runtime configuration not initialized")?;
        health.retain(|id, _| applied.config.proxies.iter().any(|proxy| proxy.id == *id));
        // The public surface publishes typed health observations, never opaque
        // transport error text that could carry credentials or a health path.
        for stats in health.values_mut() {
            stats.last_failure_reason = None;
        }
        inner.observation_sequence = inner.observation_sequence.saturating_add(1);
        Ok(LiveRuntimeSnapshot {
            schema_version: 1,
            identity,
            config_path,
            sequence: inner.observation_sequence,
            captured_at: Utc::now(),
            captured_boot_nanos: boot_time_nanos()?,
            ready: inner.ready,
            test_mode,
            applied,
            runtime: runtime_status_snapshot(&inner),
            proxy_health: health,
            selections,
        })
    }

    pub async fn routing_snapshot(&self) -> Self {
        Self {
            inner: Arc::new(RwLock::new(self.inner.read().await.clone())),
            configuration_gate: self.configuration_gate.clone(),
        }
    }

    /// Owner holds configuration_gate exclusively through kernel publication,
    /// observation invalidation, this rebase and the config-bus commit.
    pub async fn rebase(&self, active_proxy: Option<String>) {
        let mut inner = self.inner.write().await;
        inner.effective_proxy = active_proxy.clone();
        inner.original_proxy = active_proxy;
        inner.failover_at = None;
        inner.last_switch_at = Some(Utc::now());
        inner.recovery_detected_at = None;
        inner.all_unhealthy_since = None;
        inner.degradation_active = false;
    }

    /// Record the daemon's firewall posture, fixed for the process lifetime:
    /// whether live REDIRECT rules exist and which mark (if any) exempts our
    /// own direct-connect sockets. Called once by run_daemon before tasks spawn.
    pub async fn set_firewall_context(&self, active: bool, bypass_mark: Option<u32>) {
        let mut inner = self.inner.write().await;
        inner.firewall_active = active;
        inner.direct_bypass_mark = bypass_mark;
    }

    /// Firewall context snapshot: (rules live, self-exemption mark).
    pub async fn firewall_context(&self) -> (bool, Option<u32>) {
        let inner = self.inner.read().await;
        (inner.firewall_active, inner.direct_bypass_mark)
    }

    /// Get currently effective proxy ID (may be failover target)
    pub async fn get_effective_proxy(&self) -> Option<String> {
        let inner = self.inner.read().await;
        inner.effective_proxy.clone()
    }

    /// Get the original proxy ID from config (for failback reference)
    pub async fn get_original_proxy(&self) -> Option<String> {
        let inner = self.inner.read().await;
        inner.original_proxy.clone()
    }

    /// Check if we're currently in a failover state
    pub async fn is_failed_over(&self) -> bool {
        let inner = self.inner.read().await;
        inner.failover_at.is_some()
    }

    /// Get failover timestamp if in failover state
    #[allow(dead_code)] // Will be used by status command
    pub async fn get_failover_at(&self) -> Option<DateTime<Utc>> {
        let inner = self.inner.read().await;
        inner.failover_at
    }

    /// Perform failover to a new proxy
    pub async fn failover_to(&self, new_proxy: &str) {
        let now = Utc::now();
        let mut inner = self.inner.write().await;
        inner.effective_proxy = Some(new_proxy.to_string());
        inner.failover_at = Some(now);
        inner.last_switch_at = Some(now);
        inner.recovery_detected_at = None;

        tracing::info!(
            from = ?inner.original_proxy,
            to = new_proxy,
            "Failover performed"
        );
    }

    /// Perform failback to original proxy
    pub async fn failback(&self) {
        let now = Utc::now();
        let mut inner = self.inner.write().await;
        let original = inner.original_proxy.clone();
        inner.effective_proxy = original.clone();
        inner.failover_at = None;
        inner.last_switch_at = Some(now);
        inner.recovery_detected_at = None;

        tracing::info!(
            to = ?original,
            "Failback performed"
        );
    }

    /// Record that original proxy has recovered (start failback timer)
    pub async fn record_recovery_detected(&self) {
        let mut inner = self.inner.write().await;
        if inner.recovery_detected_at.is_none() {
            inner.recovery_detected_at = Some(Utc::now());
            tracing::debug!(
                proxy = ?inner.original_proxy,
                "Original proxy recovery detected, starting failback timer"
            );
        }
    }

    /// Clear recovery detection (original failed again)
    pub async fn clear_recovery_detected(&self) {
        let mut inner = self.inner.write().await;
        if inner.recovery_detected_at.is_some() {
            inner.recovery_detected_at = None;
            tracing::debug!(
                proxy = ?inner.original_proxy,
                "Original proxy recovery cleared (failed again)"
            );
        }
    }

    /// Update degradation state based on healthy proxy list and delay.
    ///
    /// Returns true if degradation_active changed during this call.
    pub async fn update_degradation_state(
        &self,
        healthy_proxies: &[String],
        delay_secs: u64,
    ) -> bool {
        let mut inner = self.inner.write().await;
        let now = Utc::now();
        let previous = inner.degradation_active;

        if healthy_proxies.is_empty() {
            if inner.all_unhealthy_since.is_none() {
                inner.all_unhealthy_since = Some(now);
                tracing::warn!("All proxies unhealthy, starting degradation delay");
            }

            if let Some(since) = inner.all_unhealthy_since {
                let elapsed = now.signed_duration_since(since).num_seconds().max(0) as u64;
                inner.degradation_active = elapsed >= delay_secs;
                if inner.degradation_active && !previous {
                    tracing::warn!(elapsed_secs = elapsed, "Degradation mode activated");
                }
            }
        } else {
            if inner.degradation_active {
                tracing::info!("Degradation mode deactivated, healthy proxy available");
            }
            inner.all_unhealthy_since = None;
            inner.degradation_active = false;
        }

        previous != inner.degradation_active
    }

    /// Check if degradation policy is currently active.
    #[allow(dead_code)] // Will be used by status/diagnostics
    pub async fn is_degraded(&self) -> bool {
        let inner = self.inner.read().await;
        inner.degradation_active
    }

    /// Get degradation status for display.
    #[allow(dead_code)] // Will be used by status/diagnostics
    pub async fn get_degradation_status(&self) -> Option<DegradationStatus> {
        let inner = self.inner.read().await;
        inner.all_unhealthy_since.map(|since| DegradationStatus {
            unhealthy_since: since,
            active: inner.degradation_active,
        })
    }

    /// Check if enough time has passed for failback
    pub async fn failback_delay_passed(&self, delay_secs: u64) -> bool {
        let inner = self.inner.read().await;
        inner
            .recovery_detected_at
            .map(|t| Utc::now().signed_duration_since(t).num_seconds().max(0) as u64 >= delay_secs)
            .unwrap_or(false)
    }

    /// Check if enough time has passed since last switch (flapping prevention)
    #[allow(dead_code)] // Will be used for flapping prevention
    pub async fn can_switch(&self, min_interval_secs: u64) -> bool {
        let inner = self.inner.read().await;
        inner
            .last_switch_at
            .map(|t| {
                Utc::now().signed_duration_since(t).num_seconds().max(0) as u64 >= min_interval_secs
            })
            .unwrap_or(true)
    }

    /// Get a snapshot of runtime state for status display
    #[allow(dead_code)] // Will be used by status command
    pub async fn get_status_snapshot(&self) -> RuntimeStateSnapshot {
        let inner = self.inner.read().await;
        runtime_status_snapshot(&inner)
    }
}

fn runtime_status_snapshot(inner: &RuntimeStateInner) -> RuntimeStateSnapshot {
    RuntimeStateSnapshot {
        effective_proxy: inner.effective_proxy.clone(),
        original_proxy: inner.original_proxy.clone(),
        is_failed_over: inner.failover_at.is_some(),
        failover_at: inner.failover_at,
        last_switch_at: inner.last_switch_at,
        degradation_active: inner.degradation_active,
        all_unhealthy_since: inner.all_unhealthy_since,
    }
}

/// Snapshot of runtime state for display purposes
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)] // Will be used by status command
pub struct RuntimeStateSnapshot {
    pub effective_proxy: Option<String>,
    pub original_proxy: Option<String>,
    pub is_failed_over: bool,
    pub failover_at: Option<DateTime<Utc>>,
    pub last_switch_at: Option<DateTime<Utc>>,
    pub degradation_active: bool,
    pub all_unhealthy_since: Option<DateTime<Utc>>,
}

/// Degradation status for display/diagnostics.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Will be used by status/diagnostics
pub struct DegradationStatus {
    pub unhealthy_since: DateTime<Utc>,
    pub active: bool,
}

// =============================================================================
// Pidfile — single-daemon guarantee and crash detection
// =============================================================================

/// Default pidfile path. Lives on tmpfs; written by the daemon at startup,
/// removed on graceful exit, left behind by crashes (which is the point:
/// a leftover file with a dead pid proves the previous run died).
pub const DEFAULT_PID_PATH: &str = "/run/rust_proxy.pid";

/// The lock inode stays in place across restarts. Removing a locked file would
/// let a second process lock a different inode and become a second owner.
pub const DEFAULT_LOCK_PATH: &str = "/run/rust_proxy.lock";

pub struct DaemonOwnership {
    _lock: fs::File,
}

impl DaemonOwnership {
    pub fn acquire(path: &std::path::Path) -> Result<Self> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;

        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .with_context(|| format!("Failed opening daemon ownership lock {}", path.display()))?;
        // SAFETY: the descriptor belongs to a live File. flock does not borrow
        // memory, and closing this File releases ownership even after a crash.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "Cannot acquire daemon ownership at {}; another daemon may be running",
                    path.display()
                )
            });
        }
        Ok(Self { _lock: lock })
    }
}

/// What to do about an existing pidfile before starting a daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PidfileDecision {
    /// No usable existing record: start.
    Start,
    /// File holds `pid` of a LIVE process: another daemon owns the rules.
    Refuse(u32),
    /// File held `pid` of a DEAD process: a crashed predecessor left it
    /// behind (along with likely-stale firewall rules). Safe to take over
    /// after clearing that state.
    TakeOver(u32),
}

/// Decide the action for an existing pidfile. Pure so tests can inject any
/// liveness probe.
pub fn decide_pidfile_action<F>(existing_pid: Option<u32>, is_alive: F) -> PidfileDecision
where
    F: FnOnce(u32) -> bool,
{
    match existing_pid {
        None => PidfileDecision::Start,
        Some(pid) if is_alive(pid) => PidfileDecision::Refuse(pid),
        Some(pid) => PidfileDecision::TakeOver(pid),
    }
}

/// Read a pid from `path`; None if missing or unparseable (both treated as
/// "no usable record").
pub fn read_pidfile(path: &std::path::Path) -> Option<u32> {
    let content = std::fs::read_to_string(path).ok()?;
    content
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|pid| *pid > 0 && *pid <= i32::MAX as u32)
}

/// Atomically write our pid: temp file + rename in the same directory, so a
/// concurrent reader never sees a torn write.
pub fn write_pidfile(path: &std::path::Path, pid: u32) -> anyhow::Result<()> {
    use std::io::Write;
    anyhow::ensure!(
        pid > 0 && pid <= i32::MAX as u32,
        "Pidfile requires a positive process ID"
    );
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "rust_proxy.pid".to_string()),
        std::process::id()
    ));
    let mut f = std::fs::File::create(&tmp)?;
    writeln!(f, "{pid}")?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Remove the pidfile if present; missing is success.
pub fn remove_pidfile(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
}

/// True when `pid` refers to a live process. `kill(pid, 0)` returns EPERM
/// for a live process we lack permission to signal — that still counts as
/// alive.
pub fn process_alive(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    if pid <= 0 {
        return false;
    }
    // SAFETY: kill(2) with signal 0 performs permission/liveness checks only;
    // no signal is delivered and no state is mutated.
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn live_fixture(config_path: &Path, port: u16) -> Result<LiveRuntimeSnapshot> {
        let runtime = RuntimeState::new(Some("live-observer".into()));
        let config = crate::config::AppConfig {
            active_proxy: Some("live-observer".into()),
            settings: crate::config::Settings {
                listen_port: port,
                ..crate::config::Settings::default()
            },
            ..crate::config::AppConfig::default()
        };
        runtime
            .record_applied_config(&config, Vec::new(), Vec::new(), 0, false)
            .await;
        runtime.set_ready(true).await;
        runtime
            .capture_live_snapshot(
                ProcessIdentity::current()?,
                crate::util::publication_path(config_path)?,
                &StateStore::new_for_testing(),
                crate::load_balancer::LoadBalancer::new().get_stats(),
                true,
            )
            .await
    }

    #[tokio::test]
    async fn live_observer_checks_real_listener_birth_config_and_freshness() -> Result<()> {
        let work = tempfile::tempdir()?.keep();
        let config = work.join("config.toml");
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let snapshot = live_fixture(&config, listener.local_addr()?.port()).await?;
        let path = work.join("live.json");
        assert_eq!(observe_runtime_at(&config, &path).status, "absent");
        publish_runtime_snapshot(&path, &snapshot)?;
        assert_eq!(observe_runtime_at(&config, &path).status, "ready");
        assert!(observe_runtime_at(&config, &path).ready());
        assert_eq!(
            observe_runtime_at(&work.join("different.toml"), &path).status,
            "foreign"
        );
        let mut reused = snapshot.clone();
        reused.identity.start_ticks += 1;
        let reused_path = work.join("reused.json");
        publish_runtime_snapshot(&reused_path, &reused)?;
        assert_eq!(observe_runtime_at(&config, &reused_path).status, "dead");
        let mut stale = snapshot.clone();
        stale.captured_boot_nanos = boot_time_nanos()?
            .checked_sub(6_000_000_000)
            .unwrap_or(u64::MAX);
        let stale_path = work.join("stale.json");
        publish_runtime_snapshot(&stale_path, &stale)?;
        assert_eq!(observe_runtime_at(&config, &stale_path).status, "stale");
        drop(listener);
        assert_eq!(
            observe_runtime_at(&config, &path).status,
            "listener_missing"
        );
        assert!(!observe_runtime_at(&config, &path).ready());
        let malformed = work.join("malformed.json");
        fs::write(&malformed, b"{invalid")?;
        assert_eq!(
            observe_runtime_at(&config, &malformed).status,
            "unavailable"
        );
        Ok(())
    }

    #[tokio::test]
    async fn stale_publisher_cannot_resurrect_a_stopped_snapshot() -> Result<()> {
        let work = tempfile::tempdir()?.keep();
        let config = work.join("config.toml");
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let snapshot = live_fixture(&config, listener.local_addr()?.port()).await?;
        let path = work.join("runtime.json");
        let mut stopped = snapshot.clone();
        stopped.ready = false;
        stopped.sequence += 1;
        publish_runtime_snapshot(&path, &stopped)?;
        publish_runtime_snapshot(&path, &snapshot)?;
        let observed = observe_runtime_at(&config, &path);
        assert_eq!(observed.status, "stopped");
        assert_eq!(observed.snapshot.unwrap().sequence, stopped.sequence);
        Ok(())
    }

    #[tokio::test]
    async fn runtime_projection_strips_auth_and_health_paths_and_preserves_generations(
    ) -> Result<()> {
        let runtime = RuntimeState::new(Some("public-observer".into()));
        let config = crate::config::AppConfig {
            proxies: vec![crate::config::ProxyConfig {
                id: "public-observer".into(),
                url: "http://public-user:public-password@127.0.0.1:12345".into(),
                auth: crate::config::ProxyAuth { username: Some("public-config-user".into()), password: Some("public-config-password".into()), username_env: Some("PUBLIC_OBSERVER_USER".into()), password_env: Some("PUBLIC_OBSERVER_PASSWORD".into()) },
                health_check_url: Some("https://public-user:public-password@health.invalid/private-health-path?private-key=123".into()),
                priority: None,
                weight: 100,
            }],
            settings: crate::config::Settings {
                health_check_target: crate::config::HealthCheckTarget::Get {
                    url: "https://global-user:global-password@global.invalid/global-private-path?global-private-key=123".into(),
                },
                ..crate::config::Settings::default()
            },
            ..crate::config::AppConfig::default()
        };
        runtime
            .record_applied_config(&config, vec!["listen_port".into()], Vec::new(), 1, false)
            .await;
        runtime.record_reload_rejected().await;
        let state = StateStore::new_for_testing();
        state
            .record_health_check(
                "public-observer",
                false,
                None,
                Some("opaque-private-error".into()),
                1,
            )
            .await;
        let snapshot = runtime
            .capture_live_snapshot(
                ProcessIdentity::current()?,
                PathBuf::from("/tmp/public-observer-config"),
                &state,
                crate::load_balancer::LoadBalancer::new().get_stats(),
                true,
            )
            .await?;
        let text = serde_json::to_string(&snapshot)?;
        for private in [
            "public-user",
            "public-password",
            "public-config-user",
            "public-config-password",
            "PUBLIC_OBSERVER_USER",
            "PUBLIC_OBSERVER_PASSWORD",
            "private-health-path",
            "private-key",
            "global-user",
            "global-password",
            "global-private-path",
            "global-private-key",
            "opaque-private-error",
        ] {
            assert!(
                !text.contains(private),
                "published credential/path token {private}"
            );
        }
        assert_eq!(
            snapshot.applied.config.proxies[0]
                .health_check_url
                .as_deref(),
            Some("https://health.invalid")
        );
        assert_eq!(snapshot.applied.config_generation, 1);
        assert_eq!(snapshot.applied.routing_generation, 1);
        assert_eq!(snapshot.applied.last_reload_result, "rejected");
        runtime
            .record_applied_config(&config, Vec::new(), Vec::new(), 2, true)
            .await;
        let next = runtime
            .capture_live_snapshot(
                ProcessIdentity::current()?,
                PathBuf::from("/tmp/public-observer-config"),
                &StateStore::new_for_testing(),
                crate::load_balancer::LoadBalancer::new().get_stats(),
                true,
            )
            .await?;
        assert_eq!(next.applied.config_generation, 2);
        assert_eq!(next.applied.routing_generation, 2);
        assert_eq!(next.applied.last_reload_result, "applied");
        assert!(next.applied.pending_restart_fields.is_empty());
        Ok(())
    }

    fn store_at(path: PathBuf) -> Result<StateStore> {
        let initial = State::load(&path)?;
        Ok(StateStore {
            live: Arc::new(RwLock::new(HashMap::new())),
            inner: Arc::new(RwLock::new(initial.clone())),
            persisted: Arc::new(tokio::sync::Mutex::new(initial)),
            flush_task: Arc::new(tokio::sync::Mutex::new(None)),
            path,
        })
    }

    #[tokio::test]
    async fn invalidated_observations_stay_invalid_after_flush_and_old_snapshot_is_frozen(
    ) -> Result<()> {
        let work = tempfile::tempdir()?.keep();
        let store = store_at(work.join("state.json"))?;
        store.record_activated("endpoint", Utc::now()).await;
        store.record_traffic("endpoint", 10, 20).await;
        store
            .record_health_check("endpoint", true, Some(100.0), None, 2)
            .await;
        store.record_ping("endpoint", 200.0).await;
        let snapshot = store.routing_snapshot().await;
        assert_eq!(store.get_latency("endpoint").await, Some(150.0));
        store.invalidate_observations(&["endpoint".into()]).await;
        store.flush().await?;
        assert_eq!(
            store.get_health_status("endpoint").await,
            HealthStatus::Unknown
        );
        assert_eq!(store.get_latency("endpoint").await, None);
        assert!(store.get_last_healthy_proxy().await.is_none());
        assert_eq!(
            snapshot.get_health_status("endpoint").await,
            HealthStatus::Healthy
        );
        assert_eq!(snapshot.get_latency("endpoint").await, Some(150.0));
        let history = store.get_all_stats().await;
        assert_eq!(
            (
                history["endpoint"].bytes_sent,
                history["endpoint"].bytes_received
            ),
            (10, 20)
        );
        assert!(history["endpoint"].activated_at.is_some());
        assert_eq!(history["endpoint"].ping_samples, 2);
        store.record_ping("endpoint", 5.0).await;
        assert_eq!(store.get_latency("endpoint").await, Some(5.0));
        store
            .record_health_check(
                "endpoint",
                false,
                None,
                Some("new endpoint failure".into()),
                2,
            )
            .await;
        assert_eq!(
            store.get_health_status("endpoint").await,
            HealthStatus::Unknown
        );
        store
            .record_health_check(
                "endpoint",
                false,
                None,
                Some("second new failure".into()),
                2,
            )
            .await;
        assert_eq!(
            store.get_health_status("endpoint").await,
            HealthStatus::Unhealthy
        );
        store.flush().await?;
        assert_eq!(
            store.get_health_status("endpoint").await,
            HealthStatus::Unhealthy
        );
        Ok(())
    }

    #[tokio::test]
    async fn increasing_degradation_delay_defers_existing_activation_without_overflow() {
        let runtime = RuntimeState::new(None);
        assert!(runtime.update_degradation_state(&[], 0).await);
        assert!(runtime.is_degraded().await);
        assert!(runtime.update_degradation_state(&[], u64::MAX).await);
        assert!(!runtime.is_degraded().await);
        assert!(runtime.update_degradation_state(&[], 0).await);
        assert!(
            runtime
                .update_degradation_state(&["available".into()], 0)
                .await
        );
        assert!(!runtime.is_degraded().await);
    }

    #[tokio::test]
    async fn runtime_rebase_resets_failback_and_degradation_but_preserves_socket_safety() {
        let runtime = RuntimeState::new(Some("first".into()));
        runtime.set_firewall_context(true, Some(0x1234)).await;
        runtime.failover_to("second").await;
        runtime.record_recovery_detected().await;
        runtime.update_degradation_state(&[], 0).await;
        let snapshot = runtime.routing_snapshot().await;
        runtime.rebase(Some("third".into())).await;
        assert_eq!(
            runtime.get_effective_proxy().await.as_deref(),
            Some("third")
        );
        assert_eq!(runtime.get_original_proxy().await.as_deref(), Some("third"));
        assert!(!runtime.is_failed_over().await);
        assert!(!runtime.is_degraded().await);
        assert_eq!(runtime.firewall_context().await, (true, Some(0x1234)));
        assert_eq!(
            snapshot.get_effective_proxy().await.as_deref(),
            Some("second")
        );
        assert_eq!(
            snapshot.get_original_proxy().await.as_deref(),
            Some("first")
        );
        assert!(snapshot.is_failed_over().await);
        assert!(snapshot.is_degraded().await);
    }

    #[tokio::test]
    async fn stale_daemon_snapshot_preserves_cli_activation_and_adds_only_dirty_counters(
    ) -> Result<()> {
        let work = tempfile::tempdir()?;
        let path = work.path().join("state.json");
        State::update(&path, |state| {
            state.proxies.insert(
                "shared".into(),
                ProxyStats {
                    bytes_sent: 100,
                    bytes_received: 200,
                    ping_avg_ms: Some(20.0),
                    ping_samples: 1,
                    ..ProxyStats::default()
                },
            );
        })?;
        let store = store_at(path.clone())?;
        store.record_traffic("shared", 5, 7).await;
        store.record_ping("shared", 40.0).await;
        store
            .record_health_check("shared", false, None, Some("outage".into()), 1)
            .await;
        let activation = Utc::now() + chrono::Duration::seconds(60);
        State::update(&path, |state| {
            let stats = state.proxies.get_mut("shared").unwrap();
            stats.activated_at = Some(activation);
            stats.last_active = Some(activation);
            state
                .proxies
                .insert("independent-cli".into(), ProxyStats::default());
        })?;
        store.flush().await?;
        store.flush().await?; // Repeated flush cannot reapply acknowledged deltas.
        let disk = State::load(&path)?;
        let stats = &disk.proxies["shared"];
        assert_eq!((stats.bytes_sent, stats.bytes_received), (105, 207));
        assert_eq!(stats.activated_at, Some(activation));
        assert_eq!(stats.last_active, Some(activation));
        assert_eq!(stats.ping_samples, 2);
        assert_eq!(stats.ping_avg_ms, Some(30.0));
        assert_eq!(stats.health_status, HealthStatus::Unhealthy);
        assert_eq!(stats.last_failure_reason.as_deref(), Some("outage"));
        assert!(disk.proxies.contains_key("independent-cli"));
        assert_eq!(store.get_all_stats().await["shared"], *stats);
        Ok(())
    }

    #[tokio::test]
    async fn independent_stale_stores_merge_counter_and_ping_sample_deltas_once() -> Result<()> {
        let work = tempfile::tempdir()?;
        let path = work.path().join("state.json");
        State::update(&path, |state| {
            state.proxies.insert(
                "shared".into(),
                ProxyStats {
                    bytes_sent: 1,
                    bytes_received: 2,
                    ping_avg_ms: Some(10.0),
                    ping_samples: 1,
                    ..ProxyStats::default()
                },
            );
        })?;
        let first = store_at(path.clone())?;
        let second = store_at(path.clone())?;
        first.record_traffic("shared", 3, 4).await;
        second.record_traffic("shared", 5, 6).await;
        first.record_ping("shared", 30.0).await;
        second.record_ping("shared", 50.0).await;
        let (a, b) = tokio::join!(first.flush(), second.flush());
        a?;
        b?;
        first.flush().await?;
        second.flush().await?;
        let disk = State::load(&path)?;
        let stats = &disk.proxies["shared"];
        assert_eq!((stats.bytes_sent, stats.bytes_received), (9, 12));
        assert_eq!(stats.ping_samples, 3);
        assert!((stats.ping_avg_ms.unwrap() - 30.0).abs() < 1e-9);
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_flush_caller_cannot_double_apply_commit_or_drop_inflight_traffic(
    ) -> Result<()> {
        let work = tempfile::tempdir()?;
        let path = work.path().join("state.json");
        let store = store_at(path.clone())?;
        store.record_traffic("shared", 10, 20).await;
        let gate = crate::util::PersistenceLock::acquire(&path)?;
        let calling_store = store.clone();
        let caller = tokio::spawn(async move { calling_store.flush().await });
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if store.persisted.try_lock().is_err() {
                break;
            }
            anyhow::ensure!(
                Instant::now() < deadline,
                "flush never captured its owned snapshot"
            );
            tokio::task::yield_now().await;
        }
        // This current-thread runtime observes the worker after it yielded on
        // filesystem I/O; its dirty snapshot exists and publication is gated.
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        store.record_traffic("shared", 7, 11).await;
        drop(gate);
        store.flush().await?;
        let disk = State::load(&path)?;
        assert_eq!(
            (
                disk.proxies["shared"].bytes_sent,
                disk.proxies["shared"].bytes_received
            ),
            (17, 31)
        );
        assert_eq!(
            store.get_all_stats().await["shared"],
            disk.proxies["shared"]
        );
        Ok(())
    }

    #[tokio::test]
    async fn failed_publication_keeps_old_bytes_and_pending_deltas_for_retry() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        // The workspace's existing CLI seam requires a non-root test actor.
        anyhow::ensure!(
            unsafe { libc::geteuid() } != 0,
            "publication-permission control requires non-root"
        );
        let work = tempfile::tempdir()?;
        let path = work.path().join("state.json");
        State::default().save(&path)?;
        let original = fs::read(&path)?;
        let store = store_at(path.clone())?;
        store.record_traffic("shared", 11, 13).await;
        fs::set_permissions(work.path(), fs::Permissions::from_mode(0o500))?;
        let failed = store.flush().await;
        fs::set_permissions(work.path(), fs::Permissions::from_mode(0o700))?;
        assert!(failed.is_err());
        assert_eq!(fs::read(&path)?, original);
        store.record_traffic("shared", 5, 7).await;
        store.flush().await?;
        let disk = State::load(&path)?;
        assert_eq!(
            (
                disk.proxies["shared"].bytes_sent,
                disk.proxies["shared"].bytes_received
            ),
            (16, 20)
        );
        Ok(())
    }

    #[test]
    fn unreadable_state_is_an_error_and_cannot_be_misclassified_as_corrupt() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        anyhow::ensure!(
            unsafe { libc::geteuid() } != 0,
            "state read-permission control requires non-root"
        );
        let work = tempfile::tempdir()?;
        let path = work.path().join("state.json");
        State::default().save(&path)?;
        let original = fs::read(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000))?;
        let failed = State::load(&path);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        assert!(failed.is_err());
        assert_eq!(fs::read(&path)?, original);
        assert_eq!(
            fs::read_dir(work.path())?.count(),
            1,
            "read failure created a false quarantine"
        );
        Ok(())
    }

    #[test]
    fn corrupt_reader_rechecks_after_a_complete_concurrent_publication() -> Result<()> {
        use std::io::Read;
        use std::os::fd::FromRawFd;
        use std::os::unix::ffi::OsStrExt;
        let work = tempfile::tempdir()?;
        let path = work.path().join("state.json");
        fs::write(&path, b"corrupt-before-writer")?;
        let gate = crate::util::PersistenceLock::acquire(&path)?;
        // SAFETY: initializes an owned inotify descriptor with close-on-exec.
        let descriptor = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
        anyhow::ensure!(
            descriptor >= 0,
            "cannot observe corrupt reader's actual file open"
        );
        // SAFETY: descriptor ownership is transferred exactly once to this File.
        let mut observer = unsafe { fs::File::from_raw_fd(descriptor) };
        let name = std::ffi::CString::new(path.as_os_str().as_bytes())?;
        // SAFETY: live descriptor and NUL-terminated pathname, valid event mask.
        anyhow::ensure!(
            unsafe { libc::inotify_add_watch(descriptor, name.as_ptr(), libc::IN_OPEN) } >= 0,
            "cannot watch state file"
        );
        let reader_path = path.clone();
        let reader = std::thread::spawn(move || State::load(&reader_path));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        let mut event = [0; 64];
        loop {
            match observer.read(&mut event) {
                Ok(n) if n >= 16 => break,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                outcome => anyhow::bail!("unexpected state-open observation: {outcome:?}"),
            }
            anyhow::ensure!(
                std::time::Instant::now() < deadline,
                "reader did not open old corrupt bytes"
            );
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let mut good = State::default();
        good.proxies.insert(
            "published".into(),
            ProxyStats {
                bytes_sent: 77,
                ..ProxyStats::default()
            },
        );
        // The controller already holds the real transaction lock.
        good.save_locked(&path)?;
        drop(gate);
        let loaded = reader
            .join()
            .map_err(|_| anyhow::anyhow!("state reader panicked"))??;
        assert_eq!(loaded.proxies["published"].bytes_sent, 77);
        assert_eq!(State::load(&path)?.proxies["published"].bytes_sent, 77);
        assert_eq!(
            fs::read_dir(work.path())?.count(),
            1,
            "reader quarantined a good publication"
        );
        Ok(())
    }

    #[test]
    fn repeated_corruption_preserves_every_original_quarantine_and_file_alias() -> Result<()> {
        use std::os::unix::fs::symlink;
        let work = tempfile::tempdir()?;
        let path = work.path().join("state.json");
        let alias = work.path().join("alias.json");
        symlink(&path, &alias)?;
        for bytes in [b"first-corrupt".as_slice(), b"second-corrupt".as_slice()] {
            fs::write(&path, bytes)?;
            assert!(State::load(&alias)?.proxies.is_empty());
            assert!(fs::symlink_metadata(&alias)?.file_type().is_symlink());
            assert!(!path.exists());
        }
        let mut saved: Vec<_> = fs::read_dir(work.path())?
            .filter_map(|entry| {
                let path = entry.ok()?.path();
                path.file_name()?
                    .to_string_lossy()
                    .starts_with("state.json.corrupt-")
                    .then(|| fs::read(path).unwrap())
            })
            .collect();
        saved.sort();
        assert_eq!(
            saved,
            vec![b"first-corrupt".to_vec(), b"second-corrupt".to_vec()]
        );
        Ok(())
    }

    // RuntimeState degradation tracking tests

    #[tokio::test]
    async fn test_runtime_state_initial_not_degraded() {
        let state = RuntimeState::new(Some("proxy-a".to_string()));
        assert!(!state.is_degraded().await);
    }

    #[tokio::test]
    async fn test_runtime_state_degradation_delay_debounces() {
        let state = RuntimeState::new(Some("proxy-a".to_string()));
        let delay_secs = 2;

        // All proxies become unhealthy - should not immediately degrade
        let healthy: Vec<String> = vec![];
        let changed = state.update_degradation_state(&healthy, delay_secs).await;
        assert!(!changed); // Not yet degraded
        assert!(!state.is_degraded().await);
    }

    #[tokio::test]
    async fn test_runtime_state_degradation_activates_after_delay() {
        let state = RuntimeState::new(Some("proxy-a".to_string()));
        let delay_secs = 0; // Zero delay means immediate activation

        // With zero delay, degradation should activate immediately
        let healthy: Vec<String> = vec![];
        let _changed = state.update_degradation_state(&healthy, delay_secs).await;
        assert!(state.is_degraded().await);
    }

    #[tokio::test]
    async fn test_runtime_state_recovery_resets_degradation() {
        let state = RuntimeState::new(Some("proxy-a".to_string()));

        // First, trigger degradation with zero delay
        let empty: Vec<String> = vec![];
        state.update_degradation_state(&empty, 0).await;
        assert!(state.is_degraded().await);

        // Now a proxy becomes healthy - should reset
        let healthy = vec!["proxy-a".to_string()];
        state.update_degradation_state(&healthy, 0).await;
        assert!(!state.is_degraded().await);
    }

    #[tokio::test]
    async fn test_runtime_state_degradation_status_tracking() {
        let state = RuntimeState::new(Some("proxy-a".to_string()));

        // Initially no degradation status
        assert!(state.get_degradation_status().await.is_none());

        // After all unhealthy, should have status
        let empty: Vec<String> = vec![];
        state.update_degradation_state(&empty, 5).await;
        let status = state.get_degradation_status().await;
        assert!(status.is_some());
        let status = status.unwrap();
        assert!(!status.active); // Not yet active (delay not elapsed)
    }

    #[tokio::test]
    async fn test_runtime_state_failover_tracking() {
        let state = RuntimeState::new(Some("proxy-a".to_string()));

        // Initially not failed over
        assert!(!state.is_failed_over().await);
        assert_eq!(
            state.get_effective_proxy().await,
            Some("proxy-a".to_string())
        );

        // Perform failover
        state.failover_to("proxy-b").await;
        assert!(state.is_failed_over().await);
        assert_eq!(
            state.get_effective_proxy().await,
            Some("proxy-b".to_string())
        );
        assert_eq!(
            state.get_original_proxy().await,
            Some("proxy-a".to_string())
        );

        // Perform failback
        state.failback().await;
        assert!(!state.is_failed_over().await);
        assert_eq!(
            state.get_effective_proxy().await,
            Some("proxy-a".to_string())
        );
    }

    #[tokio::test]
    async fn test_runtime_state_failback_delay() {
        let state = RuntimeState::new(Some("proxy-a".to_string()));

        // Initially failback delay has not passed (no recovery detected)
        assert!(!state.failback_delay_passed(5).await);

        // Record recovery
        state.record_recovery_detected().await;

        // With 0 delay, should pass immediately
        assert!(state.failback_delay_passed(0).await);
        // Large configured delays must not wrap into negative signed seconds
        // and authorize an immediate failback/switch.
        assert!(!state.failback_delay_passed(u64::MAX).await);
        state.rebase(Some("proxy-a".into())).await;
        assert!(state.can_switch(0).await);
        assert!(!state.can_switch(u64::MAX).await);
    }

    #[tokio::test]
    async fn test_runtime_state_recovery_detection_cleared() {
        let state = RuntimeState::new(Some("proxy-a".to_string()));

        // Record recovery
        state.record_recovery_detected().await;
        assert!(state.failback_delay_passed(0).await);

        // Clear recovery (proxy failed again)
        state.clear_recovery_detected().await;
        assert!(!state.failback_delay_passed(0).await);
    }

    #[tokio::test]
    async fn test_runtime_state_snapshot() {
        let state = RuntimeState::new(Some("proxy-a".to_string()));

        // Get initial snapshot
        let snapshot = state.get_status_snapshot().await;
        assert_eq!(snapshot.effective_proxy, Some("proxy-a".to_string()));
        assert_eq!(snapshot.original_proxy, Some("proxy-a".to_string()));
        assert!(!snapshot.is_failed_over);
        assert!(!snapshot.degradation_active);
        assert!(snapshot.all_unhealthy_since.is_none());
    }

    // StateStore tests

    #[tokio::test]
    async fn test_state_store_last_healthy_proxy() {
        let store = StateStore::new_for_testing();

        // Initially no last healthy proxy
        assert!(store.get_last_healthy_proxy().await.is_none());

        // Record a health check success
        store
            .record_health_check("proxy-a", true, Some(50.0), None, 3)
            .await;

        // Now should have last healthy proxy
        assert_eq!(
            store.get_last_healthy_proxy().await,
            Some("proxy-a".to_string())
        );
    }

    #[tokio::test]
    async fn test_state_store_health_status_tracking() {
        let store = StateStore::new_for_testing();

        // Initially unknown status
        assert_eq!(
            store.get_health_status("proxy-a").await,
            HealthStatus::Unknown
        );

        // Record success - should become healthy
        store
            .record_health_check("proxy-a", true, Some(50.0), None, 3)
            .await;
        assert_eq!(
            store.get_health_status("proxy-a").await,
            HealthStatus::Healthy
        );

        // Record failures - after threshold should become unhealthy
        for _ in 0..3 {
            store
                .record_health_check("proxy-a", false, None, Some("timeout".to_string()), 3)
                .await;
        }
        assert_eq!(
            store.get_health_status("proxy-a").await,
            HealthStatus::Unhealthy
        );
    }

    #[tokio::test]
    async fn test_state_store_healthy_proxies_list() {
        let store = StateStore::new_for_testing();

        // No healthy proxies initially
        assert!(store.get_healthy_proxies().await.is_empty());

        // Add some healthy proxies
        store
            .record_health_check("proxy-a", true, Some(50.0), None, 3)
            .await;
        store
            .record_health_check("proxy-b", true, Some(60.0), None, 3)
            .await;

        let healthy = store.get_healthy_proxies().await;
        assert_eq!(healthy.len(), 2);
        assert!(healthy.contains(&"proxy-a".to_string()));
        assert!(healthy.contains(&"proxy-b".to_string()));
    }

    #[test]
    fn test_health_status_display() {
        assert_eq!(format!("{}", HealthStatus::Unknown), "unknown");
        assert_eq!(format!("{}", HealthStatus::Healthy), "healthy");
        assert_eq!(format!("{}", HealthStatus::Degraded), "degraded");
        assert_eq!(format!("{}", HealthStatus::Unhealthy), "unhealthy");
    }

    #[test]
    fn test_state_save_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");

        let mut state = State::default();
        state
            .proxies
            .insert("proxy-a".to_string(), ProxyStats::default());
        state.save(&path).unwrap();

        let loaded = State::load(&path).unwrap();
        // Compare via canonical serialization (State does not derive PartialEq).
        assert_eq!(
            serde_json::to_string_pretty(&loaded).unwrap(),
            serde_json::to_string_pretty(&state).unwrap()
        );
    }

    #[test]
    fn test_state_load_recovers_from_corrupt_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        std::fs::write(&path, "{ this is not valid json").unwrap();

        let loaded = State::load(&path).unwrap();
        assert_eq!(loaded.proxies.len(), 0);

        let mut sidecars: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("state.json.corrupt-"))
            .collect();
        sidecars.sort();
        assert_eq!(sidecars.len(), 1, "exactly one corrupt sidecar expected");
        let kept = std::fs::read_to_string(dir.path().join(&sidecars[0])).unwrap();
        assert_eq!(kept, "{ this is not valid json", "original bytes preserved");
        assert!(
            !path.exists(),
            "corrupt file moved aside, not left in place"
        );
    }

    #[test]
    fn test_state_double_save_leaves_valid_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");

        for i in 0..2 {
            let mut state = State::default();
            state
                .proxies
                .insert(format!("proxy-{}", i), ProxyStats::default());
            state.save(&path).unwrap();
        }

        let entries: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, vec!["state.json"], "no temp files may linger");
        let loaded = State::load(&path).unwrap();
        assert!(loaded.proxies.contains_key("proxy-1"));
    }

    #[test]
    fn test_decide_pidfile_action_all_cases() {
        // No file: start.
        assert_eq!(
            decide_pidfile_action(None, |_| true),
            PidfileDecision::Start
        );
        // Live owner: refuse.
        assert_eq!(
            decide_pidfile_action(Some(4242), |pid| pid == 4242),
            PidfileDecision::Refuse(4242)
        );
        // Dead owner (crash): take over.
        assert_eq!(
            decide_pidfile_action(Some(4242), |_| false),
            PidfileDecision::TakeOver(4242)
        );
    }

    #[test]
    fn test_pidfile_write_read_remove_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rust_proxy.pid");

        assert_eq!(read_pidfile(&path), None, "missing file reads as None");

        write_pidfile(&path, 12345).unwrap();
        assert_eq!(read_pidfile(&path), Some(12345));

        // Overwrite (take-over path) replaces cleanly.
        write_pidfile(&path, 999).unwrap();
        assert_eq!(read_pidfile(&path), Some(999));

        remove_pidfile(&path);
        assert_eq!(read_pidfile(&path), None);
    }

    #[test]
    fn test_read_pidfile_tolerates_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("garbage.pid");
        std::fs::write(&path, "not-a-pid\n").unwrap();
        assert_eq!(read_pidfile(&path), None);
        for invalid in ["0", "4294967295", "2147483648", "-1"] {
            std::fs::write(&path, invalid).unwrap();
            assert_eq!(
                read_pidfile(&path),
                None,
                "a process-group selector is never a PID"
            );
        }
        assert!(!process_alive(0));
        assert!(!process_alive(u32::MAX));
    }

    #[test]
    fn test_process_alive_self_is_true() {
        assert!(process_alive(std::process::id()));
    }

    #[test]
    fn daemon_ownership_is_exclusive_and_recovers_after_close() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.lock");
        let first = DaemonOwnership::acquire(&path).unwrap();
        assert!(DaemonOwnership::acquire(&path).is_err());
        drop(first);
        let second = DaemonOwnership::acquire(&path).unwrap();
        assert!(DaemonOwnership::acquire(&path).is_err());
        drop(second);
        assert!(path.exists(), "the ownership inode must never be unlinked");
    }
}
