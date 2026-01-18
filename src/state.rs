use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};

use crate::config::state_dir;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProxyStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub last_active: Option<DateTime<Utc>>,
    pub activated_at: Option<DateTime<Utc>>,
    pub ping_avg_ms: Option<f64>,
    pub ping_samples: u64,
    pub last_ping_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct State {
    pub proxies: HashMap<String, ProxyStats>,
}

impl State {
    pub fn load(path: &PathBuf) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed reading state {}", path.display()))?;
        let state: State = serde_json::from_str(&content)
            .with_context(|| format!("Failed parsing state {}", path.display()))?;
        Ok(state)
    }

    pub fn save(&self, path: &PathBuf) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed creating state dir {}", parent.display()))?;
        }
        let content = serde_json::to_string_pretty(self)?;
        fs::write(path, content)
            .with_context(|| format!("Failed writing state {}", path.display()))?;
        Ok(())
    }
}

pub fn state_path() -> Result<PathBuf> {
    let dir = state_dir()?;
    Ok(dir.join("state.json"))
}

#[derive(Clone)]
pub struct StateStore {
    inner: Arc<RwLock<State>>,
    path: PathBuf,
}

impl StateStore {
    pub async fn load() -> Result<Self> {
        let path = state_path()?;
        let state = State::load(&path)?;
        Ok(Self {
            inner: Arc::new(RwLock::new(state)),
            path,
        })
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
        let mut state = self.inner.write().await;
        let stats = state.proxies.entry(proxy_id.to_string()).or_default();
        let next_count = stats.ping_samples.saturating_add(1);
        let next_avg = match stats.ping_avg_ms {
            None => ms,
            Some(avg) => avg + (ms - avg) / next_count as f64,
        };
        stats.ping_avg_ms = Some(next_avg);
        stats.ping_samples = next_count;
        stats.last_ping_at = Some(now);
    }

    pub async fn flush(&self) -> Result<()> {
        let state = self.inner.read().await;
        state.save(&self.path)
    }

    pub async fn start_flush_loop(self: Arc<Self>, interval: Duration) {
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
        });
    }
}
