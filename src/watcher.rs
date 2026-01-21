//! File system watcher for config hot-reload functionality.
//!
//! This module provides the foundational infrastructure for watching
//! configuration file changes and notifying the daemon to reload.

use anyhow::{Context, Result};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Default poll interval for file system events.
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Default debounce duration to coalesce rapid events.
const DEFAULT_DEBOUNCE: Duration = Duration::from_millis(500);

/// Watches a configuration file for changes and provides a polling interface.
///
/// The watcher internally debounces rapid file system events (e.g., multiple
/// write events from a single save operation) to avoid triggering multiple
/// reloads.
pub struct ConfigWatcher {
    /// The underlying notify watcher (kept alive to maintain watch).
    #[allow(dead_code)]
    watcher: RecommendedWatcher,
    /// Receiver for file system events.
    rx: Receiver<Result<Event, notify::Error>>,
    /// Path being watched.
    config_path: PathBuf,
    /// Duration to debounce rapid events.
    debounce: Duration,
    /// Timestamp of last change notification.
    last_change: Option<Instant>,
}

impl ConfigWatcher {
    /// Create a new ConfigWatcher for the specified config file.
    ///
    /// # Arguments
    /// * `config_path` - Path to the configuration file to watch.
    ///
    /// # Returns
    /// A new ConfigWatcher instance or an error if the watcher couldn't be created.
    pub fn new(config_path: &Path) -> Result<Self> {
        Self::with_options(config_path, DEFAULT_POLL_INTERVAL, DEFAULT_DEBOUNCE)
    }

    /// Create a new ConfigWatcher with custom options.
    ///
    /// # Arguments
    /// * `config_path` - Path to the configuration file to watch.
    /// * `poll_interval` - How often to poll for file system events.
    /// * `debounce` - Duration to coalesce rapid events.
    pub fn with_options(
        config_path: &Path,
        poll_interval: Duration,
        debounce: Duration,
    ) -> Result<Self> {
        let (tx, rx) = mpsc::channel();

        let config = Config::default().with_poll_interval(poll_interval);

        let mut watcher = RecommendedWatcher::new(move |res| {
            let _ = tx.send(res);
        }, config)
        .context("Failed to create file watcher")?;

        // Watch the config file's parent directory if the file doesn't exist yet,
        // otherwise watch the file directly. This handles the case where the file
        // might be deleted and recreated (common with atomic saves).
        let watch_path = if config_path.exists() {
            config_path
        } else {
            config_path
                .parent()
                .unwrap_or(Path::new("."))
        };

        watcher
            .watch(watch_path, RecursiveMode::NonRecursive)
            .with_context(|| format!("Failed to watch path: {}", watch_path.display()))?;

        info!(
            path = %config_path.display(),
            "Config watcher initialized"
        );

        Ok(Self {
            watcher,
            rx,
            config_path: config_path.to_path_buf(),
            debounce,
            last_change: None,
        })
    }

    /// Poll for configuration file changes.
    ///
    /// This method is non-blocking and returns `true` if the config file
    /// has been modified since the last call. It handles debouncing internally
    /// to avoid returning true multiple times for a single logical save operation.
    ///
    /// # Returns
    /// `true` if the configuration file changed and should be reloaded.
    pub fn poll(&mut self) -> bool {
        let mut has_relevant_change = false;

        // Drain all pending events
        loop {
            match self.rx.try_recv() {
                Ok(Ok(event)) => {
                    if self.is_relevant_event(&event) {
                        debug!(
                            path = ?event.paths,
                            kind = ?event.kind,
                            "Relevant config file event"
                        );
                        has_relevant_change = true;
                    }
                }
                Ok(Err(e)) => {
                    warn!(error = %e, "File watcher error");
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    warn!("File watcher channel disconnected");
                    break;
                }
            }
        }

        if !has_relevant_change {
            return false;
        }

        // Apply debouncing
        let now = Instant::now();
        if let Some(last) = self.last_change {
            if now.duration_since(last) < self.debounce {
                debug!("Debouncing config change event");
                return false;
            }
        }

        self.last_change = Some(now);
        info!(
            path = %self.config_path.display(),
            "Config file change detected"
        );
        true
    }

    /// Check if an event is relevant to our watched config file.
    fn is_relevant_event(&self, event: &Event) -> bool {
        // Only care about modifications, creates, and renames
        let is_relevant_kind = matches!(
            event.kind,
            EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
        );

        if !is_relevant_kind {
            return false;
        }

        // Check if any of the event paths match our config file
        event.paths.iter().any(|p| {
            // Exact match
            if p == &self.config_path {
                return true;
            }
            // Handle atomic saves that create temp files
            if let Some(file_name) = self.config_path.file_name() {
                if let Some(event_name) = p.file_name() {
                    return event_name == file_name;
                }
            }
            false
        })
    }

    /// Get the path being watched.
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Reset the debounce timer, allowing immediate detection of the next change.
    pub fn reset_debounce(&mut self) {
        self.last_change = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_watcher_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");
        fs::write(&config_path, "test = true").unwrap();

        let watcher = ConfigWatcher::new(&config_path);
        assert!(watcher.is_ok());
    }

    #[test]
    fn test_watcher_nonexistent_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("nonexistent.toml");

        // Should still succeed by watching the parent directory
        let watcher = ConfigWatcher::new(&config_path);
        assert!(watcher.is_ok());
    }
}
