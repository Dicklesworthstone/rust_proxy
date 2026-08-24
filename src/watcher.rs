// Allow dead_code warnings - watcher hooks are staged for future integration.
#![allow(dead_code)]

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
    /// A relevant event has been observed since the last fired notification.
    ///
    /// This is retained across `poll()` calls so that events arriving inside
    /// the debounce window are not lost: they stay pending until the window
    /// elapses and the pending change finally fires.
    pending_relevant: bool,
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

        let mut watcher = RecommendedWatcher::new(
            move |res| {
                let _ = tx.send(res);
            },
            config,
        )
        .context("Failed to create file watcher")?;

        // Watch the config file's parent directory if the file doesn't exist yet,
        // otherwise watch the file directly. This handles the case where the file
        // might be deleted and recreated (common with atomic saves).
        let watch_path = if config_path.exists() {
            config_path
        } else {
            config_path.parent().unwrap_or(Path::new("."))
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
            pending_relevant: false,
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
        // Drain all pending events, accumulating relevance across polls. The
        // flag must live on `self`: draining before the debounce check means a
        // per-call local would silently drop events observed mid-window.
        loop {
            match self.rx.try_recv() {
                Ok(Ok(event)) => {
                    if self.is_relevant_event(&event) {
                        debug!(
                            path = ?event.paths,
                            kind = ?event.kind,
                            "Relevant config file event"
                        );
                        self.pending_relevant = true;
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

        let now = Instant::now();
        let (fire, last_change) =
            debounce_decision(self.pending_relevant, self.last_change, self.debounce, now);
        self.last_change = last_change;
        if !fire {
            // Keep `pending_relevant` set: the observed change is deferred to
            // a future poll once the debounce window elapses.
            return false;
        }

        self.pending_relevant = false;
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

/// Pure debounce decision used by [`ConfigWatcher::poll`].
///
/// Returns whether a reload should fire now and the updated last-change
/// timestamp. When relevant changes are pending but still inside the debounce
/// window, the decision is "do not fire" while the caller retains the pending
/// state for a later poll.
fn debounce_decision(
    pending_relevant: bool,
    last_change: Option<Instant>,
    debounce: Duration,
    now: Instant,
) -> (bool, Option<Instant>) {
    if !pending_relevant {
        return (false, last_change);
    }
    if let Some(last) = last_change {
        if now.duration_since(last) < debounce {
            return (false, last_change);
        }
    }
    (true, Some(now))
}

#[cfg(test)]
impl ConfigWatcher {
    /// Test-only constructor that injects a pre-made event receiver, letting
    /// unit tests drive `poll()` deterministically without real file events.
    fn with_receiver(
        config_path: &Path,
        debounce: Duration,
        rx: Receiver<Result<Event, notify::Error>>,
    ) -> Self {
        let watcher =
            RecommendedWatcher::new(|_| {}, Config::default()).expect("test watcher creation");
        Self {
            watcher,
            rx,
            config_path: config_path.to_path_buf(),
            debounce,
            last_change: None,
            pending_relevant: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use notify::event::{DataChange, ModifyKind};
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

    fn modify_event(path: &Path) -> Result<Event, notify::Error> {
        Ok(
            Event::new(EventKind::Modify(ModifyKind::Data(DataChange::Any)))
                .add_path(path.to_path_buf()),
        )
    }

    /// Regression: an event drained during the debounce window must survive
    /// until the window elapses instead of being dropped.
    ///
    /// Pre-fix mechanism: `poll()` kept relevance in a per-call local
    /// (`has_relevant_change`) and returned `false` on the debounced poll
    /// without retaining it, so the post-window poll found an empty channel
    /// and reported no change -- the save was lost.
    #[test]
    fn test_poll_retains_events_observed_inside_debounce_window() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.toml");
        fs::write(&config_path, "a = 1").unwrap();

        let (tx, rx) = mpsc::channel();
        let mut watcher = ConfigWatcher::with_receiver(&config_path, Duration::from_millis(30), rx);

        tx.send(modify_event(&config_path)).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert!(
            watcher.poll(),
            "first relevant event fires immediately (no prior change)"
        );

        // Second save lands inside the debounce window.
        tx.send(modify_event(&config_path)).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert!(!watcher.poll(), "in-window event is debounced");

        // Window elapsed and no new events arrive: the retained event must
        // still fire. Pre-fix this returned false (event lost).
        std::thread::sleep(Duration::from_millis(40));
        assert!(
            watcher.poll(),
            "event observed during the debounce window must fire after it elapses"
        );

        // And nothing further is pending.
        assert!(!watcher.poll(), "pending state cleared after firing");
    }

    #[test]
    fn test_debounce_decision_pure_helper() {
        let t0 = Instant::now();
        let win = Duration::from_millis(100);

        // Nothing pending never fires and preserves last_change.
        let (fire, lc) = debounce_decision(false, Some(t0), win, t0 + win);
        assert!(!fire);
        assert_eq!(lc, Some(t0));

        // Pending inside the window: no fire, pending stays (caller keeps it).
        let (fire, _) = debounce_decision(true, Some(t0), win, t0 + Duration::from_millis(50));
        assert!(!fire);

        // Pending outside the window (or never fired): fire and stamp now.
        let (fire, lc) = debounce_decision(true, Some(t0), win, t0 + win);
        assert!(fire);
        assert_eq!(lc, Some(t0 + win));
        let (fire, lc) = debounce_decision(true, None, win, t0);
        assert!(fire);
        assert_eq!(lc, Some(t0));
    }
}
