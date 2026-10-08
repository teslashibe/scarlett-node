//! Driver-style updates. The Go node does every network read and byte check
//! (`scarlett-node desktop update-check|update-stage`), so the desktop and
//! headless updaters share one verifier. This shell decides when: it checks on
//! a schedule, shows the notices, waits for accepted jobs to finish, hands the
//! install to a detached guard (a copy of the node binary outside the bundle),
//! and on the next launch reports whether the new version is healthy so the
//! guard can keep it or roll back.
use crate::local_api::LocalApi;
use crate::node::{Error, Node, Result};
use crate::preferences::Preferences;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    sync::{Mutex, Notify},
};

/// The public changelog; entries are anchored #v<version>.
pub const CHANGELOG: &str = "https://network.scarlett.ai/changelog/";
const CHECK_EVERY: u64 = 6 * 3600;
const EVENT_DEBOUNCE: u64 = 600;
const DRAIN_LIMIT: u64 = 30 * 60;
const HEALTH_LIMIT: u64 = 4 * 60;
const SERVING_SETTLE: u64 = 60;
const COUNTDOWN: u64 = 60;
const STATE_LIMIT: usize = 16384;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Semantic version precedence; None when either side is not a version.
pub fn compare_versions(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    fn parse(v: &str) -> Option<([u64; 3], Vec<String>)> {
        if v.is_empty() || v.len() > 64 {
            return None;
        }
        let (core, pre) = match v.split_once('-') {
            Some((c, p)) => (c, Some(p)),
            None => (v, None),
        };
        let parts: Vec<&str> = core.split('.').collect();
        if parts.len() != 3 {
            return None;
        }
        let mut out = [0u64; 3];
        for (i, p) in parts.iter().enumerate() {
            if p.is_empty()
                || p.len() > 9
                || !p.bytes().all(|b| b.is_ascii_digit())
                || (p.len() > 1 && p.starts_with('0'))
            {
                return None;
            }
            out[i] = p.parse().ok()?;
        }
        let ids = match pre {
            None => Vec::new(),
            Some(p) => {
                let ids: Vec<String> = p.split('.').map(str::to_owned).collect();
                if ids.iter().any(|id| {
                    id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                }) {
                    return None;
                }
                ids
            }
        };
        Some((out, ids))
    }
    let (ac, ap) = parse(a)?;
    let (bc, bp) = parse(b)?;
    use std::cmp::Ordering::*;
    match ac.cmp(&bc) {
        Equal => {}
        other => return Some(other),
    }
    match (ap.is_empty(), bp.is_empty()) {
        (true, true) => return Some(Equal),
        (true, false) => return Some(Greater),
        (false, true) => return Some(Less),
        _ => {}
    }
    for (x, y) in ap.iter().zip(bp.iter()) {
        let order = match (x.parse::<u64>(), y.parse::<u64>()) {
            (Ok(x), Ok(y)) => x.cmp(&y),
            (Ok(_), Err(_)) => Less,
            (Err(_), Ok(_)) => Greater,
            _ => x.cmp(y),
        };
        if order != Equal {
            return Some(order);
        }
    }
    Some(ap.len().cmp(&bp.len()))
}

fn newer(a: &str, b: &str) -> bool {
    compare_versions(a, b) == Some(std::cmp::Ordering::Greater)
}

/// Release notes as the manifest and the compiled-in notes carry them. All
/// text is inserted into the page as text, never markup.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Notes {
    pub title: String,
    #[serde(default)]
    pub date: String,
    pub highlights: Vec<String>,
}
impl Notes {
    fn plain(text: &str, limit: usize) -> bool {
        !text.is_empty()
            && text.chars().count() <= limit
            && text.trim() == text
            && !text
                .chars()
                .any(|c| c.is_control() || c == '<' || c == '>' || c == '\u{fffd}')
    }
    pub fn valid(&self) -> bool {
        Self::plain(&self.title, 80)
            && (1..=3).contains(&self.highlights.len())
            && self.highlights.iter().all(|h| Self::plain(h, 160))
    }
}

/// Notes for the running version, compiled in by build.rs from
/// release-notes/<version>.json; the "Updated to" banner needs no network.
pub fn own_notes() -> Option<Notes> {
    let raw = include_str!(concat!(env!("OUT_DIR"), "/release-notes.json"));
    serde_json::from_str::<Notes>(raw)
        .ok()
        .filter(Notes::valid)
}

// The private update-state.json, owned by the Go helper (update.State).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Pending {
    pub phase: String,
    pub from: String,
    pub to: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub staged: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub app: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub previous: String,
    pub drain_owner: String,
    #[serde(default)]
    pub resume_serving: bool,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub app_pid: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub guard_pid: u32,
    #[serde(default)]
    pub started_at: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}
fn is_zero(v: &u32) -> bool {
    *v == 0
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Stamp {
    pub version: String,
    pub until: i64,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Seen {
    pub version: String,
    pub at: i64,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct State {
    pub schema: u8,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub installed: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub high_water: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub announced: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snooze: Option<Stamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<Seen>,
    #[serde(default, skip_serializing_if = "is_zero_u8")]
    pub postponed: u8,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<Pending>,
}
fn is_zero_u8(v: &u8) -> bool {
    *v == 0
}

/// What `desktop update-check` reports.
#[derive(Clone, Debug, Default, Deserialize)]
struct Check {
    #[serde(default)]
    latest: String,
    #[serde(default)]
    available: bool,
    #[serde(default)]
    signed: bool,
    #[serde(default)]
    can_verify: bool,
    #[serde(default)]
    failed: bool,
    #[serde(default)]
    notes: Option<Notes>,
    #[serde(default)]
    rollout_seconds: u64,
    #[serde(default)]
    error: Option<String>,
}

/// One line of `desktop update-stage` progress.
#[derive(Clone, Debug, Default, Deserialize)]
struct StageEvent {
    phase: String,
    #[serde(default)]
    received: u64,
    #[serde(default)]
    total: u64,
    #[serde(default)]
    error: Option<String>,
}

/// The "Updated to x.y.z" banner.
#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct Banner {
    pub version: String,
    pub notes: Option<Notes>,
    /// Offered once, after the first manual update to a version with the
    /// updater, so automatic installs are never on without a choice.
    pub offer_automatic: bool,
}
/// A rolled-back or failed install, shown by the version still running.
#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct Failure {
    pub version: String,
    pub reason: String,
    pub rolled_back: bool,
}

/// Everything the renderer shows. Codes are fixed strings.
#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct Status {
    pub version: String,
    pub mode: String,
    /// idle, checking, available, downloading, verifying, ready, scheduled,
    /// draining, installing or error.
    pub phase: String,
    pub latest: Option<String>,
    pub required: bool,
    pub notes: Option<Notes>,
    pub progress: Option<u8>,
    pub in_flight: Option<u64>,
    /// Unix milliseconds of a scheduled automatic install.
    pub install_at: Option<u64>,
    pub error: Option<String>,
    pub checked_at: Option<u64>,
    /// This build can verify and install the latest release by itself.
    pub can_install: bool,
    pub snoozed: bool,
    /// The coordinator has announced a release the manifest does not list yet.
    pub stale: bool,
    pub updated: Option<Banner>,
    pub failure: Option<Failure>,
}

#[derive(Default)]
struct Inner {
    status: Status,
    last_check: u64,
    last_seen_latest: String,
    rollout_seconds: u64,
    signed: bool,
    failed: bool,
    coordinator_since: Option<(String, u64)>,
    countdown_until: Option<u64>,
    drain_timeouts: u8,
}

pub struct Updater {
    version: String,
    state_dir: PathBuf,
    node: Arc<Node>,
    api: Arc<LocalApi>,
    preferences: Arc<Preferences>,
    inner: Mutex<Inner>,
    wake: Notify,
    acked: AtomicBool,
    acked_notify: Notify,
    busy: Mutex<()>,
    cancel: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    install_now: AtomicBool,
    postpone_until: AtomicU64,
}

/// The shell's half of a hand-off: stop serving, exit, let the guard run.
pub trait Shell: Send + Sync {
    /// The window is visible and focused, so an automatic install shows its
    /// one-minute notice first.
    fn window_attentive(&self) -> bool;
    /// Exit at once after a hand-off; the node and local API are stopped.
    fn exit_for_update(&self);
    /// Quit through the normal draining shutdown.
    fn quit(&self);
    fn changed(&self, status: &Status);
}

impl Updater {
    pub fn new(
        version: String,
        state_dir: PathBuf,
        node: Arc<Node>,
        api: Arc<LocalApi>,
        preferences: Arc<Preferences>,
    ) -> Self {
        let mode = preferences
            .snapshot()
            .map(|p| p.updates)
            .unwrap_or_else(|_| "notify".into());
        Self {
            inner: Mutex::new(Inner {
                status: Status {
                    version: version.clone(),
                    mode,
                    phase: "idle".into(),
                    ..Default::default()
                },
                ..Default::default()
            }),
            version,
            state_dir,
            node,
            api,
            preferences,
            wake: Notify::new(),
            acked: AtomicBool::new(false),
            acked_notify: Notify::new(),
            busy: Mutex::new(()),
            cancel: Mutex::new(None),
            install_now: AtomicBool::new(false),
            postpone_until: AtomicU64::new(0),
        }
    }

    pub async fn status(&self) -> Status {
        let mut status = self.inner.lock().await.status.clone();
        status.mode = self
            .preferences
            .snapshot()
            .map(|p| p.updates)
            .unwrap_or_else(|_| "notify".into());
        status
    }

    async fn update<F: FnOnce(&mut Status)>(&self, shell: &dyn Shell, change: F) {
        let status = {
            let mut inner = self.inner.lock().await;
            change(&mut inner.status);
            inner.status.clone()
        };
        shell.changed(&status);
    }

    // State file through the Go helper, which validates and locks it.
    pub async fn read_state(&self) -> Result<State> {
        let raw = self
            .node
            .helper_call(&["desktop", "update-state-get"], None, 10, STATE_LIMIT)
            .await
            .map_err(|_| Error::PrivateStorageUnavailable)?;
        serde_json::from_slice(&raw).map_err(|_| Error::PrivateStorageUnavailable)
    }
    pub async fn write_state(&self, state: &State) -> Result<()> {
        let raw = serde_json::to_vec(state).map_err(|_| Error::InvalidInput)?;
        self.node
            .helper_call(
                &["desktop", "update-state-set"],
                Some(raw),
                10,
                STATE_LIMIT,
            )
            .await
            .map_err(|_| Error::PrivateStorageUnavailable)?;
        Ok(())
    }
    async fn change_state<F: FnOnce(&mut State)>(&self, change: F) -> Result<State> {
        let mut state = self.read_state().await?;
        change(&mut state);
        self.write_state(&state).await?;
        Ok(state)
    }

    /// The renderer finished its first render: one half of post-update health.
    pub fn ack(&self) {
        self.acked.store(true, Ordering::SeqCst);
        self.acked_notify.notify_waiters();
    }

    pub fn wake(&self) {
        self.wake.notify_one();
    }

    /// Hide an available optional update for 24 hours, or postpone a
    /// scheduled automatic install (optional: 1 h, up to three times;
    /// required: 10 minutes, once).
    pub async fn later(&self, shell: &dyn Shell) -> Result<()> {
        let (latest, required, phase) = {
            let inner = self.inner.lock().await;
            (
                inner.status.latest.clone().unwrap_or_default(),
                inner.status.required,
                inner.status.phase.clone(),
            )
        };
        if latest.is_empty() {
            return Ok(());
        }
        if phase == "scheduled" || phase == "ready" && self.automatic() {
            let state = self.read_state().await?;
            let limit = if required { 1 } else { 3 };
            if state.postponed >= limit {
                return Err(Error::InvalidInput);
            }
            self.change_state(|s| s.postponed += 1).await?;
            let delay = if required { 600 } else { 3600 };
            self.postpone_until.store(now() + delay, Ordering::SeqCst);
            {
                let mut inner = self.inner.lock().await;
                inner.countdown_until = None;
            }
            self.update(shell, |s| {
                s.phase = "ready".into();
                s.install_at = Some((now() + delay) * 1000);
            })
            .await;
            return Ok(());
        }
        if required {
            return Err(Error::InvalidInput);
        }
        let until = (now() + 24 * 3600) as i64;
        self.change_state(|s| {
            s.snooze = Some(Stamp {
                version: latest.clone(),
                until,
            })
        })
        .await?;
        self.update(shell, |s| s.snoozed = true).await;
        Ok(())
    }

    /// Dismiss the "Updated to" banner or a failure notice for good.
    pub async fn dismiss(&self, shell: &dyn Shell, notice: &str) -> Result<()> {
        match notice {
            "updated" => {
                let version = self.version.clone();
                self.change_state(|s| s.announced = version).await?;
                self.update(shell, |s| s.updated = None).await;
            }
            "failure" => {
                self.change_state(|s| {
                    if s.pending.as_ref().is_some_and(|p| {
                        matches!(p.phase.as_str(), "rolled_back" | "failed")
                    }) {
                        s.pending = None;
                    }
                })
                .await?;
                self.update(shell, |s| s.failure = None).await;
            }
            _ => return Err(Error::InvalidInput),
        }
        Ok(())
    }

    fn automatic(&self) -> bool {
        self.preferences
            .snapshot()
            .is_ok_and(|p| p.updates == "automatic")
    }

    /// Cancel a download or a drain before the hand-off.
    pub async fn cancel(&self) {
        if let Some(cancel) = self.cancel.lock().await.take() {
            let _ = cancel.send(());
        }
    }

    // ---------------------------------------------------------------- launch

    /// Runs first at launch: finish a pending install, report health, show
    /// the banner or a failure notice, and start the node again if it was
    /// serving. Returns whether the node should start (resume serving).
    pub async fn on_launch(self: &Arc<Self>, shell: Arc<dyn Shell>) -> bool {
        let fresh = !self.state_dir.join("update-state.json").exists();
        let Ok(mut state) = self.read_state().await else {
            return false;
        };
        let version = self.version.clone();
        let mut resume = false;
        let mut verify = false;
        if let Some(p) = state.pending.clone() {
            match p.phase.as_str() {
                "installed" | "verifying" if p.to == version => {
                    if p.drain_owner == "updater" {
                        // The drain marker persists across restarts.
                        let _ = self.node.control("resume").await;
                    }
                    resume = p.resume_serving;
                    verify = true;
                    let pending = state.pending.as_mut().expect("pending");
                    pending.phase = "verifying".into();
                    pending.app_pid = std::process::id();
                    pending.drain_owner = "none".into();
                }
                "rolled_back" | "failed" if p.from == version => {
                    if p.drain_owner == "updater" {
                        let _ = self.node.control("resume").await;
                        if let Some(pending) = state.pending.as_mut() {
                            pending.drain_owner = "none".into();
                        }
                    }
                    resume = p.resume_serving;
                    let failure = Failure {
                        version: p.to.clone(),
                        reason: if p.reason.is_empty() {
                            "install_failed".into()
                        } else {
                            p.reason.clone()
                        },
                        rolled_back: p.phase == "rolled_back",
                    };
                    self.update(shell.as_ref(), |s| s.failure = Some(failure))
                        .await;
                }
                "healthy" if p.to == version => {
                    // The guard has kept this version; nothing is pending.
                    state.pending = None;
                }
                "draining" | "handoff" if p.from == version => {
                    // Interrupted before the guard ran: undo our pause.
                    if p.drain_owner == "updater" {
                        let _ = self.node.control("resume").await;
                    }
                    if let Some(pending) = state.pending.as_mut() {
                        pending.phase = "staged".into();
                        pending.drain_owner = "none".into();
                    }
                }
                _ if !newer(&p.to, &version) && p.phase == "staged" => state.pending = None,
                _ => {}
            }
        }
        // A manual install over existing state also gets the banner once.
        let identity = self.state_dir.join("identity.json").exists();
        let manual = state.pending.is_none()
            && state.announced != version
            && ((fresh && identity)
                || (!state.installed.is_empty() && state.installed != version));
        if state.installed.is_empty() || (manual && newer(&version, &state.installed)) {
            state.installed = version.clone();
        }
        if state.high_water.is_empty() || newer(&version, &state.high_water) {
            state.high_water = version.clone();
        }
        if self.write_state(&state).await.is_err() {
            return false;
        }
        if manual {
            let offer = !self.automatic();
            self.update(shell.as_ref(), |s| {
                s.updated = Some(Banner {
                    version: version.clone(),
                    notes: own_notes(),
                    offer_automatic: offer,
                })
            })
            .await;
        }
        if verify {
            let updater = self.clone();
            let shell = shell.clone();
            tauri::async_runtime::spawn(async move { updater.verify(shell, resume).await });
        }
        resume
    }

    /// Post-update health: the window rendered and, when the node was
    /// serving, it is still running this release a minute after start.
    async fn verify(self: Arc<Self>, shell: Arc<dyn Shell>, serving: bool) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(HEALTH_LIMIT);
        let acked = async {
            while !self.acked.load(Ordering::SeqCst) {
                let _ =
                    tokio::time::timeout(Duration::from_secs(1), self.acked_notify.notified())
                        .await;
            }
        };
        let mut reason = String::new();
        if tokio::time::timeout_at(deadline, acked).await.is_err() {
            reason = "window_not_ready".into();
        }
        if reason.is_empty() && serving {
            tokio::time::sleep(Duration::from_secs(SERVING_SETTLE)).await;
            reason = "node_not_running".into();
            while tokio::time::Instant::now() < deadline {
                let snapshot = self.node.snapshot().await;
                let observed = snapshot.observation.as_ref();
                let state = observed
                    .and_then(|o| o.get("state"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                let release = observed
                    .and_then(|o| o.get("release"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                if snapshot.supervised
                    && matches!(state, "running" | "draining")
                    && release == self.version
                {
                    reason.clear();
                    break;
                }
                if !snapshot.supervised {
                    reason = "node_exited".into();
                    break;
                }
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        }
        let version = self.version.clone();
        let healthy = reason.is_empty();
        let written = self
            .change_state(|s| {
                if let Some(p) = s.pending.as_mut().filter(|p| p.to == version) {
                    if healthy {
                        p.phase = "healthy".into();
                    } else {
                        p.phase = "unhealthy".into();
                        p.reason = reason.clone();
                    }
                }
                if healthy {
                    s.installed = version.clone();
                    s.high_water = version.clone();
                    s.postponed = 0;
                    s.first_seen = None;
                }
            })
            .await;
        if healthy && written.is_ok() {
            let offer = false;
            self.update(shell.as_ref(), |s| {
                s.updated = Some(Banner {
                    version: version.clone(),
                    notes: own_notes(),
                    offer_automatic: offer,
                })
            })
            .await;
        } else if !healthy {
            // Stop serving gracefully; the guard restores the previous
            // version once this app exits.
            eprintln!("update: {version} is unhealthy ({reason}); quitting so it can be rolled back");
            shell.quit();
        }
    }

    // ------------------------------------------------------------- the loop

    /// Checks at launch (after a minute), every six hours with jitter, when
    /// the coordinator announces a newer release, and on request.
    pub async fn run(self: Arc<Self>, shell: Arc<dyn Shell>) {
        let first = std::env::var("SCARLETT_DESKTOP_UPDATE_FIRST_CHECK_SECONDS")
            .ok()
            .filter(|_| cfg!(debug_assertions))
            .and_then(|v| v.parse().ok())
            .unwrap_or(60u64);
        let _ = tokio::time::timeout(Duration::from_secs(first), self.wake.notified()).await;
        // Six hours, give or take 15 %.
        let spread = CHECK_EVERY * 15 / 100;
        let mut next_check = 0u64;
        loop {
            if now() >= next_check {
                self.check(shell.as_ref()).await;
                next_check = now() + CHECK_EVERY - spread + jitter_seconds(2 * spread);
            }
            self.coordinator_event(shell.as_ref(), &mut next_check).await;
            if self.automatic() || self.install_now.load(Ordering::SeqCst) {
                self.automatic_step(shell.clone()).await;
            }
            // "Check for updates", "Update now" or a settings change.
            if tokio::time::timeout(Duration::from_secs(15), self.wake.notified())
                .await
                .is_ok()
            {
                next_check = 0;
            }
        }
    }

    /// The coordinator's release header, refreshed on every heartbeat, makes a
    /// running node notice a release within about a minute.
    async fn coordinator_event(&self, shell: &dyn Shell, next_check: &mut u64) {
        let snapshot = self.node.snapshot().await;
        let latest = snapshot
            .observation
            .as_ref()
            .and_then(|o| o.get("latest_release"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_owned();
        let required = snapshot
            .observation
            .as_ref()
            .and_then(|o| o.get("update_required"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let mut inner = self.inner.lock().await;
        if inner.status.required != required {
            inner.status.required = required;
            shell.changed(&inner.status);
        }
        if latest.is_empty() || !newer(&latest, &self.version) {
            inner.coordinator_since = None;
            return;
        }
        let seen = inner.last_seen_latest.clone();
        if (seen.is_empty() || newer(&latest, &seen))
            && now().saturating_sub(inner.last_check) > EVENT_DEBOUNCE
        {
            *next_check = 0;
        }
        // Freeze detection: the coordinator names a release the manifest has
        // not listed for an hour. Offer the download page only.
        match &inner.coordinator_since {
            Some((v, since)) if *v == latest => {
                let stale = !seen.is_empty() && newer(&latest, &seen) && now() - since > 3600;
                if inner.status.stale != stale {
                    inner.status.stale = stale;
                    if stale {
                        eprintln!("update: coordinator announces {latest}; the download manifest lists {seen}");
                    }
                    shell.changed(&inner.status);
                }
            }
            _ => inner.coordinator_since = Some((latest, now())),
        }
    }

    pub async fn check(&self, shell: &dyn Shell) {
        let Ok(_busy) = self.busy.try_lock() else {
            return;
        };
        self.update(shell, |s| {
            if matches!(s.phase.as_str(), "idle" | "available" | "error") {
                s.phase = "checking".into();
            }
        })
        .await;
        let result = self
            .node
            .helper_call(&["desktop", "update-check"], None, 60, 16384)
            .await
            .ok()
            .and_then(|raw| serde_json::from_slice::<Check>(&raw).ok());
        let state = self.read_state().await.unwrap_or_default();
        let mut inner = self.inner.lock().await;
        inner.last_check = now();
        let status = &mut inner.status;
        status.checked_at = Some(now() * 1000);
        let Some(check) = result.filter(|c| c.error.is_none()) else {
            if status.phase == "checking" {
                status.phase = if status.latest.is_some() {
                    "available".into()
                } else {
                    "idle".into()
                };
            }
            status.error = Some("network".into());
            shell.changed(status);
            return;
        };
        status.error = None;
        let available = check.available && newer(&check.latest, &self.version);
        status.latest = available.then(|| check.latest.clone());
        status.notes = check.notes.clone().filter(Notes::valid);
        status.can_install = check.signed && check.can_verify && available;
        status.snoozed = state
            .snooze
            .as_ref()
            .is_some_and(|s| s.version == check.latest && s.until > now() as i64);
        let staged = state.pending.as_ref().is_some_and(|p| {
            p.phase == "staged" && p.to == check.latest && p.from == self.version
        });
        if status.phase == "checking" || !available {
            status.phase = match (available, staged) {
                (false, _) => "idle",
                (true, true) => "ready",
                (true, false) => "available",
            }
            .into();
        }
        inner.last_seen_latest = check.latest.clone();
        inner.rollout_seconds = check.rollout_seconds;
        inner.signed = check.signed && check.can_verify;
        inner.failed = check.failed;
        if !available {
            inner.status.stale = false;
        }
        shell.changed(&inner.status);
    }

    // ------------------------------------------------------- installing

    /// "Update now": download and verify unthrottled, then install as soon as
    /// accepted jobs finish. The same path as automatic mode.
    pub fn install_now(&self) {
        self.install_now.store(true, Ordering::SeqCst);
        self.postpone_until.store(0, Ordering::SeqCst);
        self.wake.notify_one();
    }

    async fn automatic_step(self: &Arc<Self>, shell: Arc<dyn Shell>) {
        let manual = self.install_now.load(Ordering::SeqCst);
        let (available, signed, failed, required, rollout) = {
            let inner = self.inner.lock().await;
            (
                inner.status.latest.clone(),
                inner.signed,
                inner.failed,
                inner.status.required,
                inner.rollout_seconds,
            )
        };
        let Some(latest) = available else {
            self.install_now.store(false, Ordering::SeqCst);
            return;
        };
        if !signed || (failed && !manual) {
            self.install_now.store(false, Ordering::SeqCst);
            return;
        }
        let Ok(state) = self.read_state().await else {
            return;
        };
        let staged = state
            .pending
            .as_ref()
            .is_some_and(|p| p.phase == "staged" && p.to == latest && p.from == self.version);
        if !staged {
            let serving = self.node.snapshot().await.supervised;
            let mode = if manual {
                "manual"
            } else if serving {
                "auto-throttled"
            } else {
                "auto"
            };
            if let Err(code) = self.stage(shell.as_ref(), mode).await {
                self.install_now.store(false, Ordering::SeqCst);
                self.update(shell.as_ref(), |s| {
                    s.phase = "error".into();
                    s.error = Some(code);
                    s.progress = None;
                })
                .await;
                return;
            }
        }
        // When to install.
        let serving = self.node.snapshot().await.supervised;
        let first_seen = match state.first_seen.as_ref().filter(|s| s.version == latest) {
            Some(seen) => seen.at.max(0) as u64,
            None => {
                let at = now();
                let _ = self
                    .change_state(|s| {
                        s.first_seen = Some(Seen {
                            version: latest.clone(),
                            at: at as i64,
                        });
                        s.postponed = 0;
                    })
                    .await;
                at
            }
        };
        let mut due = if manual || !serving {
            now()
        } else if required {
            first_seen + jitter_seconds(120)
        } else {
            first_seen + rollout
        };
        due = due.max(self.postpone_until.load(Ordering::SeqCst));
        if now() < due {
            self.update(shell.as_ref(), |s| {
                s.phase = "ready".into();
                s.install_at = Some(due * 1000);
            })
            .await;
            return;
        }
        // Gates: never during a provider login or while the local API serves.
        if self.node.login_in_progress().await || self.api.snapshot().await.running {
            self.update(shell.as_ref(), |s| {
                s.phase = "ready".into();
                s.error = Some("busy".into());
            })
            .await;
            return;
        }
        // A visible, focused window gets a one-minute notice it can postpone.
        if !manual && shell.window_attentive() {
            let mut inner = self.inner.lock().await;
            let until = *inner.countdown_until.get_or_insert(now() + COUNTDOWN);
            if now() < until {
                inner.status.phase = "scheduled".into();
                inner.status.install_at = Some(until * 1000);
                shell.changed(&inner.status);
                return;
            }
        }
        self.inner.lock().await.countdown_until = None;
        match self.install(shell.clone()).await {
            Ok(()) => {}
            Err(code) => {
                self.install_now.store(false, Ordering::SeqCst);
                self.update(shell.as_ref(), |s| {
                    s.phase = if code == "drain_timeout" {
                        "ready".into()
                    } else {
                        "error".into()
                    };
                    s.error = Some(code);
                    s.in_flight = None;
                })
                .await;
            }
        }
    }

    /// Download and verify through the Go helper, reporting progress.
    async fn stage(&self, shell: &dyn Shell, mode: &str) -> std::result::Result<(), String> {
        let _busy = self.busy.lock().await;
        let mut command = self
            .node
            .command(&["desktop", "update-stage", mode])
            .map_err(|_| "unsupported".to_owned())?;
        command.stderr(std::process::Stdio::null());
        let mut child = command.spawn().map_err(|_| "unsupported".to_owned())?;
        let stdout = child.stdout.take().ok_or("unsupported")?;
        let (tx, mut rx) = tokio::sync::oneshot::channel();
        *self.cancel.lock().await = Some(tx);
        self.update(shell, |s| {
            s.phase = "downloading".into();
            s.progress = Some(0);
            s.error = None;
        })
        .await;
        let mut lines = BufReader::new(stdout).lines();
        let mut outcome = Err("install_failed".to_owned());
        loop {
            tokio::select! {
                _ = &mut rx => {
                    let _ = child.kill().await;
                    outcome = Err("cancelled".into());
                    break;
                }
                line = lines.next_line() => {
                    let Ok(Some(line)) = line else { break };
                    if line.len() > 4096 {
                        break;
                    }
                    let Ok(event) = serde_json::from_str::<StageEvent>(&line) else { continue };
                    match event.phase.as_str() {
                        "downloading" if event.total > 0 => {
                            let percent = (event.received.min(event.total) * 100 / event.total) as u8;
                            self.update(shell, |s| { s.phase = "downloading".into(); s.progress = Some(percent); }).await;
                        }
                        "verifying" => self.update(shell, |s| { s.phase = "verifying".into(); s.progress = None; }).await,
                        "staged" => { outcome = Ok(()); }
                        "error" => {
                            outcome = Err(fixed_code(event.error.as_deref().unwrap_or("install_failed")));
                        }
                        _ => {}
                    }
                }
            }
        }
        let _ = child.wait().await;
        self.cancel.lock().await.take();
        if outcome.is_ok() {
            self.update(shell, |s| {
                s.phase = "ready".into();
                s.progress = None;
            })
            .await;
        }
        outcome
    }

    /// Drain to idle without interrupting accepted work, stop, and hand off.
    async fn install(self: &Arc<Self>, shell: Arc<dyn Shell>) -> std::result::Result<(), String> {
        let _busy = self.busy.lock().await;
        let state = self.read_state().await.map_err(|_| "install_failed")?;
        let pending = state
            .pending
            .clone()
            .filter(|p| p.phase == "staged" && p.from == self.version)
            .ok_or("install_failed")?;
        let snapshot = self.node.snapshot().await;
        let serving = snapshot.supervised;
        let owner = if !serving {
            "none"
        } else if self.node.drain_marker() {
            "operator"
        } else {
            self.node
                .control("pause")
                .await
                .map_err(|_| "install_failed")?;
            "updater"
        };
        self.change_state(|s| {
            if let Some(p) = s.pending.as_mut() {
                p.phase = "draining".into();
                p.drain_owner = owner.into();
                p.resume_serving = serving;
            }
        })
        .await
        .map_err(|_| "install_failed")?;
        let undo = |updater: Arc<Self>| async move {
            if owner == "updater" {
                let _ = updater.node.control("resume").await;
            }
            let _ = updater
                .change_state(|s| {
                    if let Some(p) = s.pending.as_mut() {
                        p.phase = "staged".into();
                        p.drain_owner = "none".into();
                    }
                })
                .await;
        };
        if serving {
            let (tx, mut rx) = tokio::sync::oneshot::channel();
            *self.cancel.lock().await = Some(tx);
            let deadline = now() + DRAIN_LIMIT;
            loop {
                let snap = self.node.snapshot().await;
                let in_flight = snap
                    .observation
                    .as_ref()
                    .and_then(|o| o.get("in_flight"))
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0);
                if !snap.supervised || in_flight == 0 {
                    break;
                }
                self.update(shell.as_ref(), |s| {
                    s.phase = "draining".into();
                    s.in_flight = Some(in_flight);
                })
                .await;
                if now() > deadline {
                    self.cancel.lock().await.take();
                    undo(self.clone()).await;
                    let mut inner = self.inner.lock().await;
                    inner.drain_timeouts = inner.drain_timeouts.saturating_add(1);
                    self.postpone_until.store(now() + 3600, Ordering::SeqCst);
                    return Err("drain_timeout".into());
                }
                tokio::select! {
                    _ = &mut rx => {
                        undo(self.clone()).await;
                        return Err("cancelled".into());
                    }
                    _ = tokio::time::sleep(Duration::from_secs(3)) => {}
                }
            }
            self.cancel.lock().await.take();
        }
        self.update(shell.as_ref(), |s| {
            s.phase = "installing".into();
            s.in_flight = None;
        })
        .await;
        // Stop: closes the owner pipe; with nothing in flight it exits promptly.
        if self.api.stop().await.is_err() || self.node.stop().await.is_err() {
            undo(self.clone()).await;
            return Err("busy".into());
        }
        let guard = self.copy_guard(&pending.from).map_err(|_| "install_failed")?;
        let pid = std::process::id();
        self.change_state(|s| {
            if let Some(p) = s.pending.as_mut() {
                p.phase = "handoff".into();
                p.app_pid = pid;
            }
        })
        .await
        .map_err(|_| "install_failed")?;
        if spawn_guard(&guard, &self.state_dir).is_err() {
            undo(self.clone()).await;
            return Err("install_failed".into());
        }
        shell.exit_for_update();
        Ok(())
    }

    /// The guard is a copy of the running node binary outside the bundle, so
    /// the swap or installer never replaces the program doing it.
    fn copy_guard(&self, from: &str) -> std::io::Result<PathBuf> {
        let dir = self.state_dir.join("updates").join(format!("guard-{from}"));
        std::fs::create_dir_all(&dir)?;
        let name = if cfg!(windows) {
            "scarlett-node.exe"
        } else {
            "scarlett-node"
        };
        let target = dir.join(name);
        let temporary = dir.join(format!("{name}.tmp"));
        std::fs::copy(self.node.binary(), &temporary)?;
        std::fs::rename(&temporary, &target)?;
        Ok(target)
    }
}

/// Error codes the renderer knows; anything else is install_failed.
fn fixed_code(code: &str) -> String {
    match code {
        "network" | "signature_invalid" | "identity_mismatch" | "requirement_changed"
        | "disk_full" | "not_writable" | "translocated" | "unsupported" | "no_update_key"
        | "busy" | "app_management" => code.into(),
        _ => "install_failed".into(),
    }
}

fn jitter_seconds(limit: u64) -> u64 {
    if limit == 0 {
        return 0;
    }
    let mut bytes = [0u8; 8];
    let _ = getrandom::fill(&mut bytes);
    u64::from_le_bytes(bytes) % limit
}

/// Start the guard so that it outlives this app.
pub fn spawn_guard(guard: &Path, state_dir: &Path) -> std::io::Result<()> {
    let mut command = std::process::Command::new(guard);
    command
        .args(["desktop", "update-guard"])
        .env_clear()
        .env("SCARLETT_STATE_DIR", state_dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    for name in [
        "HOME",
        "USER",
        "PATH",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
        "TMPDIR",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // A new session: the guard survives the app's exit and its signals.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command.spawn().map(drop)
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
        command.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB);
        match command.spawn() {
            Ok(_) => Ok(()),
            // A job that forbids breakaway: start detached inside it.
            Err(_) => command
                .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
                .spawn()
                .map(drop),
        }
    }
}

/// The public changelog entry for a version.
pub fn changelog_url(version: &str) -> Result<String> {
    if compare_versions(version, version).is_none() {
        return Err(Error::InvalidInput);
    }
    Ok(format!("{CHANGELOG}#v{version}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering::*;

    #[test]
    fn versions_order_semantically_and_refuse_junk() {
        assert_eq!(compare_versions("0.1.10", "0.1.9"), Some(Greater));
        assert_eq!(compare_versions("0.1.13", "0.1.13"), Some(Equal));
        assert_eq!(compare_versions("0.1.13-rc.1", "0.1.13"), Some(Less));
        assert_eq!(compare_versions("0.1.13-rc.2", "0.1.13-rc.10"), Some(Less));
        assert_eq!(compare_versions("1.0.0", "0.99.99"), Some(Greater));
        for junk in ["", "0.1", "01.1.1", "0.1.1/../x", "0.1.1-", "<b>1</b>", "1.2.3-a b"] {
            assert_eq!(compare_versions(junk, "0.1.1"), None, "{junk}");
        }
        assert!(newer("0.1.14", "0.1.13"));
        assert!(!newer("x", "0.1.13"));
    }

    #[test]
    fn changelog_links_are_built_natively_from_a_version() {
        assert_eq!(
            changelog_url("0.1.13").unwrap(),
            "https://network.scarlett.ai/changelog/#v0.1.13"
        );
        for bad in ["0.1.13#x", "javascript:alert(1)", "../0.1.13", "0.1.13?x=1"] {
            assert_eq!(changelog_url(bad), Err(Error::InvalidInput), "{bad}");
        }
    }

    #[test]
    fn notes_are_short_plain_text() {
        let good = Notes {
            title: "Automatic updates".into(),
            date: "2026-10-09".into(),
            highlights: vec!["One".into()],
        };
        assert!(good.valid());
        for change in [
            |n: &mut Notes| n.title = "<b>x</b>".into(),
            |n: &mut Notes| n.title = "x".repeat(81),
            |n: &mut Notes| n.highlights = vec![],
            |n: &mut Notes| n.highlights = vec!["a".into(); 4],
            |n: &mut Notes| n.highlights = vec!["bell\u{7}".into()],
            |n: &mut Notes| n.highlights = vec![" padded".into()],
        ] {
            let mut notes = good.clone();
            change(&mut notes);
            assert!(!notes.valid(), "{notes:?}");
        }
        // The compiled-in notes for this build are valid when present.
        if let Some(notes) = own_notes() {
            assert!(notes.valid());
        }
    }

    #[test]
    fn state_round_trips_the_go_schema_and_drops_nothing_it_knows() {
        let raw = r#"{"schema":1,"installed":"0.1.13","high_water":"0.1.13","announced":"0.1.13","snooze":{"version":"0.1.14","until":1791480419},"first_seen":{"version":"0.1.14","at":1791480000},"postponed":2,"failed":["0.1.12"],"pending":{"phase":"staged","from":"0.1.13","to":"0.1.14","kind":"mac-app","staged":"/x/Scarlett Node.app","app":"/Applications/Scarlett Node.app","drain_owner":"none","resume_serving":true,"app_pid":42,"started_at":1791480419}}"#;
        let state: State = serde_json::from_str(raw).unwrap();
        assert_eq!(state.pending.as_ref().unwrap().to, "0.1.14");
        let back: serde_json::Value = serde_json::to_value(&state).unwrap();
        assert_eq!(back, serde_json::from_str::<serde_json::Value>(raw).unwrap());
        let empty: State = serde_json::from_str(r#"{"schema":1}"#).unwrap();
        assert_eq!(serde_json::to_string(&empty).unwrap(), r#"{"schema":1}"#);
    }

    #[test]
    fn stage_errors_map_to_fixed_codes() {
        assert_eq!(fixed_code("signature_invalid"), "signature_invalid");
        assert_eq!(fixed_code("<script>"), "install_failed");
        assert_eq!(fixed_code("exec: codesign failed"), "install_failed");
    }

    #[test]
    fn jitter_stays_inside_its_window() {
        for _ in 0..100 {
            assert!(jitter_seconds(120) < 120);
        }
        assert_eq!(jitter_seconds(0), 0);
    }
}
