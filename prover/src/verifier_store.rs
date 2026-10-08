//! Private, bounded verifier receipts, committed before external work or
//! acknowledgement, and the page body files of web receipts beside them.
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub const MAX_RECORDS: usize = 1024;
pub const MAX_RECORD_BYTES: u64 = 64 << 20;
pub const MAX_TOTAL_BYTES: u64 = 256 << 20;
/// The default web pool: two web reservations, leaving one full receipt.
pub const MAX_WEB_BYTES: u64 = 192 << 20;
pub const RETENTION_MS: u64 = 24 * 60 * 60 * 1000;
/// Web receipts are kept ten minutes past expiry, not a day. The coordinator
/// reads one only before its job's deadline and keeps the signed result
/// itself; the ten minutes cover clock skew. A day of web pages would fill
/// the store Codex and X share and refuse every registration.
pub const WEB_RETENTION_MS: u64 = 10 * 60 * 1000;

fn web(payload: &Value) -> bool {
    payload["type"] == "web.fetch"
}

/// How long a receipt with this payload is kept past its expiry.
pub fn retention_ms(payload: &Value) -> u64 {
    if web(payload) { WEB_RETENTION_MS } else { RETENTION_MS }
}

/// One hop's share of a web receipt's JSON: its head in base64, two URLs, a
/// browser hop's User-Agent and cookie names (which fit in one Cookie
/// header), and the fixed fields around them.
pub const WEB_JSON_PER_HOP: u64 = (4 * crate::webpolicy::MAX_HEAD.div_ceil(3) + 2 * crate::webpolicy::MAX_URL + crate::webpolicy::MAX_COOKIE + 3 * crate::webpolicy::MAX_COOKIE_PAIRS + 3072) as u64;

/// The most a web receipt's JSON can hold: every hop plus 64 KiB for the
/// receipt around them. The page itself is never in the JSON.
pub fn web_json_bound(max_redirects: usize) -> u64 {
    (max_redirects as u64 + 1) * WEB_JSON_PER_HOP + (64 << 10)
}

/// What an unresolved web receipt is charged: its JSON bound and a full page.
pub fn web_reservation(max_redirects: usize) -> u64 {
    web_json_bound(max_redirects) + crate::webpolicy::PAGE_MAX as u64
}

/// The most a web job's reservation can be (five redirects).
pub const WEB_RESERVATION: u64 = (crate::webpolicy::MAX_REDIRECTS as u64 + 1) * WEB_JSON_PER_HOP + (64 << 10) + crate::webpolicy::PAGE_MAX as u64;

/// The space an unresolved receipt reserves: a web job's own reservation
/// (never clamped by the record limit, since its page is a file of its own),
/// otherwise the record limit.
fn reserve(payload: &Value, limits: Limits) -> u64 {
    if !web(payload) {
        return limits.max_record_bytes;
    }
    match payload["max_redirects"].as_u64() {
        Some(redirects) if redirects <= crate::webpolicy::MAX_REDIRECTS as u64 => web_reservation(redirects as usize),
        _ => WEB_RESERVATION,
    }
}

/// The page body a receipt holds as a file: the final hop's `body_bytes`
/// when the receipt is complete, its last hop says `body_stored` and the
/// body was not released.
fn stored_body(record: &Record) -> Option<u64> {
    let status = &record.status;
    if status["status"] != "web_read" || status["complete"] != true || !status["body_released_at_ms"].is_null() {
        return None;
    }
    let last = status["hops"].as_array()?.last()?;
    if last["body_stored"] != true {
        return None;
    }
    last["body_bytes"].as_u64()
}

/// Whether a receipt keeps a page in its JSON, as receipts did before page
/// bodies became files.
fn holds_body_base64(record: &Record) -> bool {
    record.status["hops"].as_array().is_some_and(|hops| hops.iter().any(|hop| hop.get("body_base64").is_some()))
}

#[derive(Clone, Copy, Serialize)]
pub struct Limits {
    pub max_records: usize,
    pub max_record_bytes: u64,
    pub max_total_bytes: u64,
    /// The web pool: web reservations and page bodies.
    pub max_web_bytes: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self { max_records: MAX_RECORDS, max_record_bytes: MAX_RECORD_BYTES, max_total_bytes: MAX_TOTAL_BYTES, max_web_bytes: MAX_WEB_BYTES }
    }
}
impl Limits {
    /// The web pool must hold one web reservation and leave one full X or
    /// Codex receipt in the total.
    pub fn validate(self) -> Result<Self> {
        if !(1..=1_000_000).contains(&self.max_records)
            || !(1 << 20..=MAX_RECORD_BYTES).contains(&self.max_record_bytes)
            || self.max_total_bytes < self.max_record_bytes
            || self.max_total_bytes > 1 << 40
            || !(WEB_RESERVATION..=1 << 40).contains(&self.max_web_bytes)
            || self.max_web_bytes + self.max_record_bytes > self.max_total_bytes
        {
            bail!("invalid verifier capacity limits");
        }
        Ok(self)
    }
}
#[derive(Serialize)]
pub struct Capacity {
    pub limits: Limits,
    pub records: usize,
    /// Bytes on disk: receipts and page bodies.
    pub bytes: u64,
    /// What registrations are checked against: every receipt's charge plus
    /// the page bodies.
    pub reserved_bytes: u64,
    /// Whether one more worst-case X or Codex receipt fits.
    pub can_register: bool,
    pub body_files: usize,
    pub body_bytes: u64,
}
/// The web pool, as `GET /v1/capacity` reports it under `web`.
#[derive(Serialize)]
pub struct WebPool {
    /// Whether one more web reservation fits the pool and the total.
    pub can_register: bool,
    /// Web receipts' charges, bodies apart.
    pub reserved_bytes: u64,
    pub body_files: usize,
    pub body_bytes: u64,
    pub max_bytes: u64,
}
fn unresolved(record: &Record) -> bool {
    if record.in_flight > 0 { return true; }
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
    if record.expires_ms <= now { return false; }
     matches!(record.status["status"].as_str(), Some("pending" | "running"))
        || record.status["status"] == "x_read" && record.status["complete"] != true && record.status["remaining_attempts"].as_u64().unwrap_or(0) > 0
        // A web job that can still run a hop may yet store a full page.
        || record.status["status"] == "web_read"
            && record.status["complete"] != true
            && record.status["rejections"].as_array().is_some_and(Vec::is_empty)
            && record.status["remaining_sessions"].as_u64().unwrap_or(0) > 0
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub schema: u8,
    pub job_id: String,
    pub attempt: String,
    pub fence: String,
    pub payload: Value,
    pub status: Value,
    pub expires_ms: u64,
    pub in_flight: usize,
    pub token: Option<String>,
}

pub fn field(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
pub fn hash(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}
/// The name every file of one receipt starts with.
fn stem(job: &str, attempt: &str) -> String {
    hash(format!("{job}\n{attempt}").as_bytes())
}
fn name(job: &str, attempt: &str) -> String {
    format!("{}.json", stem(job, attempt))
}
fn private_file(file: &File, max_bytes: u64) -> Result<()> {
    let info = file.metadata()?;
    if !info.is_file() || info.uid() != unsafe { libc::geteuid() } || info.mode() & 0o077 != 0 || info.len() > max_bytes {
        bail!("invalid verifier state file");
    }
    Ok(())
}
fn open_private(path: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)
}
fn read_private(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let f = open_private(path)?;
    private_file(&f, max_bytes)?;
    let mut raw = Vec::new();
    f.take(max_bytes + 1).read_to_end(&mut raw)?;
    if raw.len() as u64 > max_bytes {
        bail!("verifier state too large");
    }
    Ok(raw)
}

/// One receipt's accounting.
#[derive(Clone, Copy, Default)]
struct Charge {
    /// JSON bytes on disk.
    size: u64,
    /// The receipt's charge without its body: its reservation while
    /// unresolved, else its size.
    reservation: u64,
    /// A stored, unreleased page body's size.
    body: Option<u64>,
    web: bool,
}

impl Charge {
    fn body(&self) -> u64 {
        self.body.unwrap_or(0)
    }
}

pub struct Store {
    dir: PathBuf,
    _lock: File,
    charges: HashMap<String, Charge>,
    limits: Limits,
    /// Bytes on disk: receipts and bodies.
    total_bytes: u64,
    /// Every charge plus every body.
    reserved_bytes: u64,
    /// Web receipts' charges, and their bodies.
    web_reserved: u64,
    body_bytes: u64,
    body_files: usize,
}
impl Store {
    #[cfg(test)]
    pub fn open(dir: &Path) -> Result<(Self, Vec<Record>)> { Self::open_with_limits(dir, Limits::default()) }
    pub fn open_with_limits(dir: &Path, limits: Limits) -> Result<(Self, Vec<Record>)> {
        let limits = limits.validate()?;
        if !dir.is_absolute() {
            bail!("verifier state directory must be absolute");
        }
        DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        let info = fs::symlink_metadata(dir)?;
        if !info.is_dir() || info.uid() != unsafe { libc::geteuid() } || info.mode() & 0o077 != 0 {
            bail!("verifier state directory must be private (0700)");
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(dir.join(".lock"))?;
        private_file(&lock, limits.max_record_bytes)?;
        lock.try_lock().context("another verifier owns the state directory")?;
        let mut store = Self {
            dir: dir.to_owned(),
            _lock: lock,
            charges: HashMap::new(),
            limits,
            total_bytes: 0,
            reserved_bytes: 0,
            web_reserved: 0,
            body_bytes: 0,
            body_files: 0,
        };
        let mut records = Vec::new();
        let mut bodies = HashSet::new();
        let mut stale = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let file_name = entry.file_name().into_string().map_err(|_| anyhow::anyhow!("invalid verifier state filename"))?;
            if file_name == ".lock" {
                continue;
            }
            if file_name.starts_with(".write-") || file_name.ends_with(crate::body::PARTIAL_SUFFIX) {
                stale.push(entry.path());
                continue;
            }
            if let Some(stem) = file_name.strip_suffix(crate::body::SUFFIX) {
                bodies.insert(stem.to_owned());
                continue;
            }
            if records.len() >= limits.max_records {
                bail!("verifier state has too many records");
            }
            let raw = read_private(&entry.path(), limits.max_record_bytes)?;
            let record: Record = serde_json::from_slice(&raw).context("invalid verifier state")?;
            if record.schema != 1
                || !field(&record.job_id)
                || !field(&record.attempt)
                || !field(&record.fence)
                || file_name != name(&record.job_id, &record.attempt)
                || record.expires_ms == 0
                || record.in_flight > 3
                || record
                    .token
                    .as_ref()
                    .is_some_and(|t| t.len() != 64 || !t.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
            {
                bail!("invalid verifier receipt identity");
            }
            if holds_body_base64(&record) {
                bail!("the verifier state holds a web receipt with its page inline (body_base64) from before page body files; pause web and let it age out (10 minutes after its expiry) before starting this verifier");
            }
            let charge = store.charge(&record, raw.len() as u64);
            store.add(&file_name, charge);
            if store.total_bytes > limits.max_total_bytes {
                bail!("verifier state exceeds storage bound");
            }
            records.push(record);
        }
        // Every stored, unreleased body must be there whole; every other
        // body file is an orphan of a crash.
        for record in &records {
            let stem = stem(&record.job_id, &record.attempt);
            if let Some(bytes) = stored_body(record) {
                let path = store.body_path(&record.job_id, &record.attempt);
                let file = open_private(&path).context("a stored page body is missing")?;
                if private_file(&file, crate::webpolicy::PAGE_MAX as u64).is_err() || file.metadata()?.len() != bytes {
                    bail!("a stored page body does not match its receipt");
                }
                bodies.remove(&stem);
            }
        }
        stale.extend(bodies.iter().map(|stem| dir.join(format!("{stem}{}", crate::body::SUFFIX))));
        for path in stale {
            fs::remove_file(path)?;
        }
        File::open(dir)?.sync_all()?;
        Ok((store, records))
    }
    fn charge(&self, record: &Record, size: u64) -> Charge {
        let reservation = if unresolved(record) { reserve(&record.payload, self.limits).max(size) } else { size };
        Charge { size, reservation, body: stored_body(record), web: web(&record.payload) }
    }
    fn add(&mut self, file_name: &str, charge: Charge) {
        self.total_bytes += charge.size + charge.body();
        self.reserved_bytes += charge.reservation + charge.body();
        if charge.web {
            self.web_reserved += charge.reservation;
        }
        self.body_bytes += charge.body();
        self.body_files += usize::from(charge.body.is_some());
        self.charges.insert(file_name.to_owned(), charge);
    }
    fn take(&mut self, file_name: &str) -> Charge {
        let charge = self.charges.remove(file_name).unwrap_or_default();
        self.total_bytes -= charge.size + charge.body();
        self.reserved_bytes -= charge.reservation + charge.body();
        if charge.web {
            self.web_reserved -= charge.reservation;
        }
        self.body_bytes -= charge.body();
        self.body_files -= usize::from(charge.body.is_some());
        charge
    }
    /// The web pool in use: web charges and bodies.
    fn web_used(&self) -> u64 {
        self.web_reserved + self.body_bytes
    }
    pub fn save(&mut self, record: &Record) -> Result<()> {
        let file_name = name(&record.job_id, &record.attempt);
        let raw = serde_json::to_vec(record)?;
        let new = self.charge(record, raw.len() as u64);
        let old = self.charges.get(&file_name).copied();
        let (old_size, old_charge, old_web) = old.map_or((0, 0, 0), |c| (c.size + c.body(), c.reservation + c.body(), if c.web { c.reservation + c.body() } else { 0 }));
        let new_charge = new.reservation + new.body();
        let growing = old.is_none() || new_charge > old_charge;
        if raw.len() as u64 > self.limits.max_record_bytes
            || self.total_bytes - old_size + new.size + new.body() > self.limits.max_total_bytes
            || old.is_none() && self.charges.len() >= self.limits.max_records
            || growing && self.reserved_bytes - old_charge + new_charge > self.limits.max_total_bytes
            || growing && new.web && self.web_used() - old_web + new_charge > self.limits.max_web_bytes
        {
            bail!("verifier receipt storage full");
        }
        let temp = self.dir.join(format!(".write-{}", rand::random::<u128>()));
        let result = (|| -> Result<()> {
            let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temp)?;
            file.write_all(&raw)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temp, self.dir.join(&file_name))?;
            File::open(&self.dir)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result?;
        self.take(&file_name);
        self.add(&file_name, new);
        Ok(())
    }
    /// Whether a new session with this payload can be registered: a record
    /// slot and its reservation are free, in the web pool too for a web job.
    pub fn can_reserve(&self, payload: &Value) -> bool {
        let reservation = reserve(payload, self.limits);
        self.charges.len() < self.limits.max_records
            && self.reserved_bytes.saturating_add(reservation) <= self.limits.max_total_bytes
            && (!web(payload) || self.web_used().saturating_add(reservation) <= self.limits.max_web_bytes)
    }
    pub fn capacity(&self) -> Capacity {
        Capacity {
            limits: self.limits,
            records: self.charges.len(),
            bytes: self.total_bytes,
            reserved_bytes: self.reserved_bytes,
            can_register: self.charges.len() < self.limits.max_records && self.reserved_bytes.saturating_add(self.limits.max_record_bytes) <= self.limits.max_total_bytes,
            body_files: self.body_files,
            body_bytes: self.body_bytes,
        }
    }
    pub fn web_pool(&self) -> WebPool {
        WebPool {
            can_register: self.charges.len() < self.limits.max_records
                && self.reserved_bytes.saturating_add(WEB_RESERVATION) <= self.limits.max_total_bytes
                && self.web_used().saturating_add(WEB_RESERVATION) <= self.limits.max_web_bytes,
            reserved_bytes: self.web_reserved,
            body_files: self.body_files,
            body_bytes: self.body_bytes,
            max_bytes: self.limits.max_web_bytes,
        }
    }
    /// Where a receipt's page body lives.
    pub fn body_path(&self, job: &str, attempt: &str) -> PathBuf {
        self.dir.join(format!("{}{}", stem(job, attempt), crate::body::SUFFIX))
    }
    /// Removes a receipt. A page body file it may have left is the caller's
    /// to unlink (returned), after the receipt is gone: a crash between the
    /// two leaves an orphan body, which the next open deletes.
    pub fn remove(&mut self, job: &str, attempt: &str) -> Result<Option<PathBuf>> {
        let file_name = name(job, attempt);
        fs::remove_file(self.dir.join(&file_name))?;
        File::open(&self.dir)?.sync_all()?;
        let charge = self.take(&file_name);
        Ok(charge.web.then(|| self.body_path(job, attempt)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("scarlett-verifier-{}", rand::random::<u128>()));
            DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn record() -> Record {
        Record {
            schema: 1,
            job_id: "synthetic".into(),
            attempt: "1".into(),
            fence: "f1".into(),
            payload: serde_json::json!({"type":"response.create","model":"synthetic"}),
            status: serde_json::json!({"status":"pending"}),
            expires_ms: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64 + 600_000,
            in_flight: 0,
            token: Some("a".repeat(64)),
        }
    }
    #[test]
    fn exclusive_lock_atomic_receipt_and_restart() {
        let dir = Temp::new();
        let (mut store, records) = Store::open(&dir.0).unwrap();
        assert!(records.is_empty());
        assert!(Store::open(&dir.0).is_err());
        let mut r = record();
        store.save(&r).unwrap();
        assert_eq!(fs::metadata(dir.0.join(name(&r.job_id, &r.attempt))).unwrap().mode() & 0o777, 0o600);
        r.status = serde_json::json!({"status":"running"});
        r.token = None;
        r.in_flight = 1;
        store.save(&r).unwrap();
        drop(store);
        let (mut store, records) = Store::open(&dir.0).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].status["status"], "running");
        assert!(records[0].token.is_none());
        store.remove(&r.job_id, &r.attempt).unwrap();
        drop(store);
        assert!(Store::open(&dir.0).unwrap().1.is_empty());
    }
    #[test]
    fn rejects_corrupt_public_symlink_fifo_and_oversized_records() {
        for kind in ["corrupt", "public", "symlink", "fifo", "large"] {
            let dir = Temp::new();
            let path = dir.0.join(name("synthetic", "1"));
            match kind {
                "symlink" => symlink("missing", &path).unwrap(),
                "fifo" => {
                    let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
                }
                "large" => {
                    let file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).unwrap();
                    file.set_len(MAX_RECORD_BYTES + 1).unwrap();
                }
                "public" => {
                    fs::write(&path, serde_json::to_vec(&record()).unwrap()).unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                }
                _ => {
                    fs::write(&path, b"invalid JSON").unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
                }
            }
            assert!(Store::open(&dir.0).is_err(), "{kind} accepted");
        }
    }
    #[test]
    fn full_store_and_abandoned_writes_fail_without_overwriting_receipts() {
        let dir = Temp::new();
        let (mut store, _) = Store::open(&dir.0).unwrap();
        for i in 0..MAX_RECORDS {
            let mut r = record();
            r.attempt = i.to_string();
            r.status = serde_json::json!({"status":"expired"});
            store.save(&r).unwrap();
        }
        let mut extra = record();
        extra.attempt = "overflow".into();
        assert!(store.save(&extra).is_err());
        let mut existing = record();
        existing.attempt = "0".into();
        existing.status = serde_json::json!({"status":"expired"});
        store.save(&existing).unwrap();
        fs::write(dir.0.join(".write-abandoned"), b"private unfinished receipt").unwrap();
        drop(store);
        let (_, records) = Store::open(&dir.0).unwrap();
        assert_eq!(records.len(), MAX_RECORDS);
        assert!(!dir.0.join(".write-abandoned").exists());
        assert!(records.iter().any(|r| r.attempt == "0" && r.status["status"] == "expired"));
    }
    /// The smallest valid limits around `record` bytes per receipt: a web
    /// pool of one web reservation and room for `x` more full receipts.
    fn small(max_records: usize, record: u64, x: u64) -> Limits {
        Limits { max_records, max_record_bytes: record, max_web_bytes: WEB_RESERVATION, max_total_bytes: WEB_RESERVATION + x * record }
    }
    #[test]
    fn reservations_guarantee_result_space_and_survive_restart() {
        let dir = Temp::new();
        // Two full X or Codex reservations fit beside the web pool's room, not three.
        let limits = Limits { max_records: 8, max_record_bytes: 64 << 20, max_web_bytes: WEB_RESERVATION, max_total_bytes: WEB_RESERVATION + (64 << 20) };
        let (mut store, _) = Store::open_with_limits(&dir.0, limits).unwrap();
        let mut first = record();
        store.save(&first).unwrap();
        let mut second = record(); second.attempt = "2".into(); store.save(&second).unwrap();
        assert!(!store.capacity().can_register);
        let mut third = record(); third.attempt = "3".into(); assert!(store.save(&third).is_err());
        first.status = serde_json::json!({"status":"accepted", "output":"x".repeat(100_000)});
        first.token = None;
        store.save(&first).unwrap();
        assert!(store.capacity().reserved_bytes < limits.max_total_bytes);
        drop(store);
        let (mut store, records) = Store::open_with_limits(&dir.0, limits).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(store.capacity().records, 2);
        second.status = serde_json::json!({"status":"rejected","reason":"execution_uncertain"});
        second.token = None;
        store.save(&second).unwrap();
        assert!(store.capacity().can_register);
        store.save(&third).unwrap();
    }
    fn web_record(attempt: &str, status: Value) -> Record {
        Record { attempt: attempt.into(), payload: serde_json::json!({"type":"web.fetch","url":"https://example.com/","max_redirects":5,"max_response_bytes":crate::webpolicy::PAGE_MAX}), status, ..record() }
    }
    fn web_status(remaining: u64, complete: bool, rejections: Value) -> Value {
        serde_json::json!({"status":"web_read","remaining_sessions":remaining,"complete":complete,"next_url":null,"hops":[],"rejections":rejections,"rejection":null,"body_released_at_ms":null})
    }
    /// A complete web receipt whose final hop stored `bytes` (released at `released`).
    fn web_done(bytes: u64, released: Option<u64>) -> Value {
        serde_json::json!({"status":"web_read","remaining_sessions":5,"complete":true,"next_url":null,
            "hops":[{"index":0,"body_stored":true,"body_bytes":bytes}],"rejections":[],"rejection":null,"body_released_at_ms":released})
    }
    #[test]
    fn web_receipts_reserve_space_only_while_a_hop_can_still_run() {
        let dir = Temp::new();
        let limits = small(8, 1 << 20, 4);
        let (mut store, _) = Store::open_with_limits(&dir.0, limits).unwrap();
        let mut r = web_record("1", Value::Null);
        for (status, reserved) in [
            (web_status(6, false, serde_json::json!([])), true),
            (web_status(0, false, serde_json::json!([])), false),
            (web_status(3, true, serde_json::json!([])), false),
            (web_status(5, false, serde_json::json!(["tls_failed"])), false),
        ] {
            r.status = status;
            assert_eq!(unresolved(&r), reserved, "{}", r.status);
            store.save(&r).unwrap();
            assert_eq!(store.capacity().reserved_bytes == WEB_RESERVATION, reserved);
            assert_eq!(store.web_pool().reserved_bytes == WEB_RESERVATION, reserved);
        }
        // Expiry releases the reservation whatever the status says.
        r.status = web_status(6, false, serde_json::json!([]));
        r.expires_ms = 1;
        assert!(!unresolved(&r));
        r.in_flight = 1;
        assert!(unresolved(&r));
    }
    #[test]
    fn web_receipts_reserve_their_bound_unclamped_and_keep_a_short_retention() {
        assert_eq!((WEB_JSON_PER_HOP, web_json_bound(5), web_reservation(5), WEB_RESERVATION), (98_798, 658_324, 67_767_188, 67_767_188));
        let dir = Temp::new();
        let limits = small(16, 64 << 20, 1);
        let (mut store, _) = Store::open_with_limits(&dir.0, limits).unwrap();
        let web = web_record("1", web_status(6, false, serde_json::json!([])));
        assert!(store.can_reserve(&web.payload));
        store.save(&web).unwrap();
        // The reservation is above the record limit: it is never clamped to it.
        assert_eq!(store.capacity().reserved_bytes, WEB_RESERVATION);
        assert!(WEB_RESERVATION > limits.max_record_bytes);
        // The pool is full, and X and Codex still have their floor.
        assert!(!store.can_reserve(&web.payload) && !store.web_pool().can_register);
        assert!(store.can_reserve(&record().payload) && store.capacity().can_register);
        let mut second = web;
        second.attempt = "2".into();
        assert!(store.save(&second).is_err());
        // A web payload without its bounds reserves the most a web job can.
        assert_eq!(reserve(&serde_json::json!({"type":"web.fetch"}), limits), WEB_RESERVATION);
        assert_eq!(retention_ms(&second.payload), WEB_RETENTION_MS);
        assert_eq!(retention_ms(&record().payload), RETENTION_MS);
        drop(store);
        let (store, _) = Store::open_with_limits(&dir.0, limits).unwrap();
        assert_eq!(store.capacity().reserved_bytes, WEB_RESERVATION);
    }
    #[test]
    fn a_24_gib_web_pool_holds_380_pages_and_x_still_registers() {
        let dir = Temp::new();
        let limits = Limits { max_records: 1024, max_record_bytes: 64 << 20, max_total_bytes: 32 << 30, max_web_bytes: 24 << 30 };
        let (mut store, _) = Store::open_with_limits(&dir.0, limits).unwrap();
        for i in 0..380 {
            let web = web_record(&format!("w{i}"), web_status(6, false, serde_json::json!([])));
            assert!(store.can_reserve(&web.payload), "web {i}");
            store.save(&web).unwrap();
        }
        let extra = web_record("w380", web_status(6, false, serde_json::json!([])));
        assert!(!store.can_reserve(&extra.payload) && !store.web_pool().can_register);
        assert!(store.save(&extra).is_err());
        // X and Codex keep their 8 GiB floor: 128 full receipts.
        assert!(store.capacity().can_register);
        for i in 0..128 {
            let mut x = record();
            x.attempt = format!("x{i}");
            assert!(store.can_reserve(&x.payload), "x {i}");
            store.save(&x).unwrap();
        }
        assert!(!store.capacity().can_register);
        assert_eq!(store.web_pool().reserved_bytes, 380 * WEB_RESERVATION);
    }
    #[test]
    fn page_bodies_count_until_released_and_unexpected_bodies_go_at_open() {
        let dir = Temp::new();
        // A pool of one page and 4 KiB.
        let limits = Limits { max_records: 16, max_record_bytes: 1 << 20, max_web_bytes: WEB_RESERVATION + 4096, max_total_bytes: WEB_RESERVATION + 4096 + (2 << 20) };
        let (mut store, _) = Store::open_with_limits(&dir.0, limits).unwrap();
        let mut page = web_record("1", web_status(6, false, serde_json::json!([])));
        store.save(&page).unwrap();
        // The body file is written before the receipt that names it.
        let body = store.body_path("synthetic", "1");
        fs::write(&body, vec![b'p'; 5000]).unwrap();
        fs::set_permissions(&body, fs::Permissions::from_mode(0o600)).unwrap();
        page.status = web_done(5000, None);
        store.save(&page).unwrap();
        let json = store.capacity().bytes - 5000;
        let c = store.capacity();
        assert_eq!((c.body_files, c.body_bytes, c.reserved_bytes), (1, 5000, json + 5000));
        let pool = store.web_pool();
        assert_eq!((pool.reserved_bytes, pool.body_files, pool.body_bytes, pool.max_bytes), (json, 1, 5000, WEB_RESERVATION + 4096));
        // The pool counts the body: another page does not fit until it is released.
        assert!(!store.web_pool().can_register);
        drop(store);
        let (mut store, records) = Store::open_with_limits(&dir.0, limits).unwrap();
        assert_eq!((records.len(), store.capacity().body_bytes), (1, 5000));
        assert!(body.exists());
        page.status = web_done(5000, Some(7));
        store.save(&page).unwrap();
        assert_eq!((store.capacity().body_files, store.capacity().body_bytes), (0, 0));
        assert!(store.web_pool().can_register);
        // A released body still on disk (the unlink did not happen) goes at open.
        drop(store);
        let (store, _) = Store::open_with_limits(&dir.0, limits).unwrap();
        assert!(!body.exists());
        // A removed receipt hands back its body path for the caller to unlink.
        let mut store = store;
        assert_eq!(store.remove("synthetic", "1").unwrap(), Some(body.clone()));
        assert_eq!(store.capacity().bytes, 0);
    }
    #[test]
    fn crash_leftovers_are_removed_and_missing_bodies_or_inline_pages_stop_startup() {
        let limits = small(16, 1 << 20, 2);
        let setup = |status: Value, body: Option<(&[u8], u32)>| {
            let dir = Temp::new();
            let (store, _) = Store::open_with_limits(&dir.0, limits).unwrap();
            let page = web_record("1", status);
            if let Some((bytes, mode)) = body {
                let path = store.body_path("synthetic", "1");
                fs::write(&path, bytes).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            }
            // Bypass save's accounting checks: write the receipt as a crash would leave it.
            let raw = serde_json::to_vec(&page).unwrap();
            let path = dir.0.join(name("synthetic", "1"));
            fs::write(&path, raw).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            drop(store);
            dir
        };
        // A whole stored body opens.
        let dir = setup(web_done(4, None), Some((b"page", 0o600)));
        assert!(Store::open_with_limits(&dir.0, limits).is_ok());
        // Orphans: a partial body, a body no receipt holds, a body of a receipt that never stored one.
        let dir = setup(web_status(6, false, serde_json::json!([])), Some((b"orphan", 0o600)));
        let partial = dir.0.join(format!("{}{}", "ab".repeat(32), crate::body::PARTIAL_SUFFIX));
        let lost = dir.0.join(format!("{}{}", "cd".repeat(32), crate::body::SUFFIX));
        fs::write(&partial, b"half").unwrap();
        fs::write(&lost, b"lost").unwrap();
        let (store, records) = Store::open_with_limits(&dir.0, limits).unwrap();
        assert_eq!(records.len(), 1);
        assert!(!partial.exists() && !lost.exists() && !store.body_path("synthetic", "1").exists());
        drop(store);
        // A stored body that is missing, short, long or public stops startup.
        for (case, body) in [("missing", None), ("short", Some((&b"pag"[..], 0o600))), ("long", Some((&b"pages"[..], 0o600))), ("public", Some((&b"page"[..], 0o644)))] {
            let dir = setup(web_done(4, None), body);
            assert!(Store::open_with_limits(&dir.0, limits).is_err(), "{case} accepted");
        }
        // A receipt from before page body files stops startup with a reason.
        let old = serde_json::json!({"status":"web_read","remaining_sessions":5,"complete":true,"next_url":null,"hops":[{"index":0,"body_base64":"cGFnZQ==","body_bytes":4}],"rejections":[]});
        let dir = setup(old, None);
        let error = Store::open_with_limits(&dir.0, limits).err().unwrap();
        assert!(format!("{error:#}").contains("body_base64"), "{error:#}");
    }
    #[test]
    fn invalid_capacity_limits_fail_closed() {
        let ok = Limits::default();
        assert!(ok.validate().is_ok());
        assert_eq!((ok.max_total_bytes, ok.max_record_bytes, ok.max_web_bytes), (256 << 20, 64 << 20, 192 << 20));
        for limits in [
            Limits { max_records: 0, ..ok },
            Limits { max_record_bytes: 1, ..ok },
            Limits { max_total_bytes: 1, ..ok },
            // The pool must hold one web page and leave one full receipt.
            Limits { max_web_bytes: WEB_RESERVATION - 1, ..ok },
            Limits { max_web_bytes: ok.max_total_bytes - ok.max_record_bytes + 1, ..ok },
        ] {
            assert!(limits.validate().is_err());
            let dir = Temp::new(); assert!(Store::open_with_limits(&dir.0, limits).is_err());
        }
        assert!(Limits { max_web_bytes: ok.max_total_bytes - ok.max_record_bytes, ..ok }.validate().is_ok());
    }
    #[test]
    #[ignore = "synthetic fsync benchmark; run explicitly"]
    fn benchmark_synthetic_receipt_commits() {
        let dir = Temp::new();
        let (mut store, _) = Store::open(&dir.0).unwrap();
        let started = std::time::Instant::now();
        let mut bytes = 0;
        for i in 0..100 {
            let mut r = record(); r.attempt = i.to_string();
            store.save(&r).unwrap();
            r.token = None;
            r.status = serde_json::json!({"status":"accepted","output":"s".repeat(64 * 1024)});
            bytes += serde_json::to_vec(&r).unwrap().len();
            store.save(&r).unwrap();
        }
        println!("synthetic receipts=100 durable_writes=200 final_bytes={bytes} elapsed_ms={}", started.elapsed().as_millis());
    }

}
