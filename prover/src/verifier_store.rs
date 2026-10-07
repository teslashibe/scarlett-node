//! Private, bounded verifier receipts, committed before external work or acknowledgement.
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub const MAX_RECORDS: usize = 1024;
pub const MAX_RECORD_BYTES: u64 = 64 << 20;
pub const MAX_TOTAL_BYTES: u64 = 256 << 20;
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

/// The most a web receipt can hold: the final body and every hop's head in
/// base64, two URLs per hop and the fixed fields around them.
pub fn web_receipt_bound(max_response_bytes: usize, max_redirects: usize) -> u64 {
    let base64 = |n: usize| 4 * n.div_ceil(3);
    let per_hop = base64(crate::webpolicy::MAX_HEAD) + 2 * crate::webpolicy::MAX_URL + 2048;
    (base64(max_response_bytes) + (max_redirects + 1) * per_hop + (64 << 10)) as u64
}

/// The space an unresolved receipt reserves: a web job's own bound (a page
/// is far smaller than an X or Codex receipt may grow), otherwise the record
/// limit.
fn reserve(payload: &Value, limits: Limits) -> u64 {
    match (payload["max_response_bytes"].as_u64(), payload["max_redirects"].as_u64()) {
        (Some(bytes), Some(redirects)) if web(payload) && bytes <= 1 << 30 && redirects <= 16 => {
            web_receipt_bound(bytes as usize, redirects as usize).min(limits.max_record_bytes)
        }
        _ => limits.max_record_bytes,
    }
}

#[derive(Clone, Copy, Serialize)]
pub struct Limits {
    pub max_records: usize,
    pub max_record_bytes: u64,
    pub max_total_bytes: u64,
}
impl Default for Limits {
    fn default() -> Self { Self { max_records: MAX_RECORDS, max_record_bytes: MAX_RECORD_BYTES, max_total_bytes: MAX_TOTAL_BYTES } }
}
impl Limits {
    pub fn validate(self) -> Result<Self> {
        if !(1..=1_000_000).contains(&self.max_records) || !(1 << 20..=MAX_RECORD_BYTES).contains(&self.max_record_bytes)
            || self.max_total_bytes < self.max_record_bytes || self.max_total_bytes > 1 << 40 {
            bail!("invalid verifier capacity limits");
        }
        Ok(self)
    }
}
#[derive(Serialize)]
pub struct Capacity {
    pub limits: Limits,
    pub records: usize,
    pub bytes: u64,
    pub reserved_bytes: u64,
    pub can_register: bool,
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
fn name(job: &str, attempt: &str) -> String {
    format!("{}.json", hash(format!("{job}\n{attempt}").as_bytes()))
}
fn private_file(file: &File, max_bytes: u64) -> Result<()> {
    let info = file.metadata()?;
    if !info.is_file() || info.uid() != unsafe { libc::geteuid() } || info.mode() & 0o077 != 0 || info.len() > max_bytes {
        bail!("invalid verifier state file");
    }
    Ok(())
}
fn read_private(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let f = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    private_file(&f, max_bytes)?;
    let mut raw = Vec::new();
    f.take(max_bytes + 1).read_to_end(&mut raw)?;
    if raw.len() as u64 > max_bytes {
        bail!("verifier state too large");
    }
    Ok(raw)
}

pub struct Store {
    dir: PathBuf,
    _lock: File,
    sizes: HashMap<String, u64>,
    reservations: HashMap<String, u64>,
    limits: Limits,
    total_bytes: u64,
    reserved_bytes: u64,
}
impl Store {
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
        let mut store = Self { dir: dir.to_owned(), _lock: lock, sizes: HashMap::new(), reservations: HashMap::new(), limits, total_bytes: 0, reserved_bytes: 0 };
        let mut records = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let file_name = entry.file_name().into_string().map_err(|_| anyhow::anyhow!("invalid verifier state filename"))?;
            if file_name == ".lock" {
                continue;
            }
            if file_name.starts_with(".write-") {
                fs::remove_file(entry.path())?;
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
            store.total_bytes += raw.len() as u64;
            let reservation = if unresolved(&record) { reserve(&record.payload, limits).max(raw.len() as u64) } else { raw.len() as u64 };
            store.reserved_bytes += reservation;
            store.reservations.insert(file_name.clone(), reservation);
            store.sizes.insert(file_name, raw.len() as u64);
            if store.total_bytes > limits.max_total_bytes {
                bail!("verifier state exceeds storage bound");
            }
            records.push(record);
        }
        File::open(dir)?.sync_all()?;
        Ok((store, records))
    }
    pub fn save(&mut self, record: &Record) -> Result<()> {
        let file_name = name(&record.job_id, &record.attempt);
        let raw = serde_json::to_vec(record)?;
        let old_size = *self.sizes.get(&file_name).unwrap_or(&0);
        let reservation = if unresolved(record) { reserve(&record.payload, self.limits).max(raw.len() as u64) } else { raw.len() as u64 };
        let old_reservation = *self.reservations.get(&file_name).unwrap_or(&0);
        if raw.len() as u64 > self.limits.max_record_bytes
            || self.total_bytes - old_size + raw.len() as u64 > self.limits.max_total_bytes
            || old_size == 0 && (self.sizes.len() >= self.limits.max_records || self.reserved_bytes() + reservation > self.limits.max_total_bytes)
            || old_size > 0 && reservation > old_reservation && self.reserved_bytes() - old_reservation + reservation > self.limits.max_total_bytes
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
        self.total_bytes = self.total_bytes - old_size + raw.len() as u64;
        self.reserved_bytes = self.reserved_bytes - old_reservation + reservation;
        self.reservations.insert(file_name.clone(), reservation);
        self.sizes.insert(file_name, raw.len() as u64);
        Ok(())
    }
    fn reserved_bytes(&self) -> u64 { self.reserved_bytes }
    /// Whether a new session with this payload can be registered: a record
    /// slot and its reservation are free.
    pub fn can_reserve(&self, payload: &Value) -> bool {
        self.sizes.len() < self.limits.max_records && self.reserved_bytes.saturating_add(reserve(payload, self.limits)) <= self.limits.max_total_bytes
    }
    pub fn capacity(&self) -> Capacity {
        let reserved_bytes = self.reserved_bytes();
        Capacity { limits: self.limits, records: self.sizes.len(), bytes: self.total_bytes, reserved_bytes,
            can_register: self.sizes.len() < self.limits.max_records && reserved_bytes.saturating_add(self.limits.max_record_bytes) <= self.limits.max_total_bytes }
    }
    pub fn remove(&mut self, job: &str, attempt: &str) -> Result<()> {
        let file_name = name(job, attempt);
        fs::remove_file(self.dir.join(&file_name))?;
        File::open(&self.dir)?.sync_all()?;
        self.total_bytes -= self.sizes.remove(&file_name).unwrap_or(0);
        self.reserved_bytes -= self.reservations.remove(&file_name).unwrap_or(0);
        Ok(())
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
    #[test]
    fn reservations_guarantee_result_space_and_survive_restart() {
        let dir = Temp::new();
        let limits = Limits { max_records: 8, max_record_bytes: 1 << 20, max_total_bytes: 2 << 20 };
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
    #[test]
    fn web_receipts_reserve_space_only_while_a_hop_can_still_run() {
        let dir = Temp::new();
        let limits = Limits { max_records: 8, max_record_bytes: 1 << 20, max_total_bytes: 4 << 20 };
        let (mut store, _) = Store::open_with_limits(&dir.0, limits).unwrap();
        let mut r = record();
        r.payload = serde_json::json!({"type":"web.fetch"});
        let web = |remaining: u64, complete: bool, rejections: serde_json::Value| serde_json::json!({"status":"web_read","remaining_sessions":remaining,"complete":complete,"next_url":null,"hops":[],"rejections":rejections});
        for (status, reserved) in [
            (web(6, false, serde_json::json!([])), true),
            (web(0, false, serde_json::json!([])), false),
            (web(3, true, serde_json::json!([])), false),
            (web(5, false, serde_json::json!(["tls_failed"])), false),
        ] {
            r.status = status;
            assert_eq!(unresolved(&r), reserved, "{}", r.status);
            store.save(&r).unwrap();
            assert_eq!(store.capacity().reserved_bytes == limits.max_record_bytes, reserved);
        }
        // Expiry releases the reservation whatever the status says.
        r.status = web(6, false, serde_json::json!([]));
        r.expires_ms = 1;
        assert!(!unresolved(&r));
        r.in_flight = 1;
        assert!(unresolved(&r));
    }
    #[test]
    fn web_receipts_reserve_their_bound_and_keep_a_short_retention() {
        let dir = Temp::new();
        let limits = Limits { max_records: 16, max_record_bytes: 64 << 20, max_total_bytes: 64 << 20 };
        let (mut store, _) = Store::open_with_limits(&dir.0, limits).unwrap();
        let payload = serde_json::json!({"type":"web.fetch","url":"https://example.com/","max_redirects":5,"max_response_bytes":10 << 20});
        let bound = web_receipt_bound(10 << 20, 5);
        assert!(bound > 10 << 20 && bound < 16 << 20);
        let mut r = record();
        r.payload = payload.clone();
        r.status = serde_json::json!({"status":"web_read","remaining_sessions":6,"complete":false,"next_url":null,"hops":[],"rejections":[]});
        assert!(store.can_reserve(&payload));
        store.save(&r).unwrap();
        assert_eq!(store.capacity().reserved_bytes, bound);
        // Codex and X still reserve the record limit, which no longer fits.
        assert!(!store.can_reserve(&record().payload) && store.can_reserve(&payload));
        // A web payload without its bounds reserves the record limit.
        assert_eq!(reserve(&serde_json::json!({"type":"web.fetch"}), limits), limits.max_record_bytes);
        assert_eq!(retention_ms(&payload), WEB_RETENTION_MS);
        assert_eq!(retention_ms(&record().payload), RETENTION_MS);
        drop(store);
        let (store, _) = Store::open_with_limits(&dir.0, limits).unwrap();
        assert_eq!(store.capacity().reserved_bytes, bound);
    }
    #[test]
    fn invalid_capacity_limits_fail_closed() {
        for limits in [Limits { max_records: 0, ..Limits::default() }, Limits { max_record_bytes: 1, ..Limits::default() }, Limits { max_total_bytes: 1, ..Limits::default() }] {
            let dir = Temp::new(); assert!(Store::open_with_limits(&dir.0, limits).is_err());
        }
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
