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
const MAX_RECORD_BYTES: u64 = 64 << 20;
const MAX_TOTAL_BYTES: u64 = 256 << 20;
pub const RETENTION_MS: u64 = 24 * 60 * 60 * 1000;

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
fn private_file(file: &File) -> Result<()> {
    let info = file.metadata()?;
    if !info.is_file() || info.uid() != unsafe { libc::geteuid() } || info.mode() & 0o077 != 0 || info.len() > MAX_RECORD_BYTES {
        bail!("invalid verifier state file");
    }
    Ok(())
}
fn read_private(path: &Path) -> Result<Vec<u8>> {
    let f = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    private_file(&f)?;
    let mut raw = Vec::new();
    f.take(MAX_RECORD_BYTES + 1).read_to_end(&mut raw)?;
    if raw.len() as u64 > MAX_RECORD_BYTES {
        bail!("verifier state too large");
    }
    Ok(raw)
}

pub struct Store {
    dir: PathBuf,
    _lock: File,
    sizes: HashMap<String, u64>,
}
impl Store {
    pub fn open(dir: &Path) -> Result<(Self, Vec<Record>)> {
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
        private_file(&lock)?;
        lock.try_lock().context("another verifier owns the state directory")?;
        let mut store = Self { dir: dir.to_owned(), _lock: lock, sizes: HashMap::new() };
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
            if records.len() >= MAX_RECORDS {
                bail!("verifier state has too many records");
            }
            let raw = read_private(&entry.path())?;
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
            store.sizes.insert(file_name, raw.len() as u64);
            if store.sizes.values().sum::<u64>() > MAX_TOTAL_BYTES {
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
        if raw.len() as u64 > MAX_RECORD_BYTES
            || self.sizes.values().sum::<u64>() - old_size + raw.len() as u64 > MAX_TOTAL_BYTES
            || old_size == 0 && self.sizes.len() >= MAX_RECORDS
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
        self.sizes.insert(file_name, raw.len() as u64);
        Ok(())
    }
    pub fn remove(&mut self, job: &str, attempt: &str) -> Result<()> {
        let file_name = name(job, attempt);
        fs::remove_file(self.dir.join(&file_name))?;
        File::open(&self.dir)?.sync_all()?;
        self.sizes.remove(&file_name);
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
            expires_ms: 1,
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
}
