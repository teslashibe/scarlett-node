//! Page body files.
//!
//! The final hop's entity is streamed to `<name>.body.partial` beside the
//! receipts by a writer on the blocking pool, so a session's async task
//! never touches the file system. Once the response is complete the file is
//! flushed and fsynced, renamed to `<name>.body` and the directory fsynced,
//! all before the receipt that names it is committed. A body that never
//! reaches its receipt is removed: `Sink` removes its partial file when
//! dropped unfinished, and `Stored` removes the final file when dropped
//! uncommitted. A crash leaves at most an orphan file, which the store
//! deletes when it opens.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};
use tokio::{sync::mpsc, task::JoinHandle};

/// Bytes handed to the writer at a time, and how many may wait for it.
const CHUNK: usize = 64 << 10;
const QUEUE: usize = 16;
/// The writer's buffer.
const BUFFER: usize = 1 << 20;

/// The suffix of a body file's final name.
pub const SUFFIX: &str = ".body";
/// The suffix of a body file still being written.
pub const PARTIAL_SUFFIX: &str = ".body.partial";

/// The partial name of a body file.
pub fn partial_path(body: &Path) -> PathBuf {
    let mut name = body.as_os_str().to_owned();
    name.push(".partial");
    PathBuf::from(name)
}

#[cfg(test)]
pub(crate) static SLOW_SYNC: std::sync::Mutex<Vec<(PathBuf, std::time::Duration)>> = std::sync::Mutex::new(Vec::new());

/// fsync, slowed for tests that register the file's directory.
fn sync(file: &File, _path: &Path) -> io::Result<()> {
    #[cfg(test)]
    {
        let delay = SLOW_SYNC.lock().unwrap().iter().find(|(dir, _)| _path.starts_with(dir)).map(|(_, delay)| *delay);
        if let Some(delay) = delay {
            std::thread::sleep(delay);
        }
    }
    file.sync_all()
}

fn sync_dir(path: &Path) -> io::Result<()> {
    let dir = path.parent().ok_or_else(|| io::Error::other("body file has no directory"))?;
    sync(&File::open(dir)?, path)
}

fn remove(path: &Path) {
    if let Err(e) = fs::remove_file(path)
        && e.kind() != io::ErrorKind::NotFound
    {
        eprintln!("verifier: could not remove a page body file: {}", e.kind());
    }
}

/// Removes `paths` on the blocking pool once `writer` (if any) has let go
/// of them; inline when there is no runtime.
fn remove_later(writer: Option<JoinHandle<io::Result<u64>>>, paths: Vec<PathBuf>) {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            handle.spawn(async move {
                if let Some(writer) = writer {
                    let _ = writer.await;
                }
                let _ = tokio::task::spawn_blocking(move || paths.iter().for_each(|p| remove(p))).await;
            });
        }
        Err(_) => paths.iter().for_each(|p| remove(p)),
    }
}

/// The writer of one body file.
pub struct Sink {
    path: PathBuf,
    tx: Option<mpsc::Sender<Vec<u8>>>,
    writer: Option<JoinHandle<io::Result<u64>>>,
    pending: Vec<u8>,
    finished: bool,
}

impl Sink {
    /// Starts a writer for the body file `path` (its final `.body` name).
    /// The file is created private and exclusive under its partial name; a
    /// partial file left from before is replaced.
    pub fn open(path: PathBuf) -> Self {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(QUEUE);
        let partial = partial_path(&path);
        let writer = tokio::task::spawn_blocking(move || -> io::Result<u64> {
            match fs::remove_file(&partial) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
                _ => {}
            }
            let file = OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&partial)?;
            let mut out = BufWriter::with_capacity(BUFFER, file);
            let mut written = 0u64;
            while let Some(chunk) = rx.blocking_recv() {
                out.write_all(&chunk)?;
                written += chunk.len() as u64;
            }
            let file = out.into_inner().map_err(io::IntoInnerError::into_error)?;
            sync(&file, &partial)?;
            Ok(written)
        });
        Self { path, tx: Some(tx), writer: Some(writer), pending: Vec::with_capacity(CHUNK), finished: false }
    }

    /// Appends entity bytes. Waits when the writer is 16 chunks behind.
    pub async fn write(&mut self, mut data: &[u8]) -> Result<()> {
        while !data.is_empty() {
            let take = (CHUNK - self.pending.len()).min(data.len());
            self.pending.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.pending.len() == CHUNK {
                self.send().await?;
            }
        }
        Ok(())
    }

    async fn send(&mut self) -> Result<()> {
        let chunk = std::mem::replace(&mut self.pending, Vec::with_capacity(CHUNK));
        let sent = match self.tx.as_ref() {
            Some(tx) => tx.send(chunk).await.is_ok(),
            None => false,
        };
        if sent { Ok(()) } else { Err(self.failure().await) }
    }

    /// Why the writer stopped.
    async fn failure(&mut self) -> anyhow::Error {
        match self.writer.take() {
            Some(writer) => match writer.await {
                Ok(Err(e)) => anyhow!("writing the page body failed: {}", e.kind()),
                _ => anyhow!("the page body writer stopped"),
            },
            None => anyhow!("the page body writer stopped"),
        }
    }

    /// Closes the file with exactly `bytes` written: flushed, fsynced,
    /// renamed to its final name and the directory fsynced. The result must
    /// be committed once its receipt is.
    pub async fn finish(mut self, bytes: u64) -> Result<Stored> {
        if !self.pending.is_empty() {
            self.send().await?;
        }
        drop(self.tx.take());
        let writer = self.writer.take().context("the page body writer stopped")?;
        let written = match writer.await {
            Ok(Ok(written)) => written,
            Ok(Err(e)) => bail!("writing the page body failed: {}", e.kind()),
            Err(_) => bail!("the page body writer stopped"),
        };
        if written != bytes {
            bail!("the page body file holds {written} bytes, not {bytes}");
        }
        self.finished = true;
        let (path, partial) = (self.path.clone(), partial_path(&self.path));
        let renamed = tokio::task::spawn_blocking({
            let (path, partial) = (path.clone(), partial.clone());
            move || -> io::Result<()> {
                fs::rename(&partial, &path)?;
                sync_dir(&path)
            }
        })
        .await;
        match renamed {
            Ok(Ok(())) => Ok(Stored { path: Some(path) }),
            failed => {
                remove_later(None, vec![partial, path]);
                match failed {
                    Ok(Err(e)) => bail!("storing the page body failed: {}", e.kind()),
                    _ => bail!("storing the page body failed"),
                }
            }
        }
    }
}

impl Drop for Sink {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        // Unfinished: the partial file goes once the writer has let go of it.
        drop(self.tx.take());
        remove_later(self.writer.take(), vec![partial_path(&self.path)]);
    }
}

/// A body file under its final name, before its receipt is committed.
/// Dropped without `commit`, the file is removed.
pub struct Stored {
    path: Option<PathBuf>,
}

impl Stored {
    /// The receipt that names this file is committed; keep it.
    pub fn commit(mut self) {
        self.path = None;
    }
}

impl Drop for Stored {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            remove_later(None, vec![path]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("scarlett-body-{}", rand::random::<u128>()));
            std::fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    async fn settle() {
        // Removal runs on the blocking pool after the writer ends.
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn a_body_is_written_private_renamed_and_kept_once_committed() {
        let dir = Temp::new();
        let path = dir.0.join("abc.body");
        let mut sink = Sink::open(path.clone());
        let data: Vec<u8> = (0..(3 * CHUNK + 17)).map(|i| (i % 251) as u8).collect();
        for piece in data.chunks(5000) {
            sink.write(piece).await.unwrap();
        }
        let stored = sink.finish(data.len() as u64).await.unwrap();
        assert!(!partial_path(&path).exists());
        assert_eq!(fs::read(&path).unwrap(), data);
        let meta = fs::metadata(&path).unwrap();
        assert_eq!((meta.mode() & 0o777, meta.uid()), (0o600, unsafe { libc::geteuid() }));
        stored.commit();
        settle().await;
        assert!(path.exists());
        // An empty body is a file too.
        let empty = dir.0.join("empty.body");
        Sink::open(empty.clone()).finish(0).await.unwrap().commit();
        assert_eq!(fs::read(&empty).unwrap(), b"");
    }

    #[tokio::test]
    async fn an_unfinished_or_uncommitted_body_leaves_no_file() {
        let dir = Temp::new();
        let path = dir.0.join("gone.body");
        let mut sink = Sink::open(path.clone());
        sink.write(&[7; 200_000]).await.unwrap();
        drop(sink);
        settle().await;
        assert!(!partial_path(&path).exists() && !path.exists());
        // A count that does not match what was written is refused.
        let mut sink = Sink::open(path.clone());
        sink.write(b"four").await.unwrap();
        assert!(sink.finish(5).await.is_err());
        settle().await;
        assert!(!partial_path(&path).exists() && !path.exists());
        // Renamed but never committed.
        let mut sink = Sink::open(path.clone());
        sink.write(b"page").await.unwrap();
        drop(sink.finish(4).await.unwrap());
        settle().await;
        assert!(!path.exists());
        // A stale partial from a crash is replaced, never appended to.
        fs::write(partial_path(&path), b"stale").unwrap();
        fs::set_permissions(partial_path(&path), fs::Permissions::from_mode(0o644)).unwrap();
        let mut sink = Sink::open(path.clone());
        sink.write(b"fresh").await.unwrap();
        sink.finish(5).await.unwrap().commit();
        assert_eq!(fs::read(&path).unwrap(), b"fresh");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    }

    #[tokio::test]
    async fn a_writer_that_cannot_create_its_file_fails_the_body() {
        let dir = Temp::new();
        let mut sink = Sink::open(dir.0.join("missing-dir").join("x.body"));
        let mut failed = false;
        for _ in 0..64 {
            if sink.write(&[0; CHUNK]).await.is_err() {
                failed = true;
                break;
            }
        }
        assert!(failed || sink.finish(64 * CHUNK as u64).await.is_err());
    }
}
