//! The supervised node's stderr, kept on this device: `node.log` in a private
//! directory (`~/Library/Logs/Scarlett Node` on macOS,
//! `%LOCALAPPDATA%\Scarlett Node\logs` on Windows), at most three files of
//! about 5 MiB: `node.log`, `node.log.1` and `node.log.2`.
//!
//! The node writes to the file itself, opened for appending. A pipe read by
//! the app would break when the app exits first, and a Go program writing to
//! a broken stderr pipe dies of SIGPIPE, which would cut short the drain that
//! the closed owner pipe asks for. The app rotates by copying the full file
//! to `node.log.1` and emptying it; the node's appends then continue at the
//! new end. Lines written during that copy can be lost.
use std::{
    fs::{File, OpenOptions},
    io,
    path::{Path, PathBuf},
    time::Duration,
};

pub const FILE: &str = "node.log";
/// The app's folder in the platform's log location.
const FOLDER: &str = "Scarlett Node";
/// A log is rotated once it reaches this size.
pub const LIMIT: u64 = 5 * 1024 * 1024;
/// `node.log` and the two before it.
const FILES: u32 = 3;
/// How often the size is checked while a node writes to it.
const CHECK_EVERY: Duration = Duration::from_secs(10);

/// The log directory under the platform's base: the home directory on
/// macOS, the local application data directory elsewhere.
pub fn dir(base: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        base.join("Library").join("Logs").join(FOLDER)
    } else {
        base.join(FOLDER).join("logs")
    }
}

/// Opens the log for a new node's stderr. The directory is created privately
/// if needed (0700 on Unix; on Windows the node helper's current-user/SYSTEM
/// ACL, which the file inherits), and a full log is rotated first.
pub fn open(dir: &Path, helper: &Path) -> io::Result<File> {
    private_dir(dir, helper)?;
    // A failed rotation still leaves an appendable log.
    let _ = rotate_if_full(dir, LIMIT);
    let file = options().create(true).append(true).open(dir.join(FILE))?;
    check(&file)?;
    Ok(file)
}

/// Rotates once `node.log` reaches `limit`: `node.log.1` becomes
/// `node.log.2`, dropping the oldest, a copy of `node.log` becomes
/// `node.log.1`, and `node.log` is emptied, even when the copy failed, so
/// the size bound holds.
pub fn rotate_if_full(dir: &Path, limit: u64) -> io::Result<bool> {
    let current = dir.join(FILE);
    let mut source = match options().read(true).open(&current) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    check(&source)?;
    if source.metadata()?.len() < limit {
        return Ok(false);
    }
    let shifted = (1..FILES - 1).rev().try_for_each(|n| {
        match std::fs::rename(archive(dir, n), archive(dir, n + 1)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    });
    let copied = shifted.and_then(|()| {
        let mut copy = options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(archive(dir, 1))?;
        check(&copy)?;
        io::copy(&mut source, &mut copy).map(drop)
    });
    let emptied = options().write(true).open(&current).and_then(|file| {
        check(&file)?;
        file.set_len(0)
    });
    copied.and(emptied).map(|()| true)
}

/// Keeps the log bounded while a node writes to it; aborted when it stops.
pub async fn keep_bounded(dir: PathBuf) {
    let mut tick = tokio::time::interval(CHECK_EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let _ = rotate_if_full(&dir, LIMIT);
    }
}

fn archive(dir: &Path, n: u32) -> PathBuf {
    dir.join(format!("{FILE}.{n}"))
}

fn private_dir(dir: &Path, helper: &Path) -> io::Result<()> {
    // The leaf is checked or created privately below; Unix creates only it,
    // so make sure its parent exists (~/Library/Logs normally does).
    #[cfg(unix)]
    if let Some(parent) = dir.parent() {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    crate::node::private_dir_with_helper(dir, helper)
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "private log directory"))
}

/// Never follows a link at a log file's own name.
fn options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT: open a link itself, which check refuses.
        options.custom_flags(0x0020_0000);
    }
    options
}

/// A regular file of the current user, private on Unix.
fn check(file: &File) -> io::Result<()> {
    let meta = file.metadata()?;
    let refused = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "log is not a private regular file",
        )
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } {
            return Err(refused());
        }
        if meta.mode() & 0o077 != 0 {
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // FILE_ATTRIBUTE_REPARSE_POINT
        if !meta.is_file() || meta.file_attributes() & 0x400 != 0 {
            return Err(refused());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn read(path: &Path) -> String {
        let mut text = String::new();
        File::open(path).unwrap().read_to_string(&mut text).unwrap();
        text
    }

    #[test]
    fn log_lives_in_the_platform_log_location() {
        let base = Path::new("/base");
        if cfg!(target_os = "macos") {
            assert_eq!(dir(base), base.join("Library/Logs/Scarlett Node"));
        } else {
            assert_eq!(dir(base), base.join("Scarlett Node").join("logs"));
        }
    }

    #[test]
    fn rotation_keeps_three_bounded_files_while_the_node_appends() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path();
        // The node's own handle, as passed to it for stderr.
        let mut node = options()
            .create(true)
            .append(true)
            .open(dir.join(FILE))
            .unwrap();
        assert!(!rotate_if_full(dir, 8).unwrap());
        for round in ["first", "second", "third"] {
            node.write_all(format!("{round} heartbeat line\n").as_bytes())
                .unwrap();
            assert!(rotate_if_full(dir, 8).unwrap(), "{round}");
            assert_eq!(read(&dir.join(FILE)), "");
        }
        // The oldest round is gone; the next two are kept in order.
        assert_eq!(read(&archive(dir, 1)), "third heartbeat line\n");
        assert_eq!(read(&archive(dir, 2)), "second heartbeat line\n");
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, ["node.log", "node.log.1", "node.log.2"]);
        // After emptying, the node's appends start at the new end rather
        // than leaving a hole of zeros where the old lines were.
        node.write_all(b"after\n").unwrap();
        assert_eq!(read(&dir.join(FILE)), "after\n");
        assert!(!rotate_if_full(dir, 8).unwrap());
        assert!(!rotate_if_full(&dir.join("absent"), 8).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn log_is_private_and_never_follows_a_link() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let logs = temp.path().join("Logs").join("Scarlett Node");
        let helper = temp.path().join("unused-helper");
        let mut file = open(&logs, &helper).unwrap();
        file.write_all(b"line\n").unwrap();
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&logs), 0o700);
        assert_eq!(mode(&logs.join(FILE)), 0o600);
        // Reopening appends, and tightens a file that was made readable.
        std::fs::set_permissions(logs.join(FILE), std::fs::Permissions::from_mode(0o644)).unwrap();
        open(&logs, &helper).unwrap().write_all(b"again\n").unwrap();
        assert_eq!(read(&logs.join(FILE)), "line\nagain\n");
        assert_eq!(mode(&logs.join(FILE)), 0o600);
        // A full log is rotated before a new node gets it.
        std::fs::write(logs.join(FILE), vec![b'x'; LIMIT as usize]).unwrap();
        open(&logs, &helper).unwrap();
        assert_eq!(std::fs::metadata(logs.join(FILE)).unwrap().len(), 0);
        assert_eq!(std::fs::metadata(archive(&logs, 1)).unwrap().len(), LIMIT);
        assert_eq!(mode(&archive(&logs, 1)), 0o600);
        // A link at the log's name, or a shared directory, is refused.
        std::fs::remove_file(logs.join(FILE)).unwrap();
        std::os::unix::fs::symlink(temp.path().join("elsewhere"), logs.join(FILE)).unwrap();
        assert!(open(&logs, &helper).is_err());
        assert!(rotate_if_full(&logs, 0).is_err());
        assert!(!temp.path().join("elsewhere").exists());
        let shared = temp.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(open(&shared, &helper).is_err());
    }
}
