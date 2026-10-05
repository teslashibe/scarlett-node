//! Subscription authentication stays in the bundled CLI's private config store.
//! Neither provider credentials nor identity JSON cross the native UI boundary.
use crate::node::{Error, Result, private_dir_with_helper, regular};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{
    io::AsyncReadExt,
    process::{Child, Command},
    sync::Mutex,
};

#[derive(Clone, Default, Serialize)]
pub struct Snapshot {
    pub available: bool,
    pub connected: bool,
    pub pending: bool,
    pub error: Option<Error>,
}
struct Login {
    child: Child,
    started: Instant,
}
pub struct ClaudeAuth {
    state: PathBuf,
    helper: PathBuf,
    resources: PathBuf,
    login: Mutex<Option<Login>>,
    error: Mutex<Option<Error>>,
    verified: std::sync::Mutex<Option<(u64, std::time::SystemTime, std::time::SystemTime)>>,
}
impl ClaudeAuth {
    pub fn new(state: PathBuf, helper: PathBuf, resources: PathBuf) -> Self {
        Self {
            state,
            helper,
            resources,
            login: Mutex::new(None),
            error: Mutex::new(None),
            verified: std::sync::Mutex::new(None),
        }
    }
    fn config(&self) -> PathBuf {
        self.state.join("claude")
    }
    fn blocked(&self) -> PathBuf {
        self.state.join("claude-disconnected")
    }
    fn executable(&self) -> PathBuf {
        self.resources.join("claude").join(if cfg!(windows) {
            "claude.exe"
        } else {
            "claude"
        })
    }
    fn prepare(&self) -> Result<()> {
        private_dir_with_helper(&self.state, &self.helper)?;
        for name in ["claude", "tmp"] {
            private_dir_with_helper(&self.state.join(name), &self.helper)?;
        }
        Ok(())
    }
    fn block(&self) -> Result<()> {
        self.prepare()?;
        private_dir_with_helper(&self.blocked(), &self.helper)
    }
    fn admitted(&self) -> bool {
        matches!(std::fs::symlink_metadata(self.blocked()), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
    }
    // COMPONENTS is produced from integrity-pinned provider archives by the
    // complete-bundle gate. It is part of the signed app, not an update feed.
    pub fn available(&self) -> bool {
        let exe = self.executable();
        if !regular(&exe) || !regular(&self.resources.join("COMPONENTS.json")) {
            return false;
        }
        let Ok(meta) = std::fs::metadata(&exe) else {
            return false;
        };
        let Ok(stamp) = meta.modified() else {
            return false;
        };
        let Ok(mut checked) = self.verified.lock() else {
            return false;
        };
        let Ok(manifest_stamp) =
            std::fs::metadata(self.resources.join("COMPONENTS.json")).and_then(|m| m.modified())
        else {
            return false;
        };
        if *checked == Some((meta.len(), stamp, manifest_stamp)) {
            return true;
        }
        let valid = (|| -> Option<()> {
            let manifest = std::fs::File::open(self.resources.join("COMPONENTS.json")).ok()?;
            let mut raw = Vec::new();
            manifest.take(1024 * 1024 + 1).read_to_end(&mut raw).ok()?;
            if raw.len() > 1024 * 1024 {
                return None;
            }
            let manifest: Value = serde_json::from_slice(&raw).ok()?;
            let target = if cfg!(windows) {
                "x86_64-pc-windows-msvc"
            } else if cfg!(target_arch = "aarch64") {
                "aarch64-apple-darwin"
            } else {
                "x86_64-apple-darwin"
            };
            if manifest.get("target")?.as_str()? != target {
                return None;
            }
            if manifest.get("schemaVersion")?.as_u64()? != 1
                || manifest.get("claudeVersion")?.as_str()? != "2.1.286"
            {
                return None;
            }
            let path = if cfg!(windows) {
                "claude/claude.exe"
            } else {
                "claude/claude"
            };
            let entries: Vec<_> = manifest
                .get("files")?
                .as_array()?
                .iter()
                .filter(|v| v.get("path").and_then(Value::as_str) == Some(path))
                .collect();
            if entries.len() != 1
                || entries[0].get("bytes")?.as_u64()? != meta.len()
                || meta.len() > 512 * 1024 * 1024
            {
                return None;
            }
            let mut file = std::fs::File::open(exe).ok()?;
            let mut hash = Sha256::new();
            let mut buffer = [0u8; 65536];
            let mut read = 0_u64;
            loop {
                let n = file.read(&mut buffer).ok()?;
                if n == 0 {
                    break;
                }
                read += n as u64;
                if read > meta.len() {
                    return None;
                }
                hash.update(&buffer[..n]);
            }
            if format!("{:x}", hash.finalize()) != entries[0].get("sha256")?.as_str()? {
                return None;
            }
            Some(())
        })()
        .is_some();
        *checked = valid.then_some((meta.len(), stamp, manifest_stamp));
        valid
    }
    /// Whether this process has verified the bundled runtime's integrity.
    #[cfg(test)]
    pub(crate) fn integrity_checked(&self) -> bool {
        self.verified.lock().is_ok_and(|checked| checked.is_some())
    }
    fn command(&self, args: &[&str]) -> Result<Command> {
        if !self.available() {
            return Err(Error::ClaudeUnavailable);
        }
        self.prepare()?;
        let mut command = Command::new(self.executable());
        command
            .args(args)
            .env_clear()
            .current_dir(&self.state)
            .env("HOME", &self.state)
            .env("USERPROFILE", &self.state)
            .env("CLAUDE_CONFIG_DIR", self.config())
            .env("TMPDIR", self.state.join("tmp"))
            .env("TMP", self.state.join("tmp"))
            .env("TEMP", self.state.join("tmp"))
            .env("DISABLE_AUTOUPDATER", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        for name in ["SystemRoot", "WINDIR", "LANG"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        #[cfg(unix)]
        command.process_group(0);
        #[cfg(windows)]
        command.creation_flags(0x08000000);
        Ok(command)
    }
    async fn subscription(&self) -> bool {
        let Ok(mut command) = self.command(&["auth", "status", "--json"]) else {
            return false;
        };
        command.stdout(Stdio::piped());
        matches!(
            tokio::time::timeout(Duration::from_secs(5), async {
                let mut child = command.spawn().ok()?;
                let stdout = child.stdout.take()?;
                let mut output = Vec::new();
                stdout.take(8193).read_to_end(&mut output).await.ok()?;
                let success = child.wait().await.ok()?.success();
                Some(success && subscription_status(&output, &self.config()))
            })
            .await,
            Ok(Some(true))
        )
    }
    pub async fn connected(&self) -> bool {
        self.admitted() && self.subscription().await
    }
    pub async fn connect(&self) -> Result<()> {
        let mut pending = self.login.lock().await;
        if pending.is_some() {
            return Err(Error::LoginBusy);
        }
        self.block()?;
        let child = self
            .command(&["auth", "login", "--claudeai"])?
            .spawn()
            .map_err(|_| Error::ClaudeLoginFailed)?;
        *pending = Some(Login {
            child,
            started: Instant::now(),
        });
        *self.error.lock().await = None;
        Ok(())
    }
    pub async fn finish(&self) {
        let mut pending = self.login.lock().await;
        let Some(login) = pending.as_mut() else {
            return;
        };
        if login.started.elapsed() >= Duration::from_secs(600) {
            let _ = terminate(&mut login.child).await;
            *pending = None;
            *self.error.lock().await = Some(Error::CommandTimeout);
            return;
        }
        match login.child.try_wait() {
            Ok(None) => return,
            Ok(Some(exit))
                if exit.success()
                    && self.subscription().await
                    && std::fs::remove_dir(self.blocked()).is_ok() =>
            {
                *self.error.lock().await = None;
            }
            _ => {
                *self.error.lock().await = Some(Error::ClaudeLoginFailed);
            }
        }
        *pending = None;
    }
    pub async fn cancel(&self) -> Result<()> {
        let mut pending = self.login.lock().await;
        // Serialize the durable block with completion's admission decision.
        // A concurrent status poll must not clear cancellation's block.
        self.block()?;
        if let Some(mut login) = pending.take() {
            terminate(&mut login.child).await?;
        }
        *self.error.lock().await = Some(Error::ClaudeLoginFailed);
        Ok(())
    }
    pub async fn disconnect(&self) -> Result<()> {
        self.cancel().await?;
        let mut command = self.command(&["auth", "logout"])?;
        let success = tokio::time::timeout(Duration::from_secs(10), async {
            let mut child = command.spawn().map_err(|_| Error::ClaudeLoginFailed)?;
            child.wait().await.map_err(|_| Error::ClaudeLoginFailed)
        })
        .await
        .map_err(|_| Error::CommandTimeout)??;
        if !success.success() || self.subscription().await {
            return Err(Error::ClaudeLoginFailed);
        }
        *self.error.lock().await = None;
        Ok(())
    }
    pub async fn snapshot(&self) -> Snapshot {
        self.finish().await;
        let pending = self.login.lock().await.is_some();
        Snapshot {
            available: self.available(),
            connected: !pending && self.connected().await,
            pending,
            error: self.error.lock().await.clone(),
        }
    }
}
async fn terminate(child: &mut Child) -> Result<()> {
    if child
        .try_wait()
        .map_err(|_| Error::CommandFailed)?
        .is_some()
    {
        return Ok(());
    }
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        unsafe {
            libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
        }
    }
    child.kill().await.map_err(|_| Error::CommandFailed)?;
    Ok(())
}
fn subscription_status(raw: &[u8], expected_config: &Path) -> bool {
    if raw.len() > 8192 {
        return false;
    }
    let Ok(v) = serde_json::from_slice::<Value>(raw) else {
        return false;
    };
    let Some(expected) = expected_config
        .to_str()
        .filter(|_| expected_config.is_absolute())
    else {
        return false;
    };
    v.get("configDirectory").and_then(Value::as_str) == Some(expected)
        && v.get("loggedIn").and_then(Value::as_bool) == Some(true)
        && v.get("authMethod").and_then(Value::as_str) == Some("claude.ai")
        && v.get("apiProvider").and_then(Value::as_str) == Some("firstParty")
        && matches!(
            v.get("subscriptionType").and_then(Value::as_str),
            Some("pro" | "max" | "team" | "enterprise")
        )
        && v.get("expired").is_none_or(|v| v.as_bool() == Some(false))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn status_projects_only_known_subscription_access_and_never_identity() {
        let good = br#"{"configDirectory":"/private/scarlett/claude","loggedIn":true,"authMethod":"claude.ai","apiProvider":"firstParty","subscriptionType":"max","email":"private@example.invalid","orgId":"private-org"}"#;
        let expected = if cfg!(windows) {
            Path::new(r"C:\Scarlett\claude")
        } else {
            Path::new("/private/scarlett/claude")
        };
        let mut value: Value = serde_json::from_slice(good).unwrap();
        value["configDirectory"] = Value::String(expected.to_str().unwrap().into());
        let good = serde_json::to_vec(&value).unwrap();
        assert!(subscription_status(&good, expected));
        for raw in [
            "{}",
            "not-json",
            r#"{"loggedIn":true,"authMethod":"api_key","apiProvider":"firstParty","subscriptionType":"max"}"#,
            r#"{"loggedIn":true,"authMethod":"claude.ai","apiProvider":"unknown","subscriptionType":"max"}"#,
            r#"{"loggedIn":true,"authMethod":"claude.ai","apiProvider":"firstParty","subscriptionType":"unknown"}"#,
            r#"{"loggedIn":false,"authMethod":"claude.ai","apiProvider":"firstParty","subscriptionType":"max"}"#,
            r#"{"loggedIn":true,"authMethod":"claude.ai","apiProvider":"firstParty","subscriptionType":"max","expired":true}"#,
            r#"{"loggedIn":true,"authMethod":"claude.ai","apiProvider":"firstParty","subscriptionType":"max","expired":"false"}"#,
        ] {
            let mut value: Value = serde_json::from_str(raw).unwrap_or(Value::Null);
            if let Some(object) = value.as_object_mut() {
                object.insert(
                    "configDirectory".into(),
                    Value::String(expected.to_str().unwrap().into()),
                );
            }
            assert!(
                !subscription_status(&serde_json::to_vec(&value).unwrap(), expected),
                "accepted {raw}"
            );
        }
        assert!(!subscription_status(&vec![b' '; 8193], expected));
        let mut mismatched: Value = serde_json::from_slice(&good).unwrap();
        mismatched["configDirectory"] = Value::String("/host/.claude".into());
        assert!(!subscription_status(
            &serde_json::to_vec(&mismatched).unwrap(),
            expected
        ));
        mismatched
            .as_object_mut()
            .unwrap()
            .remove("configDirectory");
        assert!(!subscription_status(
            &serde_json::to_vec(&mismatched).unwrap(),
            expected
        ));
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let invalid = Path::new(std::ffi::OsStr::from_bytes(b"/private/\xff/claude"));
            assert!(!subscription_status(br#"{"loggedIn":true,"authMethod":"claude.ai","apiProvider":"firstParty","subscriptionType":"max"}"#, invalid));
        }
        let safe = serde_json::to_string(&Snapshot {
            connected: true,
            ..Default::default()
        })
        .unwrap();
        assert!(!safe.contains("private") && !safe.contains("orgId") && !safe.contains("email"));
    }
    #[cfg(unix)]
    fn fixture() -> (tempfile::TempDir, ClaudeAuth) {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let resources = root.path().join("runtime");
        std::fs::create_dir_all(resources.join("claude")).unwrap();
        let exe = resources.join("claude/claude");
        // Synthetic CLI: all writes are disposable, identity output is never saved.
        let script = r#"#!/bin/sh
case "$2" in
login)
    if [ -e "$CLAUDE_CONFIG_DIR/hold" ]; then
        while [ -e "$CLAUDE_CONFIG_DIR/hold" ]; do /bin/sleep 0.05; done
    fi
    /usr/bin/touch "$CLAUDE_CONFIG_DIR/logged-in"
    ;;
status)
    if [ -e "$CLAUDE_CONFIG_DIR/malformed" ]; then echo 'malformed private identity'; exit 0; fi
    if [ -e "$CLAUDE_CONFIG_DIR/logged-in" ]; then
        echo "{\"configDirectory\":\"$CLAUDE_CONFIG_DIR\",\"loggedIn\":true,\"authMethod\":\"claude.ai\",\"apiProvider\":\"firstParty\",\"subscriptionType\":\"pro\",\"email\":\"private@example.invalid\"}"
    else echo '{"loggedIn":false}'; exit 1; fi
    ;;
logout)
    if [ -e "$CLAUDE_CONFIG_DIR/fail-logout" ]; then exit 1; fi
    /bin/rm -f "$CLAUDE_CONFIG_DIR/logged-in"
    ;;
*) exit 2 ;;
esac
"#;
        std::fs::write(&exe, script).unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let target = if cfg!(target_arch = "aarch64") {
            "aarch64-apple-darwin"
        } else {
            "x86_64-apple-darwin"
        };
        std::fs::write(resources.join("COMPONENTS.json"), serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"target":target,"claudeVersion":"2.1.286","files":[{"path":"claude/claude","bytes":script.len(),"sha256":format!("{:x}",Sha256::digest(script.as_bytes()))}]})).unwrap()).unwrap();
        let helper = root.path().join("scarlett-node");
        let auth = ClaudeAuth::new(root.path().join("local-api"), helper, resources);
        auth.prepare().unwrap();
        (root, auth)
    }
    #[cfg(unix)]
    #[test]
    fn fixed_runtime_manifest_and_process_environment_exclude_host_credentials() {
        let (_root, auth) = fixture();
        let command = auth.command(&["auth", "login", "--claudeai"]).unwrap();
        let command = command.as_std();
        assert_eq!(command.get_program(), auth.executable());
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["auth", "login", "--claudeai"]
        );
        let env = command
            .get_envs()
            .collect::<std::collections::HashMap<_, _>>();
        for key in [
            "PATH",
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_AUTH_TOKEN",
            "CLAUDE_CODE_OAUTH_TOKEN",
            "ANTHROPIC_PROFILE",
        ] {
            assert!(!env.contains_key(std::ffi::OsStr::new(key)));
        }
        assert_eq!(
            env.get(std::ffi::OsStr::new("CLAUDE_CONFIG_DIR")),
            Some(&Some(auth.config().as_os_str()))
        );
        assert_eq!(
            env.get(std::ffi::OsStr::new("HOME")),
            Some(&Some(auth.state.as_os_str()))
        );
        std::fs::write(auth.resources.join("COMPONENTS.json"), "{}").unwrap();
        assert!(!auth.available());
        assert!(matches!(
            auth.command(&["auth", "status", "--json"]),
            Err(Error::ClaudeUnavailable)
        ));
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn login_cancel_restart_and_failed_logout_never_reactivate_credentials() {
        let (_root, auth) = fixture();
        std::fs::write(auth.config().join("hold"), "").unwrap();
        auth.connect().await.unwrap();
        assert!(auth.snapshot().await.pending);
        assert_eq!(auth.connect().await, Err(Error::LoginBusy));
        auth.cancel().await.unwrap();
        assert!(!auth.connected().await);
        // Even a late provider write or restart cannot undo cancellation.
        std::fs::write(auth.config().join("logged-in"), "synthetic").unwrap();
        let restarted = ClaudeAuth::new(
            auth.state.clone(),
            auth.helper.clone(),
            auth.resources.clone(),
        );
        assert!(!restarted.connected().await);
        std::fs::remove_file(auth.config().join("hold")).unwrap();
        auth.connect().await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while auth.snapshot().await.pending {
            assert!(Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(auth.connected().await);
        let restored = ClaudeAuth::new(
            auth.state.clone(),
            auth.helper.clone(),
            auth.resources.clone(),
        );
        assert!(restored.connected().await);
        std::fs::write(auth.config().join("fail-logout"), "").unwrap();
        assert_eq!(auth.disconnect().await, Err(Error::ClaudeLoginFailed));
        assert!(!auth.connected().await);
        let restored = ClaudeAuth::new(
            auth.state.clone(),
            auth.helper.clone(),
            auth.resources.clone(),
        );
        assert!(!restored.connected().await);
        std::fs::remove_file(auth.config().join("fail-logout")).unwrap();
        auth.disconnect().await.unwrap();
        assert!(!auth.config().join("logged-in").exists());
        assert!(!auth.snapshot().await.connected);
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn concurrent_completion_and_cancellation_leave_admission_blocked() {
        let (_root, auth) = fixture();
        for _ in 0..8 {
            auth.connect().await.unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if auth
                    .login
                    .lock()
                    .await
                    .as_mut()
                    .unwrap()
                    .child
                    .try_wait()
                    .unwrap()
                    .is_some()
                {
                    break;
                }
                assert!(Instant::now() < deadline);
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let (_, cancelled) = tokio::join!(auth.finish(), auth.cancel());
            cancelled.unwrap();
            assert!(!auth.connected().await);
            assert!(auth.blocked().is_dir());
        }
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn malformed_cli_status_and_timeout_fail_closed() {
        let (_root, auth) = fixture();
        std::fs::write(auth.config().join("logged-in"), "synthetic").unwrap();
        std::fs::write(auth.config().join("malformed"), "").unwrap();
        assert!(!auth.connected().await);
        std::fs::remove_file(auth.config().join("malformed")).unwrap();
        std::fs::write(auth.config().join("hold"), "").unwrap();
        auth.connect().await.unwrap();
        auth.login.lock().await.as_mut().unwrap().started =
            Instant::now() - Duration::from_secs(601);
        auth.finish().await;
        let status = auth.snapshot().await;
        assert!(!status.pending && !status.connected);
        assert_eq!(status.error, Some(Error::CommandTimeout));
    }
}
