//! App-owned loopback service. No inherited account profiles or renderer paths.
use crate::node::{Account, Error, Result, private_dir_with_helper, regular};
use serde::Serialize;
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    process::{Child, Command},
    sync::Mutex,
};

#[derive(Clone, Default, Serialize)]
pub struct Snapshot {
    pub available: bool,
    pub running: bool,
    pub ready: bool,
    pub base_url: Option<String>,
    pub claude_enabled: bool,
}
struct Running {
    child: Child,
    port: u16,
    claude_enabled: bool,
}
pub struct LocalApi {
    state: PathBuf,
    binary: PathBuf,
    helper: PathBuf,
    resources: PathBuf,
    node_state: PathBuf,
    running: Mutex<Option<Running>>,
}
impl LocalApi {
    pub fn new(node_state: &Path, binary: PathBuf, resources: PathBuf) -> Self {
        Self {
            state: node_state.join("local-api"),
            helper: binary
                .parent()
                .unwrap_or(Path::new("."))
                .join(if cfg!(windows) {
                    "scarlett-node.exe"
                } else {
                    "scarlett-node"
                }),
            binary,
            resources,
            node_state: node_state.into(),
            running: Mutex::new(None),
        }
    }
    fn prepare(&self) -> Result<()> {
        private_dir_with_helper(&self.node_state, &self.helper)?;
        private_dir_with_helper(&self.state, &self.helper)?;
        for name in ["codex", "claude", "claude-runs", "tmp"] {
            private_dir_with_helper(&self.state.join(name), &self.helper)?;
        }
        Ok(())
    }
    fn available(&self) -> bool {
        // Native storage and process checks run before a runtime becomes ready.
        regular(&self.binary)
            && regular(&self.helper)
            && regular(&self.resources.join("codex_profile.json"))
            && regular(&self.resources.join("codex_scaffold.json"))
    }
    pub fn key(&self) -> Result<String> {
        self.prepare()?;
        private_key(&self.state.join("bearer"), &self.helper)
    }
    fn command(&self, port: u16, accounts: &[Account], claude_key: &str) -> Result<Command> {
        if port < 1024
            || (!claude_key.is_empty()
                && (claude_key.len() > 512 || !claude_key.bytes().all(|b| (33..=126).contains(&b))))
        {
            return Err(Error::InvalidInput);
        }
        if !self.available() {
            return Err(Error::ApiUnavailable);
        }
        self.prepare()?;
        let key = self.key()?;
        let profile = self.resources.join("codex_profile.json");
        let scaffold = self.resources.join("codex_scaffold.json");
        let mut clients = Vec::new();
        for account in accounts.iter().filter(|a| a.service == "codex") {
            if !crate::node::valid_id(&account.id) || clients.len() >= 8 {
                return Err(Error::InvalidInput);
            }
            let home = self.node_state.join("codex-logins").join(&account.id);
            // Only this app's completed login profiles; never registry-provided paths.
            private_dir_with_helper(&home, &self.helper)?;
            if !regular(&home.join("auth.json")) {
                return Err(Error::LoginFailed);
            }
            clients.push(json!({"label": account.id, "codex_home": home, "auth_path": home.join("auth.json"), "profile_path": profile, "scaffold_path": scaffold}));
        }
        let mut cmd = Command::new(&self.helper);
        cmd.args(["desktop", "api", &port.to_string()])
            .env_clear()
            .current_dir(&self.state)
            .env("HOME", &self.state)
            .env("USERPROFILE", &self.state)
            .env("TMPDIR", self.state.join("tmp"))
            .env("TEMP", self.state.join("tmp"))
            .env("TMP", self.state.join("tmp"))
            .env("CODEX_HOME", self.state.join("codex"))
            .env("CODEX_AUTH_PATH", self.state.join("codex/auth.json"))
            .env(
                "CODEX_CLIENTS",
                if clients.is_empty() {
                    String::new()
                } else {
                    serde_json::to_string(&clients).map_err(|_| Error::InvalidInput)?
                },
            )
            .env("CODEX_PROFILE_PATH", profile)
            .env("CODEX_SCAFFOLD_PATH", scaffold)
            .env("CODEX_USAGE_HISTORY_PATH", self.state.join("usage.json"))
            .env(
                "CODEX_CLIENT_MAX_INFLIGHT",
                accounts
                    .iter()
                    .filter(|a| a.service == "codex")
                    .map(|a| a.concurrency)
                    .min()
                    .unwrap_or(1)
                    .clamp(1, 32)
                    .to_string(),
            )
            .env("GATEWAY_BEARER_SECRET", key)
            .env(
                "GATEWAY_PROVIDERS",
                if claude_key.is_empty() {
                    "codex"
                } else {
                    "codex,claude"
                },
            )
            .env("CLAUDE_CONFIG_DIR", self.state.join("claude"))
            .env("CLAUDE_RUN_DIR", self.state.join("claude-runs"))
            .env(
                "CLAUDE_EXECUTABLE",
                self.resources.join("claude").join(if cfg!(windows) {
                    "claude.exe"
                } else {
                    "claude"
                }),
            )
            .env("CLAUDE_BRIDGE_EXECUTABLE", &self.binary)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        for name in ["SystemRoot", "WINDIR", "LANG"] {
            if let Some(value) = std::env::var_os(name) {
                cmd.env(name, value);
            }
        }
        if !claude_key.is_empty() {
            if !regular(&self.resources.join("claude").join(if cfg!(windows) {
                "claude.exe"
            } else {
                "claude"
            })) {
                return Err(Error::ApiUnavailable);
            }
            cmd.env("ANTHROPIC_API_KEY", claude_key);
        }
        #[cfg(unix)]
        cmd.process_group(0);
        #[cfg(windows)]
        cmd.creation_flags(0x08000000);
        Ok(cmd)
    }
    pub async fn start(&self, port: u16, accounts: &[Account], claude_key: String) -> Result<()> {
        let mut running = self.running.lock().await;
        if let Some(run) = running.as_mut() {
            if run
                .child
                .try_wait()
                .map_err(|_| Error::CommandFailed)?
                .is_none()
            {
                return Err(Error::AlreadyRunning);
            }
            *running = None;
        }
        // Refuse an occupied socket before spawning, never adopt another local API.
        let reservation =
            std::net::TcpListener::bind(("127.0.0.1", port)).map_err(|_| Error::ApiNotReady)?;
        let mut command = self.command(port, accounts, &claude_key)?;
        drop(reservation);
        let mut run = Running {
            child: command.spawn().map_err(|_| Error::ApiUnavailable)?,
            port,
            claude_enabled: !claude_key.is_empty(),
        };
        let key = self.key()?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            if run
                .child
                .try_wait()
                .map_err(|_| Error::CommandFailed)?
                .is_some()
            {
                return Err(Error::ApiNotReady);
            }
            if protected_ready(port, &key).await {
                *running = Some(run);
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                stop_process(&mut run.child).await?;
                return Err(Error::ApiNotReady);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    pub async fn snapshot(&self) -> Snapshot {
        let mut result = Snapshot {
            available: self.available(),
            ..Default::default()
        };
        let mut running = self.running.lock().await;
        if let Some(run) = running.as_mut() {
            if matches!(run.child.try_wait(), Ok(None)) {
                result.running = true;
                result.base_url = Some(format!("http://127.0.0.1:{}/v1", run.port));
                result.claude_enabled = run.claude_enabled;
                result.ready = match self.key() {
                    Ok(key) => protected_ready(run.port, &key).await,
                    Err(_) => false,
                };
            } else {
                *running = None;
            }
        }
        result
    }
    pub async fn stop(&self) -> Result<()> {
        let mut running = self.running.lock().await;
        if let Some(run) = running.as_mut() {
            stop_process(&mut run.child).await?;
        }
        *running = None;
        Ok(())
    }
}
async fn status(port: u16, path: &str, key: Option<&str>) -> Option<u16> {
    tokio::time::timeout(Duration::from_secs(1), async {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.ok()?;
        let auth = key
            .map(|v| format!("Authorization: Bearer {v}\r\n"))
            .unwrap_or_default();
        stream
            .write_all(
                format!(
                    "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{auth}Connection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .ok()?;
        let mut header = Vec::new();
        loop {
            let byte = stream.read_u8().await.ok()?;
            header.push(byte);
            if header.ends_with(b"\r\n") {
                break;
            }
            if header.len() > 128 {
                return None;
            }
        }
        let line = std::str::from_utf8(&header).ok()?;
        if !line.starts_with("HTTP/1.1 ") {
            return None;
        }
        line.split_whitespace().nth(1)?.parse().ok()
    })
    .await
    .ok()
    .flatten()
}
async fn protected_ready(port: u16, key: &str) -> bool {
    status(port, "/health/ready", None).await == Some(200)
        && status(port, "/v1/models", None).await == Some(401)
        && status(port, "/v1/models", Some(key)).await == Some(200)
}
async fn stop_process(child: &mut Child) -> Result<()> {
    if child
        .try_wait()
        .map_err(|_| Error::CommandFailed)?
        .is_some()
    {
        return Ok(());
    }
    drop(child.stdin.take());
    match tokio::time::timeout(Duration::from_secs(20), child.wait()).await {
        Ok(result) => {
            result.map_err(|_| Error::CommandFailed)?;
            Ok(())
        }
        Err(_) => {
            child.kill().await.map_err(|_| Error::CommandFailed)?;
            Err(Error::CommandTimeout)
        }
    }
}
fn private_key(path: &Path, helper: &Path) -> Result<String> {
    #[cfg(windows)]
    {
        let value = crate::node::private_helper(helper, "bearer", path)?;
        let key = value
            .get("key")
            .and_then(serde_json::Value::as_str)
            .ok_or(Error::PrivateStorageUnavailable)?;
        if key.len() != 64
            || !key
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::PrivateStorageUnavailable);
        }
        Ok(key.to_owned())
    }
    #[cfg(unix)]
    {
        let _ = helper;
        use std::{
            fs::OpenOptions,
            io::{Read, Write},
            os::unix::fs::{MetadataExt, OpenOptionsExt},
        };
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut random = [0u8; 32];
                getrandom::fill(&mut random).map_err(|_| Error::PrivateStorageUnavailable)?;
                let key = random
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
                let mut created = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(path)
                    .map_err(|_| Error::PrivateStorageUnavailable)?;
                created
                    .write_all(key.as_bytes())
                    .map_err(|_| Error::PrivateStorageUnavailable)?;
                created
                    .sync_all()
                    .map_err(|_| Error::PrivateStorageUnavailable)?;
                return Ok(key);
            }
            Err(_) => return Err(Error::PrivateStorageUnavailable),
        };
        let meta = file
            .metadata()
            .map_err(|_| Error::PrivateStorageUnavailable)?;
        if !meta.is_file()
            || meta.mode() & 0o077 != 0
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.len() != 64
        {
            return Err(Error::PrivateStorageUnavailable);
        }
        let mut key = String::new();
        file.read_to_string(&mut key)
            .map_err(|_| Error::PrivateStorageUnavailable)?;
        if !key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::PrivateStorageUnavailable);
        }
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn bearer_is_private_stable_and_refuses_symlinks_or_shared_files() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("bearer");
        let key = private_key(&file, Path::new("unused")).unwrap();
        assert_eq!(key.len(), 64);
        assert_eq!(private_key(&file, Path::new("unused")).unwrap(), key);
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            private_key(&file, Path::new("unused")),
            Err(Error::PrivateStorageUnavailable)
        );
        let link = root.path().join("link");
        symlink(&file, &link).unwrap();
        assert_eq!(
            private_key(&link, Path::new("unused")),
            Err(Error::PrivateStorageUnavailable)
        );
    }
    #[cfg(unix)]
    #[test]
    fn launch_environment_has_only_app_profiles_and_loopback() {
        let root = tempfile::tempdir().unwrap();
        let binary = root.path().join("api");
        let resources = root.path().join("runtime");
        std::fs::create_dir(&resources).unwrap();
        std::fs::write(&binary, "fixture").unwrap();
        std::fs::write(root.path().join("scarlett-node"), "fixture").unwrap();
        for file in ["codex_profile.json", "codex_scaffold.json"] {
            std::fs::write(resources.join(file), "{}").unwrap();
        }
        let api = LocalApi::new(&root.path().join("state"), binary, resources);
        let command = api.command(8088, &[], "").unwrap();
        let command = command.as_std();
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["desktop", "api", "8088"]
        );
        let env = command
            .get_envs()
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(
            env.get(std::ffi::OsStr::new("HOME")),
            Some(&Some(api.state.as_os_str()))
        );
        assert_eq!(
            env.get(std::ffi::OsStr::new("GATEWAY_PROVIDERS")),
            Some(&Some(std::ffi::OsStr::new("codex")))
        );
        assert!(!env.contains_key(std::ffi::OsStr::new("ANTHROPIC_API_KEY")));
        assert!(!env.contains_key(std::ffi::OsStr::new("PATH")));
        assert!(api.command(80, &[], "").is_err());
        assert!(api.command(8088, &[], "key\nINJECT=value").is_err());
        assert!(
            !serde_json::to_string(&Snapshot::default())
                .unwrap()
                .contains("bearer")
        );
    }
    #[tokio::test]
    async fn readiness_requires_authenticated_models_and_rejects_open_service() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut connection, _) = listener.accept().await.unwrap();
                let mut bytes = [0u8; 1024];
                let read = connection.read(&mut bytes).await.unwrap();
                assert!(read > 0);
                connection
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
            }
        });
        assert!(!protected_ready(port, &"a".repeat(64)).await);
        server.await.unwrap();
    }
    #[tokio::test]
    #[ignore = "requires explicitly supplied reviewed native API and resources; makes no provider jobs"]
    async fn native_api_supervisor_uses_disposable_profiles_and_stops() {
        let binary = PathBuf::from(
            std::env::var_os("SCARLETT_NATIVE_API_TEST").expect("explicit native API required"),
        );
        let resources = PathBuf::from(
            std::env::var_os("SCARLETT_NATIVE_RESOURCE_TEST")
                .expect("explicit native resources required"),
        );
        let root = tempfile::tempdir().unwrap();
        let api = LocalApi::new(&root.path().join("state"), binary, resources);
        let socket = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = socket.local_addr().unwrap().port();
        assert_eq!(
            api.start(port, &[], String::new()).await,
            Err(Error::ApiNotReady)
        );
        drop(socket);
        api.start(port, &[], String::new()).await.unwrap();
        let status = api.snapshot().await;
        assert!(status.ready && status.running);
        assert!(!status.claude_enabled);
        assert_eq!(
            api.start(port, &[], String::new()).await,
            Err(Error::AlreadyRunning)
        );
        assert!(!root.path().join("state/local-api/codex/auth.json").exists());
        api.stop().await.unwrap();
        assert!(!api.snapshot().await.running);
        assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
        api.start(port, &[], String::new()).await.unwrap();
        // OS closure of the desktop's pipe has this same observable boundary.
        // The host must stop the API even without a native Stop invocation.
        {
            let mut running = api.running.lock().await;
            drop(running.as_mut().unwrap().child.stdin.take());
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while api.snapshot().await.running {
            assert!(
                tokio::time::Instant::now() < deadline,
                "API survived owner input closure"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
    }
}
