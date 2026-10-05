//! Fixed native CLI delegation. Raw provider/CLI output never crosses the UI boundary.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    path::{Component, Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
    sync::Mutex,
};

const COORDINATOR: &str = "https://network.scarlett.ai";
const VERIFIER: &str = "verifier.scarlett.ai:7047";
const CLI_VERSION: &str = "codex-cli 0.159.2";
const OUTPUT_LIMIT: usize = 32768;
/// The node's durable keyed-relay halt marker (worker.RelayHaltFile). It exists
/// from the moment the node catches its verifier misusing an X session until
/// `scarlett-node relay-resume` removes it.
const RELAY_HALT_FILE: &str = "relay-halt";

#[derive(Clone)]
struct Endpoints {
    coordinator: String,
    verifier: String,
    verifier_ca: Option<PathBuf>,
    coordinator_ca: Option<PathBuf>,
}
impl Default for Endpoints {
    fn default() -> Self {
        Self {
            coordinator: COORDINATOR.into(),
            verifier: VERIFIER.into(),
            verifier_ca: None,
            coordinator_ca: None,
        }
    }
}
impl Endpoints {
    fn resolve(
        debug: bool,
        coordinator: Option<&str>,
        verifier: Option<&str>,
        ca: Option<&Path>,
        coordinator_ca: Option<&Path>,
    ) -> Result<Self> {
        if !debug {
            return Ok(Self::default());
        }
        let mut out = Self::default();
        if let Some(raw) = coordinator {
            let url = tauri::Url::parse(raw).map_err(|_| Error::InvalidInput)?;
            let loopback = url.host_str().is_some_and(|h| {
                h == "localhost"
                    || h.trim_matches(['[', ']'])
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            });
            if !loopback
                || url.scheme() != "https"
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
                || url.path() != "/"
                || url.port().is_none_or(|p| p < 1024)
            {
                return Err(Error::InvalidInput);
            }
            let ca = coordinator_ca.ok_or(Error::InvalidInput)?;
            if !ca.is_absolute() || !regular(ca) {
                return Err(Error::InvalidInput);
            }
            out.coordinator_ca = Some(ca.to_path_buf());
            out.coordinator = raw.trim_end_matches('/').to_owned();
        } else if coordinator_ca.is_some() {
            return Err(Error::InvalidInput);
        }
        if let Some(raw) = verifier {
            let address: std::net::SocketAddr = raw.parse().map_err(|_| Error::InvalidInput)?;
            if !address.ip().is_loopback() || address.port() < 1024 {
                return Err(Error::InvalidInput);
            }
            out.verifier = raw.into();
            // Local verifier still needs an explicitly trusted TLS CA; no plaintext flag.
            let ca = ca.ok_or(Error::InvalidInput)?;
            if !ca.is_absolute() || !regular(ca) {
                return Err(Error::InvalidInput);
            }
            out.verifier_ca = Some(ca.to_path_buf());
        } else if ca.is_some() {
            return Err(Error::InvalidInput);
        }
        Ok(out)
    }
}

#[derive(Clone, Serialize, Debug, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Error {
    InvalidInput,
    RuntimeUnavailable,
    AccountsUnavailable,
    AccountLimit,
    CliUnavailable,
    CommandFailed,
    CommandTimeout,
    AlreadyRunning,
    NotPaired,
    LoginBusy,
    LoginFailed,
    ClaudeUnavailable,
    ClaudeLoginFailed,
    ApiUnavailable,
    ApiNotReady,
    ApiPortInUse,
    ApiProcessExited,
    ModeConflict,
    AutostartUnavailable,
    PrivateStorageUnavailable,
    BrowserProtected,
    BrowserBusy,
    BrowserInvalid,
    BrowserNoXSession,
    BrowserAmbiguous,
    BrowserUnsupported,
}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct BrowserProfile {
    pub id: String,
    pub browser: String,
    pub label: String,
}

fn browser_profile_id(id: &str) -> bool {
    ["chrome_", "firefox_", "safari_"].iter().any(|prefix| {
        id.strip_prefix(prefix).is_some_and(|hash| {
            hash.len() == 32
                && hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    })
}

fn browser_import_error(raw: &[u8]) -> Error {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Failure {
        status: String,
        code: String,
    }
    let Ok(failure) = serde_json::from_slice::<Failure>(raw) else {
        return Error::CommandFailed;
    };
    if failure.status != "error" {
        return Error::CommandFailed;
    }
    match failure.code.as_str() {
        "browser_protected" => Error::BrowserProtected,
        "browser_busy" => Error::BrowserBusy,
        "browser_invalid" => Error::BrowserInvalid,
        "browser_no_x_session" => Error::BrowserNoXSession,
        "browser_ambiguous" => Error::BrowserAmbiguous,
        "browser_unsupported" => Error::BrowserUnsupported,
        _ => Error::CommandFailed,
    }
}

fn browser_profile_projection(raw: &[u8]) -> Result<Vec<BrowserProfile>> {
    let profiles: Vec<BrowserProfile> =
        serde_json::from_slice(raw).map_err(|_| Error::CommandFailed)?;
    if profiles.len() > 48
        || profiles.iter().any(|p| {
            !browser_profile_id(&p.id)
                || !matches!(p.browser.as_str(), "chrome" | "firefox" | "safari")
                || !p.id.starts_with(&format!("{}_", p.browser))
                || p.label.is_empty()
                || p.label.len() > 100
                || p.label.chars().any(char::is_control)
        })
    {
        return Err(Error::CommandFailed);
    }
    Ok(profiles)
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Account {
    pub id: String,
    pub service: String,
    pub concurrency: u8,
}
#[derive(Clone, Serialize, Default)]
pub struct Snapshot {
    pub local_api: crate::local_api::Snapshot,
    pub runtime_available: bool,
    pub accounts_available: bool,
    pub helper_available: bool,
    pub codex_login_available: bool,
    pub paired: bool,
    pub supervised: bool,
    pub login_pending: bool,
    pub login_error: Option<Error>,
    pub observation: Option<Value>,
    pub accounts: Vec<Account>,
    /// Whether the saved relay halt is still on disk. With the status's
    /// `relay_halted`, this tells a pending resume (marker gone, node not yet
    /// caught up) from a halt nobody has resumed.
    pub relay_halt_marker: bool,
}
struct Login {
    child: Child,
    id: String,
    concurrency: u8,
    home: PathBuf,
    started: Instant,
}
pub struct Node {
    pub state: PathBuf,
    endpoints: Endpoints,
    binary: PathBuf,
    helper: PathBuf,
    codex_binary: PathBuf,
    running: Mutex<Option<Child>>,
    login: Mutex<Option<Login>>,
    login_error: Mutex<Option<Error>>,
    mutation: Mutex<()>,
}

pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 32
        && id != "legacy"
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}
/// One X cookie value as the node's session validation accepts it.
fn x_cookie(v: &str, max: usize) -> bool {
    !v.is_empty()
        && v.len() <= max
        && v.bytes()
            .all(|b| (33..=126).contains(&b) && !b";=\\\"".contains(&b))
}
fn valid_selection(service: &str, id: &str, concurrency: u8) -> Result<()> {
    if (service != "codex" && service != "x_read")
        || !valid_id(id)
        || !(1..=32).contains(&concurrency)
    {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
/// Codex accounts the node accepts per provider; see maxProviderAccounts.
const MAX_CODEX_ACCOUNTS: usize = 8;
const CODEX_PROFILE_NAMES: u32 = 10_000;
// Reserve a new app-owned profile atomically, including after cancelled logins.
// Existing directories, files and links must never be reused for another login.
fn new_codex_profile(
    profiles: &Path,
    accounts: &[Account],
    helper: &Path,
    names: u32,
) -> Result<(String, PathBuf)> {
    if accounts.iter().filter(|a| a.service == "codex").count() >= MAX_CODEX_ACCOUNTS {
        return Err(Error::AccountLimit);
    }
    for number in 1..=names {
        let id = format!("codex-{number}");
        if accounts.iter().any(|a| a.service == "codex" && a.id == id) {
            continue;
        }
        let home = profiles.join(&id);
        if reserve_private_dir(&home, helper)? {
            return Ok((id, home));
        }
    }
    Err(Error::AccountLimit)
}
/// Exclusively creates one new private directory. `Ok(false)` means the name is
/// already held by any entry, including a file, a link or an older directory.
fn reserve_private_dir(path: &Path, helper: &Path) -> Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let _ = helper;
        match std::fs::DirBuilder::new()
            .recursive(false)
            .mode(0o700)
            .create(path)
        {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(_) => Err(Error::PrivateStorageUnavailable),
        }
    }
    #[cfg(windows)]
    {
        // std::fs::DirBuilder calls CreateDirectoryW(path, NULL): the directory
        // only inherits ACEs and the node's private-dir check rejects it. The
        // node helper applies its protected DACL in the create itself.
        if std::fs::symlink_metadata(path).is_ok() {
            // Cheap skip only; the helper's exclusive create stays authoritative.
            return Ok(false);
        }
        let response = private_helper(helper, "private-dir-new", path)?;
        match response.get("status").and_then(Value::as_str) {
            Some("created") => Ok(true),
            Some("exists") => Ok(false),
            _ => Err(Error::PrivateStorageUnavailable),
        }
    }
}
// The node renews only Codex profiles directly under this root: the app's own
// completed logins. The node and the local API never run together, so the node
// is the only writer while it renews. The node rejects a root that is not a clean
// absolute path; such a state path leaves renewal off rather than stopping it.
fn managed_codex_root(state: &Path) -> Option<PathBuf> {
    let root = state.join("codex-logins");
    let normal: PathBuf = root.components().collect();
    let text = root.to_str()?;
    (root.is_absolute()
        && normal.as_os_str() == root.as_os_str()
        && !root
            .components()
            .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
        && !text.contains(['\0', '\r', '\n']))
    .then_some(root)
}
#[cfg(unix)]
fn private_dir(path: &Path) -> Result<()> {
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        match std::fs::symlink_metadata(path) {
            Ok(meta)
                if meta.is_dir()
                    && !meta.file_type().is_symlink()
                    && meta.mode() & 0o077 == 0
                    && meta.uid() == unsafe { libc::geteuid() } =>
            {
                Ok(())
            }
            Ok(_) => Err(Error::PrivateStorageUnavailable),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::DirBuilder::new()
                .mode(0o700)
                .create(path)
                .map_err(|_| Error::PrivateStorageUnavailable),
            Err(_) => Err(Error::PrivateStorageUnavailable),
        }
    }
}
pub(crate) fn private_dir_with_helper(path: &Path, helper: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let _ = helper;
        private_dir(path)
    }
    #[cfg(windows)]
    {
        let response = private_helper(helper, "private-dir", path)?;
        if response.get("ok").and_then(Value::as_bool) != Some(true) {
            return Err(Error::PrivateStorageUnavailable);
        }
        Ok(())
    }
}
pub(crate) fn private_helper(binary: &Path, action: &str, path: &Path) -> Result<Value> {
    if !path.is_absolute() || !regular(binary) {
        return Err(Error::PrivateStorageUnavailable);
    }
    let mut command = std::process::Command::new(binary);
    command
        .args([
            std::ffi::OsStr::new("desktop"),
            std::ffi::OsStr::new(action),
            path.as_os_str(),
        ])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for name in ["SystemRoot", "WINDIR"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command
        .spawn()
        .map_err(|_| Error::PrivateStorageUnavailable)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(25));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::PrivateStorageUnavailable);
            }
        }
    };
    use std::io::Read;
    let mut output = Vec::new();
    child
        .stdout
        .take()
        .ok_or(Error::PrivateStorageUnavailable)?
        .take(129)
        .read_to_end(&mut output)
        .map_err(|_| Error::PrivateStorageUnavailable)?;
    if !status.success() || output.len() > 128 {
        return Err(Error::PrivateStorageUnavailable);
    }
    serde_json::from_slice(&output).map_err(|_| Error::PrivateStorageUnavailable)
}
pub(crate) fn regular(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file() && !m.file_type().is_symlink())
}
/// The node's fixed `{"status":"updated"}` acknowledgement of an account write.
fn updated(raw: &[u8]) -> Result<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Updated {
        status: String,
    }
    if serde_json::from_slice::<Updated>(raw)
        .map_err(|_| Error::CommandFailed)?
        .status
        != "updated"
    {
        return Err(Error::CommandFailed);
    }
    Ok(())
}
fn account_projection(raw: &[u8]) -> Result<Vec<Account>> {
    let records: Vec<Value> = serde_json::from_slice(raw).map_err(|_| Error::CommandFailed)?;
    if records.len() > 16 {
        return Err(Error::CommandFailed);
    }
    records
        .into_iter()
        .map(|v| {
            let a: Account = serde_json::from_value(v).map_err(|_| Error::CommandFailed)?;
            valid_selection(&a.service, &a.id, a.concurrency).map_err(|_| Error::CommandFailed)?;
            Ok(a)
        })
        .collect()
}
fn observation_projection(raw: &[u8]) -> Result<Value> {
    let v: Value = serde_json::from_slice(raw).map_err(|_| Error::CommandFailed)?;
    let source = v.as_object().ok_or(Error::CommandFailed)?;
    let mut out = serde_json::Map::new();
    for key in [
        "version",
        "state",
        "updated_at",
        "last_heartbeat_at",
        "in_flight",
        "unresolved_attempts",
        "drain_requested",
        "relay_halted",
    ] {
        if let Some(value) = source.get(key)
            && (value.is_string() || value.is_boolean() || value.is_number())
        {
            out.insert(key.into(), value.clone());
        }
    }
    for (key, allowed) in [
        (
            "services",
            &[
                "kind",
                "state",
                "capacity",
                "in_flight",
                "last_error_code",
                "proof_modes",
            ][..],
        ),
        (
            "accounts",
            &[
                "id",
                "service",
                "state",
                "capacity",
                "in_flight",
                "last_error_code",
                "rest_until",
            ][..],
        ),
    ] {
        let items = source
            .get(key)
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .take(16)
                    .filter_map(|item| {
                        let obj = item.as_object()?;
                        let mut safe = serde_json::Map::new();
                        for field in allowed {
                            let Some(value) = obj.get(*field) else {
                                continue;
                            };
                            if *field == "proof_modes" {
                                if let Some(modes) = proof_modes(value) {
                                    safe.insert((*field).into(), modes);
                                }
                            } else if value.is_string() || value.is_number() || value.is_null() {
                                safe.insert((*field).into(), value.clone());
                            }
                        }
                        Some(Value::Object(safe))
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        out.insert(key.into(), Value::Array(items));
    }
    Ok(Value::Object(out))
}
/// Proof modes a service advertises, reduced to the ones this app can name.
/// Absent means MPC-TLS only, as for every node before the field existed.
fn proof_modes(value: &Value) -> Option<Value> {
    let modes = value
        .as_array()?
        .iter()
        .take(8)
        .filter_map(Value::as_str)
        .filter(|mode| matches!(*mode, "mpc" | "relay"))
        .map(|mode| Value::String(mode.into()))
        .collect::<Vec<_>>();
    Some(Value::Array(modes))
}
impl Node {
    pub fn new(state: PathBuf, binary: PathBuf, helper: PathBuf) -> Self {
        let codex_binary = binary
            .parent()
            .unwrap_or(Path::new("."))
            .join(if cfg!(windows) { "codex.exe" } else { "codex" });
        Self {
            state,
            endpoints: Endpoints::default(),
            binary,
            helper,
            codex_binary,
            running: Mutex::new(None),
            login: Mutex::new(None),
            login_error: Mutex::new(None),
            mutation: Mutex::new(()),
        }
    }
    pub fn with_provider_runtime(mut self, resource_root: &Path) -> Self {
        self.codex_binary = resource_root
            .join("runtime")
            .join("codex")
            .join("bin")
            .join(if cfg!(windows) { "codex.exe" } else { "codex" });
        self
    }
    pub fn from_environment(state: PathBuf, binary: PathBuf, helper: PathBuf) -> Result<Self> {
        let mut node = Self::new(state, binary, helper);
        let coordinator = std::env::var("SCARLETT_DESKTOP_LOCAL_COORDINATOR").ok();
        let verifier = std::env::var("SCARLETT_DESKTOP_LOCAL_VERIFIER").ok();
        let ca = std::env::var_os("SCARLETT_DESKTOP_LOCAL_VERIFIER_CA").map(PathBuf::from);
        let coordinator_ca =
            std::env::var_os("SCARLETT_DESKTOP_LOCAL_COORDINATOR_CA").map(PathBuf::from);
        node.endpoints = Endpoints::resolve(
            cfg!(debug_assertions),
            coordinator.as_deref(),
            verifier.as_deref(),
            ca.as_deref(),
            coordinator_ca.as_deref(),
        )?;
        Ok(node)
    }
    pub fn network_url(&self, destination: &str) -> Result<String> {
        let path = match destination {
            "setup" => "/setup/",
            "dashboard" => "/dashboard/",
            "settings" => "/settings/",
            _ => return Err(Error::InvalidInput),
        };
        Ok(format!("{}{path}", self.endpoints.coordinator))
    }
    fn prepare(&self) -> Result<()> {
        private_dir_with_helper(&self.state, &self.binary)?;
        Ok(())
    }
    fn command(&self, args: &[&str]) -> Result<Command> {
        self.prepare()?;
        if !regular(&self.binary) {
            return Err(Error::RuntimeUnavailable);
        }
        let mut cmd = Command::new(&self.binary);
        cmd.args(args).env_clear();
        for name in [
            "HOME",
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "SystemRoot",
            "WINDIR",
            "TEMP",
            "TMP",
            "TMPDIR",
            "LANG",
        ] {
            if let Some(v) = std::env::var_os(name) {
                cmd.env(name, v);
            }
        }
        cmd.env("SCARLETT_STATE_DIR", &self.state)
            .env("SCARLETT_ACCOUNTS_FILE", self.state.join("accounts.json"))
            .env("SCARLETT_COORDINATOR", &self.endpoints.coordinator)
            .env("SCARLETT_VERIFIER", &self.endpoints.verifier)
            .env("SCARLETT_EXECUTOR", "services")
            .env("SCARLETT_SERVICES", "codex,x_read")
            .env("SCARLETT_PROFILE", "standard")
            .env("SCARLETT_PROVER", &self.helper)
            .env(
                "SCARLETT_CODEX_HOME",
                self.state.join("unused-legacy-codex"),
            )
            .env(
                "SCARLETT_X_SESSION",
                self.state.join("unused-legacy-x.json"),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        #[cfg(windows)]
        cmd.creation_flags(0x08000000);
        if let Some(root) = managed_codex_root(&self.state) {
            cmd.env("SCARLETT_CODEX_MANAGED_ROOT", root);
        }
        if let Some(ca) = &self.endpoints.verifier_ca {
            cmd.env("SCARLETT_VERIFIER_CA_FILE", ca);
        }
        if let Some(ca) = &self.endpoints.coordinator_ca {
            cmd.env("SCARLETT_COORDINATOR_CA_FILE", ca);
        }
        Ok(cmd)
    }
    async fn call(&self, args: &[&str], input: Option<Vec<u8>>, seconds: u64) -> Result<Vec<u8>> {
        let mut child = self
            .command(args)?
            .spawn()
            .map_err(|_| Error::RuntimeUnavailable)?;
        let stdout = child.stdout.take().ok_or(Error::CommandFailed)?;
        let result = tokio::time::timeout(Duration::from_secs(seconds), async {
            if let Some(input) = input {
                if input.len() > 16384 {
                    return Err(Error::InvalidInput);
                }
                let mut pipe = child.stdin.take().ok_or(Error::CommandFailed)?;
                pipe.write_all(&input)
                    .await
                    .map_err(|_| Error::CommandFailed)?;
                pipe.shutdown().await.map_err(|_| Error::CommandFailed)?;
            }
            drop(child.stdin.take());
            let mut reader = stdout.take((OUTPUT_LIMIT + 1) as u64);
            let mut output = Vec::new();
            reader
                .read_to_end(&mut output)
                .await
                .map_err(|_| Error::CommandFailed)?;
            if output.len() > OUTPUT_LIMIT {
                return Err(Error::CommandFailed);
            }
            if !child
                .wait()
                .await
                .map_err(|_| Error::CommandFailed)?
                .success()
            {
                if args.first() == Some(&"accounts")
                    && matches!(args.get(1), Some(&"import-x" | &"reimport-x"))
                {
                    return Err(browser_import_error(&output));
                }
                return Err(Error::CommandFailed);
            }
            Ok(output)
        })
        .await
        .map_err(|_| Error::CommandTimeout)?;
        // kill_on_drop also covers timeout, malformed output and early pipe errors.
        result
    }
    pub async fn accounts(&self) -> Result<Vec<Account>> {
        let raw = self
            .call(&["accounts", "list"], None, 5)
            .await
            .map_err(|e| {
                if e == Error::CommandFailed {
                    Error::AccountsUnavailable
                } else {
                    e
                }
            })?;
        account_projection(&raw)
    }
    pub async fn pair(&self, code: String) -> Result<()> {
        let _guard = self.mutation.lock().await;
        if code.len() != 64
            || !code
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::InvalidInput);
        }
        if regular(&self.state.join("identity.json")) {
            return Err(Error::CommandFailed);
        }
        // One invocation only. A timeout is ambiguous; never retry automatically.
        self.call(&["pair"], Some(format!("{code}\n").into_bytes()), 15)
            .await?;
        Ok(())
    }
    pub async fn connect_x(
        &self,
        id: String,
        concurrency: u8,
        auth_token: String,
        ct0: String,
    ) -> Result<()> {
        let _guard = self.mutation.lock().await;
        valid_selection("x_read", &id, concurrency)?;
        if !x_cookie(&auth_token, 64) || !x_cookie(&ct0, 160) {
            return Err(Error::InvalidInput);
        }
        self.accounts().await?;
        let input = serde_json::to_vec(&json!({"auth_token":auth_token,"ct0":ct0}))
            .map_err(|_| Error::InvalidInput)?;
        self.call(
            &[
                "accounts",
                "connect",
                "x_read",
                &id,
                &concurrency.to_string(),
            ],
            Some(input),
            5,
        )
        .await?;
        Ok(())
    }
    pub async fn browser_profiles(&self) -> Result<Vec<BrowserProfile>> {
        let raw = self
            .call(&["accounts", "browser-profiles"], None, 5)
            .await?;
        browser_profile_projection(&raw)
    }
    pub async fn import_x(&self, profile: String, id: String, concurrency: u8) -> Result<()> {
        let _guard = self.mutation.lock().await;
        valid_selection("x_read", &id, concurrency)?;
        if !browser_profile_id(&profile) {
            return Err(Error::InvalidInput);
        }
        self.accounts().await?;
        let raw = self
            .call(
                &[
                    "accounts",
                    "import-x",
                    &profile,
                    &id,
                    &concurrency.to_string(),
                ],
                None,
                45,
            )
            .await?;
        updated(&raw)
    }
    /// A re-import only targets an X account the node already has.
    async fn registered_x(&self, id: &str) -> Result<()> {
        valid_selection("x_read", id, 1)?;
        if !self
            .accounts()
            .await?
            .iter()
            .any(|a| a.service == "x_read" && a.id == id)
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
    /// Re-import for an X account whose session X expired or revoked: the same
    /// local ID keeps its concurrency and only its saved session is replaced.
    pub async fn reconnect_x(&self, id: String, auth_token: String, ct0: String) -> Result<()> {
        let _guard = self.mutation.lock().await;
        if !x_cookie(&auth_token, 64) || !x_cookie(&ct0, 160) {
            return Err(Error::InvalidInput);
        }
        self.registered_x(&id).await?;
        let input = serde_json::to_vec(&json!({"auth_token":auth_token,"ct0":ct0}))
            .map_err(|_| Error::InvalidInput)?;
        self.call(&["accounts", "reconnect", "x_read", &id], Some(input), 5)
            .await?;
        Ok(())
    }
    pub async fn reimport_x(&self, profile: String, id: String) -> Result<()> {
        let _guard = self.mutation.lock().await;
        if !browser_profile_id(&profile) {
            return Err(Error::InvalidInput);
        }
        self.registered_x(&id).await?;
        let raw = self
            .call(&["accounts", "reimport-x", &profile, &id], None, 45)
            .await?;
        updated(&raw)
    }
    /// Clears a saved keyed-relay halt with the bundled node's `relay-resume`,
    /// which only removes `<state>/relay-halt` and syncs the directory. It is
    /// safe while the supervised node runs, so this never drains, stops or
    /// restarts it: that would drop every warm X client and interrupt accepted
    /// work. A running node keeps relay paused until it picks the change up.
    pub async fn resume_relay(&self) -> Result<()> {
        self.call(&["relay-resume"], None, 5).await?;
        if self.relay_halt_marker() {
            return Err(Error::CommandFailed);
        }
        Ok(())
    }
    fn relay_halt_marker(&self) -> bool {
        std::fs::symlink_metadata(self.state.join(RELAY_HALT_FILE)).is_ok()
    }
    pub async fn remove(&self, service: String, id: String) -> Result<()> {
        let _guard = self.mutation.lock().await;
        valid_selection(&service, &id, 1)?;
        self.accounts().await?;
        self.call(&["accounts", "remove", &service, &id], None, 5)
            .await?;
        Ok(())
    }
    pub async fn start(&self) -> Result<()> {
        let _guard = self.mutation.lock().await;
        let mut running = self.running.lock().await;
        if running
            .as_mut()
            .is_some_and(|p| p.try_wait().ok().flatten().is_none())
        {
            return Err(Error::AlreadyRunning);
        }
        if !regular(&self.state.join("identity.json")) {
            return Err(Error::NotPaired);
        }
        if !regular(&self.helper) {
            return Err(Error::RuntimeUnavailable);
        }
        if self.accounts().await?.is_empty() {
            return Err(Error::AccountsUnavailable);
        }
        let mut cmd = self.command(&["desktop", "run"])?;
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(unix)]
        {
            cmd.process_group(0);
        }
        *running = Some(cmd.spawn().map_err(|_| Error::RuntimeUnavailable)?);
        Ok(())
    }
    pub async fn control(&self, action: &str) -> Result<()> {
        match action {
            "start" => self.start().await,
            "pause" => {
                self.call(&["drain"], None, 5).await?;
                Ok(())
            }
            "resume" => {
                self.call(&["resume"], None, 5).await?;
                Ok(())
            }
            "stop" => self.stop().await,
            _ => Err(Error::InvalidInput),
        }
    }
    pub async fn stop(&self) -> Result<()> {
        let _guard = self.mutation.lock().await;
        self.cancel_login().await?;
        let mut running = self.running.lock().await;
        if let Some(child) = running.as_mut() {
            if child
                .try_wait()
                .map_err(|_| Error::CommandFailed)?
                .is_some()
            {
                *running = None;
                return Ok(());
            }
            self.call(&["drain"], None, 5).await?;
            // Closing this owned pipe requests drain without signaling a stale PID.
            drop(child.stdin.take());
            {
                // Node gives accepted work up to two minutes, within its lease.
                match tokio::time::timeout(Duration::from_secs(125), child.wait()).await {
                    Ok(result) => {
                        result.map_err(|_| Error::CommandFailed)?;
                    }
                    Err(_) => {
                        #[cfg(unix)]
                        {
                            if let Some(pid) = child.id() {
                                unsafe {
                                    libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
                                }
                            }
                        }
                        child.kill().await.map_err(|_| Error::CommandFailed)?;
                        return Err(Error::CommandTimeout);
                    }
                }
                *running = None;
            }
        }
        Ok(())
    }
    pub async fn cancel_login(&self) -> Result<()> {
        if let Some(mut pending) = self.login.lock().await.take() {
            let _ = pending.child.kill().await;
            *self.login_error.lock().await = Some(Error::LoginFailed);
        }
        Ok(())
    }
    async fn codex_cli(&self) -> Option<PathBuf> {
        let candidates = [&self.codex_binary];
        for p in candidates {
            let Ok(p) = p.canonicalize() else { continue };
            if !regular(&p) {
                continue;
            }
            let mut cmd = Command::new(&p);
            cmd.arg("--version")
                .env_clear()
                .env("HOME", &self.state)
                .env("USERPROFILE", &self.state)
                .env("CODEX_HOME", self.state.join("runtime-probe"))
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true);
            #[cfg(windows)]
            cmd.creation_flags(0x08000000);
            for name in ["SystemRoot", "WINDIR"] {
                if let Some(value) = std::env::var_os(name) {
                    cmd.env(name, value);
                }
            }
            let checked = tokio::time::timeout(Duration::from_secs(3), async {
                let mut child = cmd.spawn().ok()?;
                let stdout = child.stdout.take()?;
                let mut output = Vec::new();
                stdout.take(129).read_to_end(&mut output).await.ok()?;
                if output.len() > 128 {
                    return None;
                }
                let status = child.wait().await.ok()?;
                (status.success() && String::from_utf8_lossy(&output).trim() == CLI_VERSION)
                    .then_some(())
            })
            .await;
            if matches!(checked, Ok(Some(()))) {
                return Some(p);
            }
        }
        None
    }
    // Each login gets a fresh private CODEX_HOME that the node itself accepts.
    fn reserve_codex_login(&self, accounts: &[Account]) -> Result<(String, PathBuf)> {
        let profiles = self.state.join("codex-logins");
        private_dir_with_helper(&profiles, &self.binary)?;
        let (id, home) = new_codex_profile(&profiles, accounts, &self.binary, CODEX_PROFILE_NAMES)?;
        private_dir_with_helper(&home, &self.binary)?;
        Ok((id, home))
    }
    pub async fn connect_codex(&self, concurrency: u8) -> Result<()> {
        let _guard = self.mutation.lock().await;
        if !(1..=32).contains(&concurrency) {
            return Err(Error::InvalidInput);
        }
        let accounts = self.accounts().await?;
        let mut login = self.login.lock().await;
        if login.is_some() {
            return Err(Error::LoginBusy);
        }
        let cli = self.codex_cli().await.ok_or(Error::CliUnavailable)?;
        let (id, home) = self.reserve_codex_login(&accounts)?;
        let mut cmd = Command::new(cli);
        cmd.args(["-c", "cli_auth_credentials_store=\"file\"", "login"])
            .env_clear()
            .env("CODEX_HOME", &home)
            .current_dir(&home)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        #[cfg(windows)]
        cmd.creation_flags(0x08000000);
        for name in [
            "HOME",
            "USERPROFILE",
            "SystemRoot",
            "WINDIR",
            "TEMP",
            "TMP",
            "TMPDIR",
            "PATH",
            "LANG",
        ] {
            if let Some(v) = std::env::var_os(name) {
                cmd.env(name, v);
            }
        }
        let child = cmd.spawn().map_err(|_| Error::CliUnavailable)?;
        *login = Some(Login {
            child,
            id,
            concurrency,
            home,
            started: Instant::now(),
        });
        *self.login_error.lock().await = None;
        Ok(())
    }
    pub async fn finish_login(&self) {
        let _guard = self.mutation.lock().await;
        let mut login = self.login.lock().await;
        let Some(p) = login.as_mut() else { return };
        if p.started.elapsed() > Duration::from_secs(300) {
            let _ = p.child.kill().await;
            *self.login_error.lock().await = Some(Error::CommandTimeout);
            *login = None;
            return;
        }
        let Ok(Some(status)) = p.child.try_wait() else {
            return;
        };
        let p = login.take().unwrap();
        drop(login);
        if !status.success() || !regular(&p.home.join("auth.json")) {
            *self.login_error.lock().await = Some(Error::LoginFailed);
            return;
        }
        let Some(path) = p.home.to_str() else {
            *self.login_error.lock().await = Some(Error::LoginFailed);
            return;
        };
        if self
            .call(
                &[
                    "accounts",
                    "add",
                    "codex",
                    &p.id,
                    path,
                    &p.concurrency.to_string(),
                ],
                None,
                5,
            )
            .await
            .is_err()
        {
            *self.login_error.lock().await = Some(Error::LoginFailed);
        }
    }
    pub async fn save_preferences(&self, data: &crate::preferences::Data) -> Result<()> {
        let path = self.state.join("preferences.json");
        let raw = serde_json::to_vec(data).map_err(|_| Error::InvalidInput)?;
        let output = self
            .call(
                &[
                    "desktop",
                    "preferences-set",
                    path.to_str().ok_or(Error::InvalidInput)?,
                ],
                Some(raw),
                5,
            )
            .await?;
        let persisted: crate::preferences::Data =
            serde_json::from_slice(&output).map_err(|_| Error::PrivateStorageUnavailable)?;
        if &persisted != data {
            return Err(Error::PrivateStorageUnavailable);
        }
        Ok(())
    }
    pub async fn snapshot(&self) -> Snapshot {
        if self.prepare().is_err() {
            return Snapshot::default();
        }
        self.finish_login().await;
        let mut s = Snapshot {
            runtime_available: regular(&self.binary),
            helper_available: regular(&self.helper),
            paired: regular(&self.state.join("identity.json")),
            ..Default::default()
        };
        s.codex_login_available = self.codex_cli().await.is_some();
        if let Ok(accounts) = self.accounts().await {
            s.accounts_available = true;
            s.accounts = accounts;
        }
        if let Ok(raw) = self.call(&["status"], None, 5).await {
            s.observation = observation_projection(&raw).ok();
        }
        s.relay_halt_marker = self.relay_halt_marker();
        let mut run = self.running.lock().await;
        if let Some(p) = run.as_mut() {
            s.supervised = p.try_wait().ok().flatten().is_none();
            if !s.supervised {
                *run = None;
            }
        }
        s.login_pending = self.login.lock().await.is_some();
        s.login_error = self.login_error.lock().await.clone();
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn browser_inventory_and_failures_never_project_paths_or_credentials() {
        let profile = json!({"id":"firefox_0123456789abcdef0123456789abcdef", "browser":"firefox", "label":"Firefox / Isolated"});
        let raw = serde_json::to_vec(&vec![profile.clone()]).unwrap();
        assert_eq!(browser_profile_projection(&raw).unwrap().len(), 1);
        for (key, value) in [
            ("path", "/private/browser"),
            ("auth_token", "synthetic-token"),
            ("browser", "chrome"),
            ("id", "../../escape"),
            ("label", "unsafe\nlabel"),
        ] {
            let mut invalid = profile.clone();
            invalid[key] = json!(value);
            assert!(
                browser_profile_projection(&serde_json::to_vec(&vec![invalid]).unwrap()).is_err()
            );
        }
        assert!(
            browser_profile_projection(&serde_json::to_vec(&vec![profile; 49]).unwrap()).is_err()
        );
        assert_eq!(
            browser_import_error(br#"{"status":"error","code":"browser_busy"}"#),
            Error::BrowserBusy
        );
        for raw in [
            br#"{"status":"error","code":"private-token"}"#.as_slice(),
            br#"{"status":"error","code":"browser_busy","auth_token":"private-token"}"#,
            br#"{"status":"updated","code":"browser_busy"}"#,
            b"private provider stderr",
        ] {
            assert_eq!(browser_import_error(raw), Error::CommandFailed);
        }
    }
    #[test]
    fn release_defaults_ignore_debug_endpoint_overrides() {
        let endpoints = Endpoints::resolve(
            false,
            Some("http://remote.example:18083"),
            Some("192.0.2.1:7047"),
            Some(Path::new("relative.pem")),
            Some(Path::new("ignored-coordinator.pem")),
        )
        .unwrap();
        assert_eq!(endpoints.coordinator, COORDINATOR);
        assert_eq!(endpoints.verifier, VERIFIER);
        assert!(endpoints.verifier_ca.is_none());
        assert!(endpoints.coordinator_ca.is_none());
    }
    #[test]
    fn debug_coordinator_requires_trusted_https_loopback_origin() {
        let temp = tempfile::tempdir().unwrap();
        let ca = temp.path().join("coordinator-ca.pem");
        std::fs::write(&ca, "synthetic CA fixture").unwrap();
        for origin in [
            "https://localhost:18443",
            "https://127.0.0.1:18443/",
            "https://[::1]:18443",
        ] {
            assert!(Endpoints::resolve(true, Some(origin), None, None, Some(&ca)).is_ok());
            assert!(Endpoints::resolve(true, Some(origin), None, None, None).is_err());
        }
        for origin in [
            "http://localhost:18083",
            "http://127.0.0.1:18083/",
            "https://network.scarlett.ai:18443",
            "https://192.0.2.1:18443",
            "https://localhost.evil.test:18443",
            "https://user:secret@localhost:18443",
            "https://localhost:18443/setup/",
            "https://localhost:18443/?next=evil",
            "https://localhost:18443/#evil",
            "https://localhost",
            "https://localhost:443",
            "ftp://localhost:18443",
        ] {
            assert!(Endpoints::resolve(true, Some(origin), None, None, Some(&ca)).is_err());
        }
        assert!(Endpoints::resolve(true, None, None, None, Some(&ca)).is_err());
        for invalid in [temp.path(), Path::new("relative.pem")] {
            assert!(
                Endpoints::resolve(
                    true,
                    Some("https://localhost:18443"),
                    None,
                    None,
                    Some(invalid)
                )
                .is_err()
            );
        }
    }
    #[cfg(unix)]
    #[test]
    fn local_verifier_requires_ca_and_never_enables_plaintext() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let ca = temp.path().join("local-ca.pem");
        std::fs::write(&ca, "synthetic CA fixture").unwrap();
        let link = temp.path().join("ca-link.pem");
        symlink(&ca, &link).unwrap();
        for verifier in ["127.0.0.1:17047", "[::1]:17047"] {
            assert!(Endpoints::resolve(true, None, Some(verifier), Some(&ca), None).is_ok());
        }
        assert!(Endpoints::resolve(true, None, Some("127.0.0.1:17047"), None, None).is_err());
        assert!(Endpoints::resolve(true, None, None, Some(&ca), None).is_err());
        for verifier in ["192.0.2.1:17047", "remote.example:17047", "127.0.0.1:443"] {
            assert!(Endpoints::resolve(true, None, Some(verifier), Some(&ca), None).is_err());
        }
        for invalid in [link.as_path(), temp.path(), Path::new("relative.pem")] {
            assert!(
                Endpoints::resolve(true, None, Some("127.0.0.1:17047"), Some(invalid), None)
                    .is_err()
            );
        }
        let binary = temp.path().join("node");
        std::fs::write(&binary, "synthetic node fixture").unwrap();
        let mut node = Node::new(
            temp.path().join("state"),
            binary,
            temp.path().join("helper"),
        );
        node.endpoints = Endpoints::resolve(
            true,
            Some("https://localhost:18443"),
            Some("127.0.0.1:17047"),
            Some(&ca),
            Some(&ca),
        )
        .unwrap();
        let command = node.command(&["status"]).unwrap();
        let env = command
            .as_std()
            .get_envs()
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(
            env.get(std::ffi::OsStr::new("SCARLETT_VERIFIER_CA_FILE")),
            Some(&Some(ca.as_os_str()))
        );
        assert_eq!(
            env.get(std::ffi::OsStr::new("SCARLETT_COORDINATOR_CA_FILE")),
            Some(&Some(ca.as_os_str()))
        );
        assert!(!env.contains_key(std::ffi::OsStr::new("SCARLETT_VERIFIER_PLAINTEXT_FIXTURE")));
        assert!(!env.contains_key(std::ffi::OsStr::new("SCARLETT_LOCAL_FIXTURE")));
        // Renewal covers exactly the app-owned login profiles new_codex_profile makes.
        let managed = temp.path().join("state").join("codex-logins");
        assert_eq!(
            env.get(std::ffi::OsStr::new("SCARLETT_CODEX_MANAGED_ROOT")),
            Some(&Some(managed.as_os_str()))
        );
        let state = temp.path().join("state");
        let state_text = state.to_str().unwrap();
        for unusable in [
            PathBuf::from("relative-state"),
            PathBuf::from(format!("{state_text}{0}{0}x", std::path::MAIN_SEPARATOR)),
            state.join(".").join("x"),
            state.join("..").join("x"),
            PathBuf::from(format!("{state_text}\nx")),
        ] {
            assert_eq!(managed_codex_root(&unusable), None, "{unusable:?}");
        }
        assert_eq!(
            node.network_url("setup").unwrap(),
            "https://localhost:18443/setup/"
        );
        assert_eq!(
            node.network_url("https://evil.test"),
            Err(Error::InvalidInput)
        );
    }
    #[test]
    fn identities_cannot_be_paths_or_shell_args() {
        for id in ["../x", "x/y", "x;echo", "UPPER", "legacy", ""] {
            assert!(!valid_id(id));
        }
        assert!(valid_id("work-2"));
    }
    /// The real built node helper. Windows creates private directories only
    /// through it, so Windows runs must supply it (desktop-complete does).
    /// Unix runs use it when supplied to cross-check the node's own checks.
    fn test_node_helper() -> Option<PathBuf> {
        let helper = std::env::var_os("SCARLETT_TEST_NODE_BINARY").map(PathBuf::from);
        assert!(
            cfg!(unix) || helper.is_some(),
            "set SCARLETT_TEST_NODE_BINARY to the built scarlett-node.exe"
        );
        helper
    }
    /// A private profile root, as connect_codex prepares `codex-logins`.
    fn profile_root(temp: &tempfile::TempDir) -> (PathBuf, PathBuf) {
        let helper = test_node_helper().unwrap_or_else(|| temp.path().join("unused-helper"));
        let profiles = temp.path().join("codex-logins");
        private_dir_with_helper(&profiles, &helper).unwrap();
        (profiles, helper)
    }
    /// An unprotected directory: inherited-only ACL on Windows (as the earlier
    /// DirBuilder reservation left it), group/other access on Unix.
    fn unprotected_dir(path: &Path) {
        std::fs::create_dir(path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    #[test]
    fn automatic_codex_profiles_preserve_registered_and_abandoned_names() {
        let temp = tempfile::tempdir().unwrap();
        let (profiles, helper) = profile_root(&temp);
        unprotected_dir(&profiles.join("codex-1"));
        std::fs::write(profiles.join("codex-2"), "retained synthetic file").unwrap();
        let accounts = vec![Account {
            id: "codex-3".into(),
            service: "codex".into(),
            concurrency: 1,
        }];
        let (id, home) =
            new_codex_profile(&profiles, &accounts, &helper, CODEX_PROFILE_NAMES).unwrap();
        assert_eq!(id, "codex-4");
        assert_eq!(home, profiles.join("codex-4"));
        assert!(home.is_dir());
        assert_eq!(private_dir_with_helper(&home, &helper), Ok(()));
        assert_eq!(
            std::fs::read_to_string(profiles.join("codex-2")).unwrap(),
            "retained synthetic file"
        );
        // An older unprotected reservation is skipped, never adopted or repaired.
        assert_eq!(
            private_dir_with_helper(&profiles.join("codex-1"), &helper),
            Err(Error::PrivateStorageUnavailable)
        );
        // A cancelled, empty profile remains reserved for that login.
        assert_eq!(
            new_codex_profile(&profiles, &accounts, &helper, CODEX_PROFILE_NAMES)
                .unwrap()
                .0,
            "codex-5"
        );
    }
    #[test]
    fn automatic_codex_profiles_reserve_distinct_homes_concurrently() {
        let temp = tempfile::tempdir().unwrap();
        let (profiles, helper) = profile_root(&temp);
        let mut ids = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        new_codex_profile(&profiles, &[], &helper, CODEX_PROFILE_NAMES)
                            .unwrap()
                            .0
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect::<Vec<_>>()
        });
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 8);
        assert!(
            ids.iter()
                .all(|id| valid_id(id)
                    && private_dir_with_helper(&profiles.join(id), &helper).is_ok())
        );
    }
    #[test]
    fn automatic_codex_profiles_enforce_pool_and_storage_limits() {
        let temp = tempfile::tempdir().unwrap();
        let (profiles, helper) = profile_root(&temp);
        let accounts: Vec<_> = (0..MAX_CODEX_ACCOUNTS)
            .map(|i| Account {
                id: format!("old-{i}"),
                service: "codex".into(),
                concurrency: 1,
            })
            .collect();
        assert_eq!(
            new_codex_profile(&profiles, &accounts, &helper, CODEX_PROFILE_NAMES),
            Err(Error::AccountLimit)
        );
        assert_eq!(std::fs::read_dir(&profiles).unwrap().count(), 0);
        // X accounts never count toward the Codex limit.
        let mut mixed = accounts[1..].to_vec();
        mixed.push(Account {
            id: "x-one".into(),
            service: "x_read".into(),
            concurrency: 1,
        });
        assert_eq!(
            new_codex_profile(&profiles, &mixed, &helper, CODEX_PROFILE_NAMES)
                .unwrap()
                .0,
            "codex-1"
        );
        // Exhausted candidate names report the same limit, not missing support.
        std::fs::write(profiles.join("codex-2"), "retained synthetic file").unwrap();
        assert_eq!(
            new_codex_profile(&profiles, &[], &helper, 2),
            Err(Error::AccountLimit)
        );
        assert_eq!(
            serde_json::to_string(&Error::AccountLimit).unwrap(),
            "\"account_limit\""
        );
        assert_eq!(
            new_codex_profile(&profiles.join("missing"), &[], &helper, CODEX_PROFILE_NAMES),
            Err(Error::PrivateStorageUnavailable)
        );
        assert!(!profiles.join("missing").exists());
    }
    #[cfg(unix)]
    #[test]
    fn automatic_codex_profiles_skip_links_and_are_private() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let temp = tempfile::tempdir().unwrap();
        symlink(
            temp.path().join("missing-target"),
            temp.path().join("codex-1"),
        )
        .unwrap();
        let (id, home) =
            new_codex_profile(temp.path(), &[], Path::new("unused"), CODEX_PROFILE_NAMES).unwrap();
        assert_eq!(id, "codex-2");
        assert_eq!(
            std::fs::metadata(home).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(
            std::fs::symlink_metadata(temp.path().join("codex-1"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
    // Regression for Windows Connect Codex: the reserved CODEX_HOME must pass the
    // node's own private-dir check, not only this bridge's view of it.
    #[test]
    fn codex_login_reservation_passes_the_real_node_private_storage_check() {
        let Some(helper) = test_node_helper() else {
            return;
        };
        let temp = tempfile::tempdir().unwrap();
        let node = Node::new(
            temp.path().join("state"),
            helper.clone(),
            temp.path().join("prover"),
        );
        node.prepare().unwrap();
        let ok = json!({"ok": true});
        let (id, home) = node.reserve_codex_login(&[]).unwrap();
        assert_eq!(id, "codex-1");
        assert_eq!(home, node.state.join("codex-logins").join("codex-1"));
        assert_eq!(
            private_helper(&helper, "private-dir", &home),
            Ok(ok.clone())
        );
        let orphan = node.state.join("codex-logins").join("codex-2");
        unprotected_dir(&orphan);
        assert_eq!(
            private_helper(&helper, "private-dir", &orphan),
            Err(Error::PrivateStorageUnavailable)
        );
        let (id, home) = node.reserve_codex_login(&[]).unwrap();
        assert_eq!(id, "codex-3");
        assert_eq!(private_helper(&helper, "private-dir", &home), Ok(ok));
        assert_eq!(
            private_helper(&helper, "private-dir", &orphan),
            Err(Error::PrivateStorageUnavailable)
        );
        // The helper itself reports a taken name instead of failing.
        assert_eq!(
            private_helper(&helper, "private-dir-new", &home),
            Ok(json!({"status": "exists"}))
        );
    }
    #[test]
    fn projection_drops_secret_paths_and_unknown_fields() {
        let raw=br#"[{"id":"work","service":"codex","concurrency":1,"path":"SECRET_PATH","token":"SECRET"}]"#;
        let safe = serde_json::to_string(&account_projection(raw).unwrap()).unwrap();
        assert!(!safe.contains("SECRET"));
        let status=observation_projection(br#"{"state":"running","credential":"SECRET","services":[{"type":"x_read","state":"configured","token":"SECRET"}],"accounts":[{"id":"work","service":"codex","path":"SECRET"}]}"#).unwrap();
        assert!(!status.to_string().contains("SECRET"));
    }
    #[test]
    fn projection_keeps_relay_state_and_only_known_proof_modes() {
        let status = observation_projection(
            br#"{"state":"running","relay_halted":true,"services":[{"kind":"x_read","state":"configured","capacity":1,"proof_modes":["mpc","relay","SECRET"],"models":["SECRET"]},{"kind":"codex","state":"ready","proof_modes":"SECRET"}],"accounts":[{"id":"one","service":"x_read","state":"auth_required","last_error_code":"auth_required","path":"SECRET"}]}"#,
        )
        .unwrap();
        assert!(!status.to_string().contains("SECRET"));
        assert_eq!(status["relay_halted"], json!(true));
        assert_eq!(status["services"][0]["kind"], json!("x_read"));
        assert_eq!(status["services"][0]["state"], json!("configured"));
        assert_eq!(
            status["services"][0]["proof_modes"],
            json!(["mpc", "relay"])
        );
        assert!(status["services"][1].get("proof_modes").is_none());
        assert_eq!(status["accounts"][0]["state"], json!("auth_required"));
        assert_eq!(
            status["accounts"][0]["last_error_code"],
            json!("auth_required")
        );
        let unhalted = observation_projection(br#"{"state":"running","services":[]}"#).unwrap();
        assert!(unhalted.get("relay_halted").is_none());
    }
    /// A fake bundled node that records each invocation and serves a halted,
    /// running status. `relay-resume` removes the marker unless told not to.
    #[cfg(unix)]
    fn relay_fixture(temp: &tempfile::TempDir) -> Node {
        use std::os::unix::fs::PermissionsExt;
        let binary = temp.path().join("node");
        let script = r##"#!/bin/sh
printf '%s\n' "$*" >> "$SCARLETT_STATE_DIR/calls"
case "$1 $2" in
'accounts list') printf '[{"id":"one","service":"x_read","concurrency":1}]';;
'desktop run') cat >/dev/null;;
'drain ') ;;
'status ') printf '{"state":"running","relay_halted":true,"services":[{"kind":"x_read","state":"ready","proof_modes":["mpc"]}]}';;
'relay-resume ') [ -e "$SCARLETT_STATE_DIR/keep-halt" ] || rm -f "$SCARLETT_STATE_DIR/relay-halt"; printf '{"state":"running"}';;
*) exit 1;;
esac
"##;
        std::fs::write(&binary, script).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let helper = temp.path().join("helper");
        std::fs::write(&helper, "synthetic helper fixture").unwrap();
        let node = Node::new(temp.path().join("state"), binary, helper);
        node.prepare().unwrap();
        std::fs::write(node.state.join("identity.json"), "{}").unwrap();
        node
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn relay_resume_runs_only_the_bundled_command_and_never_restarts_the_node() {
        let temp = tempfile::tempdir().unwrap();
        let node = relay_fixture(&temp);
        let marker = node.state.join(RELAY_HALT_FILE);
        std::fs::write(&marker, "verifier misused this node's X session\n").unwrap();
        node.start().await.unwrap();
        let calls = node.state.join("calls");
        let began = Instant::now();
        while !std::fs::read_to_string(&calls).is_ok_and(|c| c.contains("desktop run")) {
            assert!(began.elapsed() < Duration::from_secs(5));
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let halted = node.snapshot().await;
        assert!(halted.supervised && halted.relay_halt_marker);
        assert_eq!(halted.observation.unwrap()["relay_halted"], json!(true));
        // The fixed bundled binary with a cleared environment: never PATH.
        let command = node.command(&["relay-resume"]).unwrap();
        assert_eq!(command.as_std().get_program(), node.binary.as_os_str());
        assert!(
            !command
                .as_std()
                .get_envs()
                .any(|(name, _)| name == std::ffi::OsStr::new("PATH"))
        );
        std::fs::write(node.state.join("calls"), "").unwrap();
        node.resume_relay().await.unwrap();
        assert!(!marker.exists());
        assert_eq!(
            std::fs::read_to_string(node.state.join("calls")).unwrap(),
            "relay-resume\n"
        );
        // The supervised node keeps running; it picks the change up itself, so
        // the status may still say halted while the saved halt is gone.
        let pending = node.snapshot().await;
        assert!(pending.supervised);
        assert!(!pending.relay_halt_marker);
        assert_eq!(pending.observation.unwrap()["relay_halted"], json!(true));
        assert!(
            !std::fs::read_to_string(node.state.join("calls"))
                .unwrap()
                .lines()
                .any(|call| call == "drain" || call.starts_with("desktop"))
        );
        // A marker the command did not remove is reported, not assumed gone.
        std::fs::write(&marker, "verifier misused this node's X session\n").unwrap();
        std::fs::write(node.state.join("keep-halt"), "").unwrap();
        assert_eq!(node.resume_relay().await, Err(Error::CommandFailed));
        assert!(node.snapshot().await.relay_halt_marker);
        node.stop().await.unwrap();
    }
    #[tokio::test]
    async fn relay_resume_clears_the_real_node_marker_and_is_repeatable() {
        let Some(binary) = test_node_helper() else {
            return;
        };
        let temp = tempfile::tempdir().unwrap();
        let node = Node::new(
            temp.path().join("state"),
            binary,
            temp.path().join("prover"),
        );
        node.prepare().unwrap();
        let marker = node.state.join(RELAY_HALT_FILE);
        std::fs::write(&marker, "verifier misused this node's X session\n").unwrap();
        assert!(node.snapshot().await.relay_halt_marker);
        node.resume_relay().await.unwrap();
        assert!(!marker.exists());
        assert!(!node.snapshot().await.relay_halt_marker);
        node.resume_relay().await.unwrap();
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn x_reimport_replaces_only_a_registered_account_through_fixed_commands() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("node");
        let script = r##"#!/bin/sh
case "$1 $2" in
'accounts list') printf '[{"id":"one","service":"x_read","concurrency":2},{"id":"work","service":"codex","concurrency":1}]';;
'accounts reconnect') cat > "$SCARLETT_STATE_DIR/captured.json"; printf '%s\n' "$@" > "$SCARLETT_STATE_DIR/args"; printf '{"status":"updated"}';;
'accounts reimport-x') printf '%s\n' "$@" > "$SCARLETT_STATE_DIR/args"; printf 'synthetic-private-provider-error' >&2; printf '{"status":"error","code":"browser_busy"}'; exit 1;;
*) exit 1;;
esac
"##;
        std::fs::write(&binary, script).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let node = Node::new(
            temp.path().join("state"),
            binary,
            temp.path().join("helper"),
        );
        node.reconnect_x(
            "one".into(),
            "synthetic_token".into(),
            "synthetic_ct0".into(),
        )
        .await
        .unwrap();
        let args = std::fs::read_to_string(node.state.join("args")).unwrap();
        assert_eq!(args, "accounts\nreconnect\nx_read\none\n");
        let input: Value =
            serde_json::from_slice(&std::fs::read(node.state.join("captured.json")).unwrap())
                .unwrap();
        assert_eq!(
            input,
            json!({"auth_token":"synthetic_token","ct0":"synthetic_ct0"})
        );
        std::fs::remove_file(node.state.join("args")).unwrap();
        // Unknown, Codex and malformed IDs never reach the node's write path.
        for id in ["missing", "work", "../one"] {
            assert_eq!(
                node.reconnect_x(id.into(), "token".into(), "csrf".into())
                    .await,
                Err(Error::InvalidInput)
            );
        }
        assert_eq!(
            node.reconnect_x("one".into(), "bad;token".into(), "csrf".into())
                .await,
            Err(Error::InvalidInput)
        );
        assert!(!node.state.join("args").exists());
        let profile = "firefox_0123456789abcdef0123456789abcdef";
        assert_eq!(
            node.reimport_x(profile.into(), "one".into()).await,
            Err(Error::BrowserBusy)
        );
        assert_eq!(
            std::fs::read_to_string(node.state.join("args")).unwrap(),
            format!("accounts\nreimport-x\n{profile}\none\n")
        );
        assert_eq!(
            node.reimport_x("/private/arbitrary-path".into(), "one".into())
                .await,
            Err(Error::InvalidInput)
        );
        assert_eq!(
            node.reimport_x(profile.into(), "missing".into()).await,
            Err(Error::InvalidInput)
        );
    }
    #[tokio::test]
    async fn x_reconnect_replaces_the_real_node_session_for_the_same_id() {
        let Some(binary) = test_node_helper() else {
            return;
        };
        let temp = tempfile::tempdir().unwrap();
        let node = Node::new(
            temp.path().join("state"),
            binary,
            temp.path().join("prover"),
        );
        node.connect_x(
            "one".into(),
            2,
            "synthetic-expired-auth".into(),
            "synthetic-expired-csrf".into(),
        )
        .await
        .unwrap();
        node.reconnect_x(
            "one".into(),
            "synthetic-fresh-auth".into(),
            "synthetic-fresh-csrf".into(),
        )
        .await
        .unwrap();
        let accounts = node.accounts().await.unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].concurrency, 2);
        assert_eq!(
            node.reconnect_x("two".into(), "synthetic-a".into(), "synthetic-b".into())
                .await,
            Err(Error::InvalidInput)
        );
        let session = std::fs::read_to_string(
            node.state
                .join("accounts")
                .join("x_read-one")
                .join("session.json"),
        )
        .unwrap();
        assert!(session.contains("synthetic-fresh-auth") && !session.contains("synthetic-expired"));
    }
    #[test]
    fn unrecognized_registry_is_not_mocked_ready() {
        assert!(account_projection(br#"{"status":"updated"}"#).is_err());
        assert!(
            account_projection(br#"[{"id":"../x","service":"codex","concurrency":1}]"#).is_err()
        );
    }
    #[cfg(unix)]
    #[test]
    fn private_storage_refuses_links_and_shared_permissions() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = tempfile::tempdir().unwrap();
        let p = root.path().join("state");
        private_dir(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(private_dir(&p), Err(Error::PrivateStorageUnavailable));
        let q = root.path().join("link");
        symlink(&p, &q).unwrap();
        assert_eq!(private_dir(&q), Err(Error::PrivateStorageUnavailable));
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn codex_connect_assigns_profiles_and_cancellation_never_reuses_them() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("node");
        std::fs::write(
            &binary,
            "#!/bin/sh\n[ \"$1 $2\" = 'accounts list' ] || exit 1\nprintf '[]'\n",
        )
        .unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let resources = temp.path().join("resources");
        let cli = resources.join("runtime/codex/bin/codex");
        std::fs::create_dir_all(cli.parent().unwrap()).unwrap();
        std::fs::write(&cli, "#!/bin/sh\nif [ \"$1\" = '--version' ]; then printf 'codex-cli 0.159.2\\n'; exit 0; fi\n[ \"$1\" = '-c' ] && [ \"$2\" = 'cli_auth_credentials_store=\"file\"' ] && [ \"$3\" = 'login' ] || exit 1\nexec /bin/sleep 30\n").unwrap();
        std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o700)).unwrap();
        let node = Node::new(
            temp.path().join("state"),
            binary,
            temp.path().join("helper"),
        )
        .with_provider_runtime(&resources);
        node.connect_codex(1).await.unwrap();
        {
            let login = node.login.lock().await;
            let pending = login.as_ref().unwrap();
            assert_eq!(pending.id, "codex-1");
            assert_eq!(pending.concurrency, 1);
            assert_eq!(pending.home, node.state.join("codex-logins/codex-1"));
        }
        assert_eq!(node.connect_codex(1).await, Err(Error::LoginBusy));
        assert!(!node.state.join("codex-logins/codex-2").exists());
        node.cancel_login().await.unwrap();
        node.connect_codex(1).await.unwrap();
        assert_eq!(node.login.lock().await.as_ref().unwrap().id, "codex-2");
        node.cancel_login().await.unwrap();
        assert!(node.state.join("codex-logins/codex-1").is_dir());
        assert!(node.state.join("codex-logins/codex-2").is_dir());
        assert!(node.login.lock().await.is_none());
        assert!(node.accounts().await.unwrap().is_empty());
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn codex_login_uses_only_the_fixed_bundled_native_runtime() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let bundled = temp.path().join("resources/runtime/codex/bin/codex");
        std::fs::create_dir_all(bundled.parent().unwrap()).unwrap();
        // Even a compatible sibling outside the fixed resource layout is ignored.
        let sibling = temp.path().join("codex");
        std::fs::write(&sibling, "#!/bin/sh\nprintf 'codex-cli 0.159.2\\n'\n").unwrap();
        std::fs::set_permissions(&sibling, std::fs::Permissions::from_mode(0o700)).unwrap();
        let node = Node::new(
            temp.path().join("state"),
            temp.path().join("node"),
            temp.path().join("helper"),
        )
        .with_provider_runtime(&temp.path().join("resources"));
        assert!(node.codex_cli().await.is_none());
        std::fs::write(&bundled, "#!/bin/sh\nprintf 'codex-cli 0.154.0\\n'\n").unwrap();
        std::fs::set_permissions(&bundled, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(node.codex_cli().await.is_none());
        std::fs::write(&bundled, "#!/bin/sh\n[ \"$CODEX_HOME\" = \"$HOME/runtime-probe\" ] || exit 1\nprintf 'codex-cli 0.159.2\\n'\n").unwrap();
        assert_eq!(
            node.codex_cli().await,
            Some(bundled.canonicalize().unwrap())
        );
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn secrets_use_stdin_and_account_support_is_real() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let binary = tmp.path().join("node");
        let script = "#!/bin/sh\ncase \"$1 $2\" in\n'accounts list') printf '[]';;\n'accounts connect') cat > \"$SCARLETT_STATE_DIR/captured.json\"; printf '%s\\n' \"$@\" > \"$SCARLETT_STATE_DIR/args\"; printf '{\"status\":\"updated\"}';;\n*) exit 1;;\nesac\n";
        std::fs::write(&binary, script).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let node = Node::new(tmp.path().join("state"), binary, tmp.path().join("helper"));
        node.connect_x(
            "one".into(),
            1,
            "synthetic_token".into(),
            "synthetic_ct0".into(),
        )
        .await
        .unwrap();
        let args = std::fs::read_to_string(node.state.join("args")).unwrap();
        assert_eq!(args, "accounts\nconnect\nx_read\none\n1\n");
        assert!(!args.contains("synthetic"));
        let input: Value =
            serde_json::from_slice(&std::fs::read(node.state.join("captured.json")).unwrap())
                .unwrap();
        assert_eq!(
            input,
            json!({"auth_token":"synthetic_token","ct0":"synthetic_ct0"})
        );
        assert_eq!(
            node.connect_x("../x".into(), 1, "token".into(), "csrf".into())
                .await,
            Err(Error::InvalidInput)
        );
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn browser_import_delegates_only_ids_and_projects_fixed_nonzero_failure() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("node");
        let script = r##"#!/bin/sh
case "$1 $2" in
'accounts list') printf '[]';;
'accounts browser-profiles') printf '[{"id":"firefox_0123456789abcdef0123456789abcdef","browser":"firefox","label":"Firefox / Isolated"}]';;
'accounts import-x') printf '%s\n' "$@" > "$SCARLETT_STATE_DIR/args"; printf 'synthetic-private-provider-error' >&2; printf '{"status":"error","code":"browser_busy"}'; exit 1;;
*) exit 1;;
esac
"##;
        std::fs::write(&binary, script).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let node = Node::new(
            temp.path().join("state"),
            binary,
            temp.path().join("helper"),
        );
        let profiles = node.browser_profiles().await.unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(
            node.import_x(profiles[0].id.clone(), "browser-one".into(), 2)
                .await,
            Err(Error::BrowserBusy)
        );
        let args = std::fs::read_to_string(node.state.join("args")).unwrap();
        assert_eq!(
            args,
            "accounts\nimport-x\nfirefox_0123456789abcdef0123456789abcdef\nbrowser-one\n2\n"
        );
        assert_eq!(
            node.import_x("/private/arbitrary-path".into(), "one".into(), 1)
                .await,
            Err(Error::InvalidInput)
        );
        assert_eq!(
            std::fs::read_to_string(node.state.join("args")).unwrap(),
            args
        );
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn failed_pairing_is_not_retried_or_returned_raw() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("node");
        std::fs::write(&binary, "#!/bin/sh\ncat > \"$SCARLETT_STATE_DIR/pair-input\"\nprintf 'attempt\\n' >> \"$SCARLETT_STATE_DIR/attempts\"\nprintf 'SECRET_RAW_PROVIDER_OUTPUT'\nexit 1\n").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let node = Node::new(
            temp.path().join("state"),
            binary,
            temp.path().join("helper"),
        );
        let code = "a".repeat(64);
        assert_eq!(node.pair(code.clone()).await, Err(Error::CommandFailed));
        assert_eq!(
            std::fs::read_to_string(node.state.join("attempts")).unwrap(),
            "attempt\n"
        );
        assert_eq!(
            std::fs::read_to_string(node.state.join("pair-input")).unwrap(),
            format!("{code}\n")
        );
        assert_eq!(
            serde_json::to_string(&Error::CommandFailed).unwrap(),
            "\"command_failed\""
        );
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn supervised_runtime_requires_dependencies_and_drains_before_stop() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("node");
        let helper = temp.path().join("helper");
        std::fs::write(&binary, "#!/bin/sh\ncase \"$1 $2\" in\n'accounts list') printf '[{\"id\":\"work\",\"service\":\"codex\",\"concurrency\":1}]';;\n'desktop run') cat >/dev/null;;\n'drain ') printf 'drained' > \"$SCARLETT_STATE_DIR/drain-observed\";;\n*) exit 1;;\nesac\n").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let node = Node::new(temp.path().join("state"), binary, helper.clone());
        assert_eq!(node.start().await, Err(Error::NotPaired));
        node.prepare().unwrap();
        std::fs::write(node.state.join("identity.json"), "{}").unwrap();
        assert_eq!(node.start().await, Err(Error::RuntimeUnavailable));
        std::fs::write(&helper, "synthetic helper fixture").unwrap();
        node.start().await.unwrap();
        assert_eq!(node.start().await, Err(Error::AlreadyRunning));
        let began = Instant::now();
        node.stop().await.unwrap();
        assert!(began.elapsed() < Duration::from_secs(5));
        assert!(node.running.lock().await.is_none());
        assert_eq!(
            std::fs::read_to_string(node.state.join("drain-observed")).unwrap(),
            "drained"
        );
        assert_eq!(
            node.control("shell-command").await,
            Err(Error::InvalidInput)
        );
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_and_oversized_stdout_are_bounded() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let binary = temp.path().join("node");
        std::fs::write(&binary, "#!/bin/sh\ncase \"$1\" in slow) exec sleep 10;; large) head -c 40000 /dev/zero;; esac\n").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let node = Node::new(
            temp.path().join("state"),
            binary,
            temp.path().join("helper"),
        );
        let start = Instant::now();
        assert_eq!(
            node.call(&["slow"], None, 1).await,
            Err(Error::CommandTimeout)
        );
        assert!(start.elapsed() < Duration::from_secs(3));
        assert_eq!(
            node.call(&["large"], None, 2).await,
            Err(Error::CommandFailed)
        );
    }
}
