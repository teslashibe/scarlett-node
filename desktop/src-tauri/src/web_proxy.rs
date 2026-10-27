//! The operator's own web proxy (Webshare, United States), for web pages only.
//! Its username and password live in one OS credential store item and reach
//! the node only on the start line the app writes to its stdin, never through
//! the environment, the command line, a file or the renderer. The non-secret
//! choices (on or off, which pages, the port) are device preferences.
use crate::{
    node::{Error, Node, Result},
    preferences::Preferences,
};
use serde::{Deserialize, Serialize};
use std::{net::Ipv4Addr, sync::Arc};

/// The one credential store item, holding `{"username","password"}`.
pub const SERVICE: &str = "Scarlett Node";
pub const ACCOUNT: &str = "web-egress-proxy";
/// The ports Webshare documents for username and password sign-in.
pub const PORTS: [u16; 3] = [80, 1080, 3128];
/// The longest start line `desktop run` reads, newline included.
pub const START_LINE_LIMIT: usize = 4096;
/// Webshare proxy passwords are short; this bounds what the app stores and
/// sends, well inside the start line.
const PASSWORD_MAX: usize = 128;

/// Which web pages use the proxy: only sites that limit this network (the
/// node's `both` egress) or every page (`proxy`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Use {
    LimitedSites,
    All,
}
impl Use {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "limited_sites" => Some(Self::LimitedSites),
            "all" => Some(Self::All),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LimitedSites => "limited_sites",
            Self::All => "all",
        }
    }
}

/// The saved, non-secret proxy choice for the next node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Route {
    #[serde(rename = "use")]
    pub pages: Use,
    pub port: u16,
}
impl Route {
    pub fn new(pages: &str, port: u16) -> Result<Self> {
        let pages = Use::parse(pages).ok_or(Error::InvalidInput)?;
        if !PORTS.contains(&port) {
            return Err(Error::InvalidInput);
        }
        Ok(Self { pages, port })
    }
}

/// The Webshare proxy username and password. Debug never shows either, and
/// both are overwritten when dropped.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    username: String,
    password: String,
}
impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credentials { username: [redacted], password: [redacted] }")
    }
}
impl Drop for Credentials {
    fn drop(&mut self) {
        for secret in [&mut self.username, &mut self.password] {
            let mut bytes = std::mem::take(secret).into_bytes();
            bytes.fill(0);
            std::hint::black_box(&bytes);
        }
    }
}
impl Credentials {
    /// The username is Webshare's base username, `[A-Za-z0-9]{1,32}`; the
    /// node adds the country and a session per job. The password is printable
    /// ASCII without spaces.
    pub fn new(username: String, password: String) -> Result<Self> {
        let credentials = Self { username, password };
        if !credentials.valid() {
            return Err(Error::InvalidInput);
        }
        Ok(credentials)
    }
    fn valid(&self) -> bool {
        (1..=32).contains(&self.username.len())
            && self.username.bytes().all(|b| b.is_ascii_alphanumeric())
            && (1..=PASSWORD_MAX).contains(&self.password.len())
            && self.password.bytes().all(|b| b.is_ascii_graphic())
    }
    /// Enough of the username to recognize the saved account: its first
    /// characters (at most three, never more than half), then a mask.
    pub fn masked_username(&self) -> String {
        let shown = (self.username.len() / 2).min(3);
        format!("{}••••", &self.username[..shown])
    }
}

/// The proxy object the node reads: inside the start line under
/// `web_egress_proxy`, and alone on `desktop proxy-test`'s stdin.
#[derive(Serialize)]
struct Proxy<'a> {
    provider: &'static str,
    username: &'a str,
    password: &'a str,
    country: &'static str,
    port: u16,
    #[serde(rename = "use")]
    pages: &'static str,
}
fn proxy<'a>(credentials: &'a Credentials, route: Route) -> Proxy<'a> {
    Proxy {
        provider: "webshare",
        username: &credentials.username,
        password: &credentials.password,
        country: "us",
        port: route.port,
        pages: route.pages.as_str(),
    }
}

/// Bytes holding the credentials: the start line, the test input and the
/// keychain item. Like Credentials they are overwritten when dropped, on
/// every path, and Debug never shows them.
pub struct Secret(Vec<u8>);
impl Secret {
    /// Room for any line this module writes, so writing never regrows the
    /// buffer and leaves a copy behind in a freed allocation.
    fn new() -> Self {
        Self(Vec::with_capacity(START_LINE_LIMIT + 1))
    }
}
impl std::ops::Deref for Secret {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret([redacted])")
    }
}
impl Drop for Secret {
    fn drop(&mut self) {
        self.0.fill(0);
        std::hint::black_box(&self.0);
    }
}

/// `desktop proxy-test`'s stdin: the proxy object and a newline.
pub fn test_input(credentials: &Credentials, route: Route) -> Result<Secret> {
    let mut raw = Secret::new();
    serde_json::to_writer(&mut raw.0, &proxy(credentials, route))
        .map_err(|_| Error::InvalidInput)?;
    raw.0.push(b'\n');
    Ok(raw)
}

/// The one line the app writes to `desktop run` before any owner command:
/// the proxy for this node, or `{}` without one. The app always sends it.
pub fn start_line(web_proxy: Option<(&Credentials, Route)>) -> Result<Secret> {
    #[derive(Serialize)]
    struct Line<'a> {
        web_egress_proxy: Proxy<'a>,
    }
    let mut raw = Secret::new();
    match web_proxy {
        Some((credentials, route)) => serde_json::to_writer(
            &mut raw.0,
            &Line {
                web_egress_proxy: proxy(credentials, route),
            },
        )
        .map_err(|_| Error::InvalidInput)?,
        None => raw.0.extend_from_slice(b"{}"),
    }
    raw.0.push(b'\n');
    if raw.len() > START_LINE_LIMIT {
        return Err(Error::InvalidInput);
    }
    Ok(raw)
}

/// What `desktop proxy-test` found: the exit IP on success, else one of the
/// node's failure classes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TestResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
}
impl TestResult {
    pub fn failed(class: &str) -> Self {
        Self {
            ok: false,
            exit: None,
            class: Some(class.into()),
        }
    }
}
/// The failure classes `desktop proxy-test` prints.
const TEST_CLASSES: [&str; 7] = [
    "proxy_unreachable",
    "proxy_auth",
    "proxy_quota",
    "proxy_busy",
    "proxy_refused",
    "proxy_exit",
    "invalid",
];
/// `{"ok":true,"exit":"<ipv4>"}` or `{"ok":false,"class":"<class>"}`, and
/// nothing else: anything more is refused rather than shown.
pub fn test_projection(raw: &[u8]) -> Result<TestResult> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reply {
        ok: bool,
        exit: Option<String>,
        class: Option<String>,
    }
    let reply: Reply = serde_json::from_slice(raw).map_err(|_| Error::CommandFailed)?;
    match (reply.ok, reply.exit, reply.class) {
        (true, Some(exit), None) => Ok(TestResult {
            ok: true,
            exit: Some(public_ipv4(&exit).ok_or(Error::CommandFailed)?.to_string()),
            class: None,
        }),
        (false, None, Some(class)) if TEST_CLASSES.contains(&class.as_str()) => {
            Ok(TestResult::failed(&class))
        }
        _ => Err(Error::CommandFailed),
    }
}

/// A public IPv4 address in its canonical form: not private, CGNAT,
/// loopback, link-local, documentation, benchmarking, multicast or reserved,
/// as the coordinator accepts exits.
pub fn public_ipv4(value: &str) -> Option<Ipv4Addr> {
    let ip: Ipv4Addr = value.parse().ok()?;
    let [a, b, c, _] = ip.octets();
    let reserved = a == 0
        || ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_documentation()
        || ip.is_multicast()
        || a >= 240
        || (a == 100 && (64..128).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (b == 18 || b == 19));
    (!reserved && ip.to_string() == value).then_some(ip)
}

/// The OS credential store: the macOS Keychain, Windows Credential Manager or
/// the Linux Secret Service. Tests use keyring's in-memory mock store, so they
/// never touch the device's own.
pub struct Keychain {
    store: Option<Arc<keyring_core::CredentialStore>>,
}
impl Keychain {
    pub fn native() -> Self {
        Self { store: None }
    }
    #[cfg(test)]
    pub fn mock() -> Self {
        Self {
            store: Some(keyring_core::mock::Store::new().unwrap()),
        }
    }
    /// Makes the next call on the mock item fail as a locked store would.
    #[cfg(test)]
    pub fn fail_next(&self) {
        let entry = self.entry().unwrap();
        let mock: &keyring_core::mock::Cred = entry.as_any().downcast_ref().unwrap();
        mock.set_error(keyring_core::Error::NoStorageAccess("locked".into()));
    }
    /// The store's name as the operator's OS shows it.
    pub fn name() -> &'static str {
        if cfg!(target_os = "macos") {
            "Keychain"
        } else if cfg!(windows) {
            "Credential Manager"
        } else {
            "Secret Service"
        }
    }
    fn entry(&self) -> keyring_core::Result<keyring_core::Entry> {
        match &self.store {
            Some(store) => store.build(SERVICE, ACCOUNT, None),
            None => keyring::Entry::new(SERVICE, ACCOUNT).map(|entry| entry.inner),
        }
    }
    pub fn save(&self, credentials: &Credentials) -> Result<()> {
        let mut raw = Secret::new();
        serde_json::to_writer(&mut raw.0, credentials).map_err(|_| Error::InvalidInput)?;
        self.entry()
            .and_then(|entry| entry.set_secret(&raw))
            .map_err(|_| Error::KeychainUnavailable)
    }
    /// The saved credentials, or none. An item that is not what this app
    /// saves fails closed; Remove deletes it.
    pub fn load(&self) -> Result<Option<Credentials>> {
        let raw = match self.entry().and_then(|entry| entry.get_secret()) {
            Ok(raw) => Secret(raw),
            Err(keyring_core::Error::NoEntry) => return Ok(None),
            Err(_) => return Err(Error::KeychainUnavailable),
        };
        serde_json::from_slice::<Credentials>(&raw)
            .ok()
            .filter(Credentials::valid)
            .map(Some)
            .ok_or(Error::KeychainUnavailable)
    }
    /// Removes the item; removing an absent one succeeds.
    pub fn delete(&self) -> Result<()> {
        match self.entry().and_then(|entry| entry.delete_credential()) {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(_) => Err(Error::KeychainUnavailable),
        }
    }
}

/// What the settings page may know about the saved proxy: whether one is
/// saved, a masked username and the store's name. Never the password.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Saved {
    pub saved: bool,
    pub username: Option<String>,
    pub store: &'static str,
}
impl Saved {
    pub fn of(credentials: Option<&Credentials>) -> Self {
        Self {
            saved: credentials.is_some(),
            username: credentials.map(Credentials::masked_username),
            store: Keychain::name(),
        }
    }
}

/// What the settings page sends to save or test the proxy. Leaving both the
/// username and the password empty keeps the saved ones, since the page is
/// never given them back.
pub struct Form {
    pub enabled: bool,
    pub route: Route,
    pub username: String,
    pub password: String,
}
impl Form {
    /// New credentials from the form, or none to use the saved ones.
    fn credentials(&mut self) -> Result<Option<Credentials>> {
        let username = std::mem::take(&mut self.username);
        let password = std::mem::take(&mut self.password);
        match (username.is_empty(), password.is_empty()) {
            (true, true) => Ok(None),
            (false, false) => Credentials::new(username, password).map(Some),
            _ => {
                drop(Secret(password.into_bytes()));
                Err(Error::InvalidInput)
            }
        }
    }
}

/// What Save did: the saved credentials as the page may see them, whether
/// the proxy is now on, and the test it ran first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SaveResult {
    #[serde(flatten)]
    pub saved: Saved,
    pub enabled: bool,
    pub test: Option<TestResult>,
}

pub async fn saved(node: &Node) -> Result<Saved> {
    Ok(Saved::of(node.web_proxy_credentials().await?.as_ref()))
}

/// Test runs one probe with the form's credentials, or the saved ones, and
/// saves nothing.
pub async fn test(node: &Node, mut form: Form) -> Result<TestResult> {
    let credentials = match form.credentials()? {
        Some(credentials) => credentials,
        None => node
            .web_proxy_credentials()
            .await?
            .ok_or(Error::WebProxyNotSaved)?,
    };
    node.test_web_proxy(&credentials, form.route).await
}

/// Save keeps new credentials in the keychain first. With the switch on it
/// then runs Test, and only a passing test turns the proxy on: after a
/// failed one (or a test that could not run) the credentials stay saved and
/// the switch is saved off. The change applies when the node next starts.
pub async fn save(
    node: &Node,
    preferences: &Preferences,
    runtime: &tokio::sync::Mutex<()>,
    mut form: Form,
) -> Result<SaveResult> {
    let credentials = match form.credentials()? {
        Some(credentials) => {
            node.save_web_proxy_credentials(&credentials).await?;
            Some(credentials)
        }
        None => node.web_proxy_credentials().await?,
    };
    let test = match (&credentials, form.enabled) {
        (Some(credentials), true) => Some(node.test_web_proxy(credentials, form.route).await),
        (None, true) => Some(Err(Error::WebProxyNotSaved)),
        (_, false) => None,
    };
    let enabled = matches!(&test, Some(Ok(result)) if result.ok);
    {
        let _guard = runtime.lock().await;
        let mut data = preferences.snapshot()?;
        data.web_proxy = enabled;
        data.web_proxy_use = form.route.pages.as_str().into();
        data.web_proxy_port = form.route.port;
        node.save_preferences(&data).await?;
        node.set_web_proxy(data.web_proxy_route());
        preferences.updated(data)?;
    }
    Ok(SaveResult {
        saved: Saved::of(credentials.as_ref()),
        enabled,
        test: test.transpose()?,
    })
}

/// Remove turns the proxy off, then deletes the keychain item, so no node
/// start ever looks for an item that is gone.
pub async fn remove(
    node: &Node,
    preferences: &Preferences,
    runtime: &tokio::sync::Mutex<()>,
) -> Result<()> {
    {
        let _guard = runtime.lock().await;
        let mut data = preferences.snapshot()?;
        if data.web_proxy {
            data.web_proxy = false;
            node.save_preferences(&data).await?;
            preferences.updated(data)?;
        }
        node.set_web_proxy(None);
    }
    node.delete_web_proxy_credentials().await
}

#[cfg(test)]
mod tests {
    use super::*;
    fn synthetic() -> Credentials {
        Credentials::new("synthuser".into(), "synthetic-pass".into()).unwrap()
    }
    fn form(enabled: bool, pages: &str, port: u16, username: &str, password: &str) -> Form {
        Form {
            enabled,
            route: Route::new(pages, port).unwrap(),
            username: username.into(),
            password: password.into(),
        }
    }
    /// A fake bundled node: its preferences helper echoes what it saves, and
    /// `desktop proxy-test` records its stdin and environment and answers
    /// with `proxy-reply`. The keychain is the in-memory mock.
    #[cfg(unix)]
    fn fixture(temp: &tempfile::TempDir) -> (Node, Preferences, tokio::sync::Mutex<()>) {
        use std::os::unix::fs::PermissionsExt;
        let binary = temp.path().join("node");
        std::fs::write(
            &binary,
            r##"#!/bin/sh
case "$1 $2" in
'desktop preferences-get') printf '%s' '{"schema":1,"local_api_port":8088,"background":false,"x_concurrency":2,"updates":"notify","resume_serving":false,"serve_web":true,"web_concurrency":0,"web_browser_concurrency":0,"web_proxy":false,"web_proxy_use":"limited_sites","web_proxy_port":80}';;
'desktop preferences-set') [ -e "$SCARLETT_STATE_DIR/fail-save" ] && exit 1; cat;;
'desktop proxy-test')
  printf '%s\n' "$*" >> "$SCARLETT_STATE_DIR/calls"
  cat >> "$SCARLETT_STATE_DIR/proxy-input"
  env >> "$SCARLETT_STATE_DIR/env"
  cat "$SCARLETT_STATE_DIR/proxy-reply";;
*) exit 1;;
esac
"##,
        )
        .unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let state = temp.path().join("state");
        crate::node::private_dir_with_helper(&state, &binary).unwrap();
        let preferences = Preferences::load(&state, &binary).unwrap();
        let node =
            Node::new(state, binary, temp.path().join("helper")).with_keychain(Keychain::mock());
        (node, preferences, tokio::sync::Mutex::new(()))
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn save_runs_the_test_first_and_a_failed_test_leaves_the_proxy_off() {
        let temp = tempfile::tempdir().unwrap();
        let (node, preferences, runtime) = fixture(&temp);
        let read = |name: &str| std::fs::read_to_string(node.state.join(name)).unwrap_or_default();
        let reply = |raw: &str| std::fs::write(node.state.join("proxy-reply"), raw).unwrap();
        // The test fails: the credentials stay saved, the switch is saved
        // off and the page is told why.
        reply(r#"{"ok":false,"class":"proxy_auth"}"#);
        let saved = save(
            &node,
            &preferences,
            &runtime,
            form(true, "all", 1080, "synthuser", "synthetic-pass"),
        )
        .await
        .unwrap();
        assert!(!saved.enabled);
        assert_eq!(saved.test, Some(TestResult::failed("proxy_auth")));
        assert_eq!(saved.saved, Saved::of(Some(&synthetic())));
        assert_eq!(node.keychain().load(), Ok(Some(synthetic())));
        let data = preferences.snapshot().unwrap();
        assert!(!data.web_proxy);
        assert_eq!(
            (data.web_proxy_use.as_str(), data.web_proxy_port),
            ("all", 1080)
        );
        assert_eq!(node.snapshot().await.web_proxy, None);
        // The probe got the proxy object on stdin, and nowhere else.
        assert_eq!(
            read("proxy-input"),
            "{\"provider\":\"webshare\",\"username\":\"synthuser\",\"password\":\"synthetic-pass\",\"country\":\"us\",\"port\":1080,\"use\":\"all\"}\n"
        );
        assert_eq!(read("calls"), "desktop proxy-test\n");
        assert!(!read("env").contains("synthuser") && !read("env").contains("synthetic-pass"));
        // A passing test with the saved credentials (both fields left empty)
        // turns it on for the next node.
        reply(r#"{"ok":true,"exit":"45.86.200.17"}"#);
        let saved = save(
            &node,
            &preferences,
            &runtime,
            form(true, "limited_sites", 3128, "", ""),
        )
        .await
        .unwrap();
        assert!(saved.enabled);
        assert_eq!(
            saved.test.as_ref().and_then(|t| t.exit.as_deref()),
            Some("45.86.200.17")
        );
        let shown = serde_json::to_string(&saved).unwrap();
        assert!(
            !shown.contains("synthetic-pass") && !shown.contains("synthuser"),
            "{shown}"
        );
        assert!(preferences.snapshot().unwrap().web_proxy);
        assert_eq!(
            node.snapshot().await.web_proxy,
            Some(Route::new("limited_sites", 3128).unwrap())
        );
        assert_eq!(read("proxy-input").lines().count(), 2);
        assert!(read("proxy-input").lines().nth(1).unwrap().contains(
            r#""password":"synthetic-pass","country":"us","port":3128,"use":"limited_sites""#
        ));
        // A test that cannot run is a failed test: the switch is saved off,
        // and the page is told the test could not run.
        reply("proxy said no to synthuser");
        assert_eq!(
            save(
                &node,
                &preferences,
                &runtime,
                form(true, "limited_sites", 3128, "", "")
            )
            .await,
            Err(Error::ProxyTestUnavailable)
        );
        assert!(!preferences.snapshot().unwrap().web_proxy);
        assert_eq!(node.snapshot().await.web_proxy, None);
        assert_eq!(
            test(&node, form(false, "all", 80, "", "")).await,
            Err(Error::ProxyTestUnavailable)
        );
        // Private storage that fails is its own error, whether or not a
        // test ran first, and the proxy stays as it was.
        reply(r#"{"ok":true,"exit":"45.86.200.17"}"#);
        std::fs::write(node.state.join("fail-save"), "").unwrap();
        for enabled in [true, false] {
            assert_eq!(
                save(
                    &node,
                    &preferences,
                    &runtime,
                    form(enabled, "all", 80, "", "")
                )
                .await,
                Err(Error::CommandFailed)
            );
        }
        assert!(!preferences.snapshot().unwrap().web_proxy);
        std::fs::remove_file(node.state.join("fail-save")).unwrap();
        // Switching off runs no test.
        let calls = read("calls");
        let saved = save(
            &node,
            &preferences,
            &runtime,
            form(false, "all", 80, "", ""),
        )
        .await
        .unwrap();
        assert!(!saved.enabled && saved.test.is_none() && saved.saved.saved);
        assert_eq!(read("calls"), calls);
        // Half a credential is refused before anything changes.
        for (username, password) in [
            ("synthuser", ""),
            ("", "synthetic-pass"),
            ("synth user", "x"),
        ] {
            assert_eq!(
                save(
                    &node,
                    &preferences,
                    &runtime,
                    form(true, "all", 80, username, password)
                )
                .await,
                Err(Error::InvalidInput)
            );
        }
        assert_eq!(read("calls"), calls);
        assert_eq!(node.keychain().load(), Ok(Some(synthetic())));
        // With nothing saved, switching on asks for credentials and stays off.
        node.delete_web_proxy_credentials().await.unwrap();
        assert_eq!(
            save(&node, &preferences, &runtime, form(true, "all", 80, "", "")).await,
            Err(Error::WebProxyNotSaved)
        );
        assert!(!preferences.snapshot().unwrap().web_proxy);
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn test_saves_nothing_and_remove_turns_off_and_deletes_the_item() {
        let temp = tempfile::tempdir().unwrap();
        let (node, preferences, runtime) = fixture(&temp);
        std::fs::write(
            node.state.join("proxy-reply"),
            r#"{"ok":true,"exit":"45.86.200.17"}"#,
        )
        .unwrap();
        assert_eq!(
            test(&node, form(false, "all", 80, "", "")).await,
            Err(Error::WebProxyNotSaved)
        );
        let result = test(&node, form(false, "all", 80, "synthuser", "synthetic-pass"))
            .await
            .unwrap();
        assert_eq!(result.exit.as_deref(), Some("45.86.200.17"));
        assert_eq!(node.keychain().load(), Ok(None));
        assert_eq!(saved(&node).await.unwrap(), Saved::of(None));
        assert!(!preferences.snapshot().unwrap().web_proxy);
        save(
            &node,
            &preferences,
            &runtime,
            form(true, "all", 80, "synthuser", "synthetic-pass"),
        )
        .await
        .unwrap();
        assert!(preferences.snapshot().unwrap().web_proxy);
        assert_eq!(
            saved(&node).await.unwrap().username.as_deref(),
            Some("syn••••")
        );
        remove(&node, &preferences, &runtime).await.unwrap();
        assert_eq!(node.keychain().load(), Ok(None));
        assert!(!preferences.snapshot().unwrap().web_proxy);
        assert_eq!(node.snapshot().await.web_proxy, None);
        // Remove is safe to repeat, and a locked store is reported.
        remove(&node, &preferences, &runtime).await.unwrap();
        node.keychain().fail_next();
        assert_eq!(
            remove(&node, &preferences, &runtime).await,
            Err(Error::KeychainUnavailable)
        );
        node.keychain().fail_next();
        assert_eq!(saved(&node).await, Err(Error::KeychainUnavailable));
    }
    #[test]
    fn keychain_saves_loads_and_deletes_one_item_in_the_mock_store() {
        let keychain = Keychain::mock();
        assert_eq!(keychain.load(), Ok(None));
        // Removing nothing succeeds, so Remove is safe to repeat.
        assert_eq!(keychain.delete(), Ok(()));
        keychain.save(&synthetic()).unwrap();
        assert_eq!(keychain.load(), Ok(Some(synthetic())));
        // The item is the one service and account, holding exactly the
        // username and password as JSON.
        let entry = keychain.entry().unwrap();
        assert_eq!(
            entry.get_specifiers(),
            Some(("Scarlett Node".into(), "web-egress-proxy".into()))
        );
        assert_eq!(
            entry.get_secret().unwrap(),
            br#"{"username":"synthuser","password":"synthetic-pass"}"#
        );
        let replaced = Credentials::new("other1".into(), "replaced".into()).unwrap();
        keychain.save(&replaced).unwrap();
        assert_eq!(keychain.load(), Ok(Some(replaced)));
        keychain.delete().unwrap();
        assert_eq!(keychain.load(), Ok(None));
        assert!(matches!(
            keychain.entry().unwrap().get_secret(),
            Err(keyring_core::Error::NoEntry)
        ));
    }
    #[test]
    fn keychain_failures_and_foreign_items_fail_closed() {
        let keychain = Keychain::mock();
        keychain.save(&synthetic()).unwrap();
        keychain.fail_next();
        assert_eq!(keychain.load(), Err(Error::KeychainUnavailable));
        keychain.fail_next();
        assert_eq!(keychain.save(&synthetic()), Err(Error::KeychainUnavailable));
        keychain.fail_next();
        assert_eq!(keychain.delete(), Err(Error::KeychainUnavailable));
        // The failure did not change or remove the item.
        assert_eq!(keychain.load(), Ok(Some(synthetic())));
        // An item this app did not write is refused, never partly used, and
        // Remove still deletes it.
        for foreign in [
            br#"{"username":"synthuser"}"#.as_slice(),
            br#"{"username":"synthuser","password":"synthetic-pass","host":"evil.example"}"#,
            br#"{"username":"synth-user","password":"synthetic-pass"}"#,
            br#"{"username":"synthuser","password":"with space"}"#,
            b"synthetic-pass",
        ] {
            keychain.entry().unwrap().set_secret(foreign).unwrap();
            assert_eq!(keychain.load(), Err(Error::KeychainUnavailable));
        }
        keychain.delete().unwrap();
        assert_eq!(keychain.load(), Ok(None));
    }
    #[test]
    fn credentials_are_bounded_and_never_shown() {
        for (username, password) in [
            ("", "synthetic"),
            ("a".repeat(33).as_str(), "synthetic"),
            ("synth-user", "synthetic"),
            ("synth user", "synthetic"),
            ("synthuser", ""),
            ("synthuser", "with space"),
            ("synthuser", "tab\tseparated"),
            ("synthuser", &"p".repeat(PASSWORD_MAX + 1)),
            ("synthuser", "naïve"),
        ] {
            assert_eq!(
                Credentials::new(username.into(), password.into()),
                Err(Error::InvalidInput),
                "{username:?}"
            );
        }
        assert!(Credentials::new("a".repeat(32), "p".repeat(PASSWORD_MAX)).is_ok());
        let credentials = synthetic();
        let shown = format!("{credentials:?} {:?}", Saved::of(Some(&credentials)));
        assert!(
            !shown.contains("synthuser") && !shown.contains("synthetic-pass"),
            "{shown}"
        );
        assert_eq!(credentials.masked_username(), "syn••••");
        for (username, masked) in [("a", "••••"), ("ab", "a••••"), ("abcde", "ab••••")]
        {
            let short = Credentials::new(username.into(), "p".into()).unwrap();
            assert_eq!(short.masked_username(), masked);
        }
        let saved = serde_json::to_value(Saved::of(Some(&credentials))).unwrap();
        assert_eq!(saved["saved"], true);
        assert_eq!(saved["username"], "syn••••");
        assert!(saved.get("password").is_none());
        assert_eq!(
            serde_json::to_value(Saved::of(None)).unwrap(),
            serde_json::json!({"saved": false, "username": null, "store": Keychain::name()})
        );
    }
    #[test]
    fn start_line_and_test_input_match_the_node_contract() {
        let credentials = synthetic();
        assert_eq!(&*start_line(None).unwrap(), b"{}\n");
        let route = Route::new("limited_sites", 80).unwrap();
        assert_eq!(
            std::str::from_utf8(&start_line(Some((&credentials, route))).unwrap()).unwrap(),
            "{\"web_egress_proxy\":{\"provider\":\"webshare\",\"username\":\"synthuser\",\"password\":\"synthetic-pass\",\"country\":\"us\",\"port\":80,\"use\":\"limited_sites\"}}\n"
        );
        let route = Route::new("all", 3128).unwrap();
        assert_eq!(
            std::str::from_utf8(&test_input(&credentials, route).unwrap()).unwrap(),
            "{\"provider\":\"webshare\",\"username\":\"synthuser\",\"password\":\"synthetic-pass\",\"country\":\"us\",\"port\":3128,\"use\":\"all\"}\n"
        );
        // The widest line fits what the node reads.
        let widest = Credentials::new("u".repeat(32), "~".repeat(PASSWORD_MAX)).unwrap();
        let line = start_line(Some((&widest, Route::new("limited_sites", 1080).unwrap()))).unwrap();
        assert!(line.len() <= START_LINE_LIMIT, "{}", line.len());
        assert_eq!(line.iter().filter(|b| **b == b'\n').count(), 1);
        for (pages, port) in [
            ("every", 80),
            ("", 80),
            ("all", 8080),
            ("all", 0),
            ("all", 443),
        ] {
            assert_eq!(Route::new(pages, port), Err(Error::InvalidInput));
        }
    }
    #[test]
    fn test_replies_are_reduced_to_an_exit_or_a_known_class() {
        assert_eq!(
            test_projection(br#"{"ok":true,"exit":"45.86.200.17"}"#).unwrap(),
            TestResult {
                ok: true,
                exit: Some("45.86.200.17".into()),
                class: None
            }
        );
        assert_eq!(
            serde_json::to_string(
                &test_projection(b"{\"ok\":false,\"class\":\"proxy_auth\"}\n").unwrap()
            )
            .unwrap(),
            r#"{"ok":false,"class":"proxy_auth"}"#
        );
        for class in TEST_CLASSES {
            let raw =
                serde_json::to_vec(&serde_json::json!({"ok": false, "class": class})).unwrap();
            assert_eq!(test_projection(&raw).unwrap().class.as_deref(), Some(class));
        }
        for raw in [
            br#"{"ok":true}"#.as_slice(),
            br#"{"ok":true,"exit":"10.0.0.7"}"#,
            br#"{"ok":true,"exit":"100.64.0.1"}"#,
            br#"{"ok":true,"exit":"203.0.113.7"}"#,
            br#"{"ok":true,"exit":"045.86.200.17"}"#,
            br#"{"ok":true,"exit":"2001:db8::1"}"#,
            br#"{"ok":true,"exit":"synthuser:synthetic-pass@45.86.200.17"}"#,
            br#"{"ok":true,"exit":"45.86.200.17","class":"proxy_auth"}"#,
            br#"{"ok":false}"#,
            br#"{"ok":false,"class":"synthuser"}"#,
            br#"{"ok":false,"class":"proxy_auth","detail":"synthetic-pass"}"#,
            br#"{"ok":false,"class":"proxy_auth","exit":"45.86.200.17"}"#,
            b"proxy said 407 for synthuser",
        ] {
            assert_eq!(test_projection(raw), Err(Error::CommandFailed));
        }
    }
    #[test]
    fn exits_are_public_ipv4_addresses_only() {
        for public in ["45.86.200.17", "1.1.1.1", "8.8.8.8", "223.255.255.1"] {
            assert!(public_ipv4(public).is_some(), "{public}");
        }
        for reserved in [
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "100.127.255.254",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.0.0.8",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.1",
            "198.51.100.1",
            "203.0.113.7",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            " 45.86.200.17",
            "45.86.200",
            "::ffff:45.86.200.17",
        ] {
            assert!(public_ipv4(reserved).is_none(), "{reserved}");
        }
    }
}
