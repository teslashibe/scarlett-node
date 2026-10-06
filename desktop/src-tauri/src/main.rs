#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod claude_auth;
mod local_api;
mod node;
mod preferences;
#[cfg(windows)]
mod windows_autostart;
use local_api::LocalApi;
use node::{Error, Node};
use preferences::{Data as PreferenceData, Preferences};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tauri::{Emitter, Manager, State, WebviewUrl, WebviewWindow, WebviewWindowBuilder};
use tauri_plugin_autostart::ManagerExt;
use tauri_plugin_opener::OpenerExt;
struct RuntimeControl(tokio::sync::Mutex<()>);
struct ShutdownState(Arc<AtomicBool>);

#[tauri::command]
fn quit_desktop(
    window: WebviewWindow,
    app: tauri::AppHandle,
    shutdown: State<'_, ShutdownState>,
) -> node::Result<()> {
    local_window(&window)?;
    quit(app, shutdown.0.clone());
    Ok(())
}

fn local_window(window: &WebviewWindow) -> node::Result<()> {
    let url = window.url().map_err(|_| Error::InvalidInput)?;
    if window.label() != "main" || !local_url(&url) {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
fn local_url(url: &tauri::Url) -> bool {
    matches!(
        (url.scheme(), url.host_str()),
        ("tauri", Some("localhost"))
            | ("https", Some("tauri.localhost"))
            | ("http", Some("tauri.localhost"))
    ) || cfg!(debug_assertions)
        && url.scheme() == "http"
        && url.host_str() == Some("127.0.0.1")
        && url.port() == Some(1420)
}
#[tauri::command]
async fn desktop_status(
    window: WebviewWindow,
    node: State<'_, Arc<Node>>,
    api: State<'_, Arc<LocalApi>>,
) -> node::Result<node::Snapshot> {
    local_window(&window)?;
    Ok(status(&node, &api).await)
}
/// Node and local API status only. Claude status is its own command: it hashes
/// the whole bundled Claude binary and launches its CLI, and waiting on that
/// kept a freshly launched, paired node showing Pair node.
async fn status(node: &Node, api: &LocalApi) -> node::Snapshot {
    let (mut status, local_api) = tokio::join!(node.snapshot(), api.snapshot());
    status.local_api = local_api;
    status
}
#[tauri::command]
async fn claude_status(
    window: WebviewWindow,
    api: State<'_, Arc<LocalApi>>,
) -> node::Result<claude_auth::Snapshot> {
    local_window(&window)?;
    Ok(api.claude.snapshot().await)
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaudeBilling {
    mode: String,
    key: Option<String>,
}
impl ClaudeBilling {
    fn key(self) -> node::Result<String> {
        let key = self.key.unwrap_or_default();
        match self.mode.as_str() {
            "subscription" if key.is_empty() => Ok(key),
            "api_key" if !key.is_empty() => Ok(key),
            _ => Err(Error::InvalidInput),
        }
    }
}
#[tauri::command]
async fn control_local_api(
    window: WebviewWindow,
    node: State<'_, Arc<Node>>,
    api: State<'_, Arc<LocalApi>>,
    action: String,
    port: Option<u16>,
    claude: Option<ClaudeBilling>,
    runtime: State<'_, RuntimeControl>,
) -> node::Result<()> {
    local_window(&window)?;
    let _guard = runtime.0.lock().await;
    match action.as_str() {
        "start" => {
            let key = claude
                .map(ClaudeBilling::key)
                .transpose()?
                .unwrap_or_default();
            let status = node.snapshot().await;
            if status.supervised
                || matches!(
                    status
                        .observation
                        .as_ref()
                        .and_then(|v| v.get("state"))
                        .and_then(serde_json::Value::as_str),
                    Some("running" | "draining")
                )
            {
                return Err(Error::ModeConflict);
            }
            api.start(
                port.ok_or(Error::InvalidInput)?,
                &node.accounts().await?,
                key,
            )
            .await
        }
        "stop" => api.stop().await,
        _ => Err(Error::InvalidInput),
    }
}
#[tauri::command]
async fn control_claude(
    window: WebviewWindow,
    api: State<'_, Arc<LocalApi>>,
    runtime: State<'_, RuntimeControl>,
    action: String,
) -> node::Result<()> {
    local_window(&window)?;
    let _guard = runtime.0.lock().await;
    match action.as_str() {
        "connect" => {
            api.stop().await?;
            api.claude.connect().await
        }
        "cancel" => {
            api.stop().await?;
            api.claude.cancel().await
        }
        "disconnect" => {
            api.stop().await?;
            api.claude.disconnect().await
        }
        _ => Err(Error::InvalidInput),
    }
}
#[tauri::command]
fn local_api_key(window: WebviewWindow, api: State<'_, Arc<LocalApi>>) -> node::Result<String> {
    local_window(&window)?;
    api.key()
}
#[tauri::command]
fn desktop_preferences(
    window: WebviewWindow,
    preferences: State<'_, Arc<Preferences>>,
) -> node::Result<PreferenceData> {
    local_window(&window)?;
    preferences.snapshot()
}
#[tauri::command]
async fn save_desktop_preferences(
    window: WebviewWindow,
    node: State<'_, Arc<Node>>,
    preferences: State<'_, Arc<Preferences>>,
    runtime: State<'_, RuntimeControl>,
    data: PreferenceData,
) -> node::Result<()> {
    local_window(&window)?;
    data.validate()?;
    let _guard = runtime.0.lock().await;
    node.save_preferences(&data).await?;
    preferences.updated(data)
}
#[tauri::command]
fn desktop_autostart(window: WebviewWindow, app: tauri::AppHandle) -> node::Result<bool> {
    local_window(&window)?;
    #[cfg(windows)]
    if !windows_autostart::registration_present(&app.package_info().name)? {
        return Ok(false);
    }
    app.autolaunch()
        .is_enabled()
        .map_err(|_| Error::AutostartUnavailable)
}
#[tauri::command]
async fn set_desktop_autostart(
    window: WebviewWindow,
    app: tauri::AppHandle,
    enabled: bool,
    runtime: State<'_, RuntimeControl>,
) -> node::Result<()> {
    local_window(&window)?;
    let _guard = runtime.0.lock().await;
    let manager = app.autolaunch();
    #[cfg(windows)]
    if enabled {
        windows_autostart::prepare_registration()?;
    } else if !windows_autostart::registration_present(&app.package_info().name)? {
        return Ok(());
    }
    if enabled {
        manager.enable()
    } else {
        manager.disable()
    }
    .map_err(|_| Error::AutostartUnavailable)?;
    #[cfg(windows)]
    if enabled {
        let quoted = std::env::current_exe()
            .map_err(|_| Error::AutostartUnavailable)
            .and_then(|exe| {
                windows_autostart::quote_registered_command(&app.package_info().name, &exe)
            });
        if let Err(error) = quoted {
            let _ = manager.disable();
            return Err(error);
        }
    }
    if manager
        .is_enabled()
        .map_err(|_| Error::AutostartUnavailable)?
        != enabled
    {
        return Err(Error::AutostartUnavailable);
    }
    Ok(())
}
#[tauri::command]
async fn pair_node(
    window: WebviewWindow,
    node: State<'_, Arc<Node>>,
    code: String,
) -> node::Result<()> {
    local_window(&window)?;
    node.pair(code).await
}
#[tauri::command]
async fn control_node(
    window: WebviewWindow,
    node: State<'_, Arc<Node>>,
    action: String,
    api: State<'_, Arc<LocalApi>>,
    runtime: State<'_, RuntimeControl>,
) -> node::Result<()> {
    local_window(&window)?;
    let _guard = runtime.0.lock().await;
    if action == "start" && api.snapshot().await.running {
        return Err(Error::ModeConflict);
    }
    node.control(&action).await
}
#[tauri::command]
async fn connect_x(
    window: WebviewWindow,
    node: State<'_, Arc<Node>>,
    id: String,
    concurrency: u8,
    auth_token: String,
    ct0: String,
) -> node::Result<()> {
    local_window(&window)?;
    node.connect_x(id, concurrency, auth_token, ct0).await
}
#[tauri::command]
async fn start_x_login(
    window: WebviewWindow,
    node: State<'_, Arc<Node>>,
    id: String,
    concurrency: u8,
    reconnect: bool,
    username: String,
    password: String,
) -> node::Result<node::XLoginStatus> {
    local_window(&window)?;
    node.start_x_login(id, concurrency, reconnect, username, password)
        .await
}
#[tauri::command]
async fn continue_x_login(
    window: WebviewWindow,
    node: State<'_, Arc<Node>>,
    id: String,
    challenge_id: String,
    code: String,
) -> node::Result<node::XLoginStatus> {
    local_window(&window)?;
    node.continue_x_login(id, challenge_id, code).await
}
#[tauri::command]
async fn cancel_x_login(window: WebviewWindow, node: State<'_, Arc<Node>>) -> node::Result<()> {
    local_window(&window)?;
    node.cancel_x_login().await
}
#[tauri::command]
async fn connect_codex(window: WebviewWindow, node: State<'_, Arc<Node>>) -> node::Result<()> {
    local_window(&window)?;
    node.connect_codex(1).await
}
#[tauri::command]
async fn remove_account(
    window: WebviewWindow,
    node: State<'_, Arc<Node>>,
    api: State<'_, Arc<LocalApi>>,
    service: String,
    id: String,
    runtime: State<'_, RuntimeControl>,
) -> node::Result<()> {
    local_window(&window)?;
    let _guard = runtime.0.lock().await;
    if service == "codex" {
        api.stop().await?;
    }
    node.remove(service, id).await
}
#[tauri::command]
async fn cancel_login(window: WebviewWindow, node: State<'_, Arc<Node>>) -> node::Result<()> {
    local_window(&window)?;
    node.cancel_login().await
}
#[tauri::command]
async fn browser_profiles(
    window: WebviewWindow,
    node: State<'_, Arc<Node>>,
) -> node::Result<Vec<node::BrowserProfile>> {
    local_window(&window)?;
    node.browser_profiles().await
}
#[tauri::command]
async fn import_x_profile(
    window: WebviewWindow,
    node: State<'_, Arc<Node>>,
    profile: String,
    id: String,
    concurrency: u8,
    consent: bool,
) -> node::Result<()> {
    local_window(&window)?;
    if !consent {
        return Err(Error::InvalidInput);
    }
    node.import_x(profile, id, concurrency).await
}
#[tauri::command]
async fn reconnect_x(
    window: WebviewWindow,
    node: State<'_, Arc<Node>>,
    id: String,
    auth_token: String,
    ct0: String,
) -> node::Result<()> {
    local_window(&window)?;
    node.reconnect_x(id, auth_token, ct0).await
}
#[tauri::command]
async fn reimport_x_profile(
    window: WebviewWindow,
    node: State<'_, Arc<Node>>,
    profile: String,
    id: String,
    consent: bool,
) -> node::Result<()> {
    local_window(&window)?;
    if !consent {
        return Err(Error::InvalidInput);
    }
    node.reimport_x(profile, id).await
}
/// Runs only the bundled node's `relay-resume`. The renderer confirms first;
/// the supervised node is neither drained nor restarted.
#[tauri::command]
async fn resume_relay(window: WebviewWindow, node: State<'_, Arc<Node>>) -> node::Result<()> {
    local_window(&window)?;
    node.resume_relay().await
}
#[tauri::command]
fn open_network(
    window: WebviewWindow,
    node: State<'_, Arc<Node>>,
    destination: String,
) -> node::Result<()> {
    local_window(&window)?;
    let url = node.network_url(&destination)?;
    window
        .app_handle()
        .opener()
        .open_url(url, None::<&str>)
        .map_err(|_| Error::CommandFailed)
}

fn quit(app: tauri::AppHandle, done: Arc<AtomicBool>) {
    if done.load(Ordering::SeqCst) {
        app.exit(0);
        return;
    }
    tauri::async_runtime::spawn(async move {
        let node = app.state::<Arc<Node>>().inner().clone();
        let api = app.state::<Arc<LocalApi>>().inner().clone();
        let runtime = app.state::<RuntimeControl>();
        let _guard = runtime.0.lock().await;
        let stopped = match api.stop().await {
            Ok(()) => {
                if api.claude.snapshot().await.pending {
                    let _ = api.claude.cancel().await;
                }
                node.stop().await
            }
            Err(error) => Err(error),
        };
        match stopped {
            Ok(()) => {
                done.store(true, Ordering::SeqCst);
                app.exit(0);
            }
            Err(error) => {
                let _ = app.emit_to("main", "shutdown-error", error);
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
        }
    });
}
fn open_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn main() {
    let done = Arc::new(AtomicBool::new(false));
    let exit_done = done.clone();
    let menu_done = done.clone();
    let app = tauri::Builder::default()
        .manage(ShutdownState(done.clone()))
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            open_window(app);
        }))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .menu(|app| {
            use tauri::menu::{Menu, MenuItem, PredefinedMenuItem, Submenu};
            // The native predefined macOS Quit terminates directly, bypassing
            // asynchronous drain. Both Cmd-Q and the menu must use our handler.
            let quit =
                MenuItem::with_id(app, "app-quit", "Quit Scarlett", true, Some("CmdOrCtrl+Q"))?;
            let open =
                MenuItem::with_id(app, "app-open", "Open Scarlett", true, Some("CmdOrCtrl+1"))?;
            let application = Submenu::with_items(app, "Scarlett Node", true, &[&open, &quit])?;
            let edit = Submenu::with_items(
                app,
                "Edit",
                true,
                &[
                    &PredefinedMenuItem::cut(app, None)?,
                    &PredefinedMenuItem::copy(app, None)?,
                    &PredefinedMenuItem::paste(app, None)?,
                    &PredefinedMenuItem::select_all(app, None)?,
                ],
            )?;
            Menu::with_items(app, &[&application, &edit])
        })
        .on_menu_event(move |app, event| match event.id.as_ref() {
            "app-open" => open_window(app),
            "app-quit" => quit(app.clone(), menu_done.clone()),
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![
            desktop_status,
            claude_status,
            quit_desktop,
            pair_node,
            control_node,
            open_network,
            connect_x,
            start_x_login,
            continue_x_login,
            cancel_x_login,
            connect_codex,
            remove_account,
            cancel_login,
            browser_profiles,
            import_x_profile,
            reconnect_x,
            reimport_x_profile,
            resume_relay,
            control_local_api,
            control_claude,
            local_api_key,
            desktop_preferences,
            save_desktop_preferences,
            desktop_autostart,
            set_desktop_autostart
        ])
        .setup(move |app| {
            let state = app.path().app_data_dir()?;
            let resources = app.path().resource_dir()?;
            let exe = std::env::current_exe()?;
            let directory = exe.parent().ok_or("missing application directory")?;
            let suffix = if cfg!(windows) { ".exe" } else { "" };
            node::private_dir_with_helper(
                &state,
                &directory.join(format!("scarlett-node{suffix}")),
            )
            .map_err(|_| "private desktop storage unavailable")?;
            app.manage(RuntimeControl(tokio::sync::Mutex::new(())));
            app.manage(Arc::new(
                Preferences::load(&state, &directory.join(format!("scarlett-node{suffix}")))
                    .map_err(|_| "private desktop preferences unavailable")?,
            ));
            app.manage(Arc::new(LocalApi::new(
                &state,
                directory.join(format!("open-agent-api{suffix}")),
                resources.join("runtime"),
            )));
            app.manage(Arc::new(
                Node::from_environment(
                    state,
                    directory.join(format!("scarlett-node{suffix}")),
                    directory.join(format!("scarlett-prover{suffix}")),
                )
                .map_err(|_| "invalid desktop endpoint configuration")?
                .with_provider_runtime(&resources),
            ));
            let login_node = app.state::<Arc<Node>>().inner().clone();
            tauri::async_runtime::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
                loop {
                    tick.tick().await;
                    login_node.finish_login().await;
                }
            });
            let window =
                WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                    .title("Scarlett Node")
                    .inner_size(960.0, 760.0)
                    .min_inner_size(640.0, 560.0)
                    .devtools(false)
                    .on_navigation(local_url)
                    .build()?;
            let handle = window.clone();
            let window_done = done.clone();
            window.on_window_event(move |event| {
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    let app = handle.app_handle();
                    if app.state::<Arc<Preferences>>().background() {
                        let _ = handle.hide();
                    } else {
                        quit(app.clone(), window_done.clone());
                    }
                }
            });
            use tauri::{
                menu::{Menu, MenuItem},
                tray::TrayIconBuilder,
            };
            let show = MenuItem::with_id(app, "show", "Open Scarlett", true, None::<&str>)?;
            let close = MenuItem::with_id(app, "quit", "Quit Scarlett", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &close])?;
            let mut rgba = vec![0; 32 * 32 * 4];
            for y in 0..32 {
                for x in 0..32 {
                    if (x as i32 - 16).pow(2) + (y as i32 - 16).pow(2) < 110 {
                        let i = (y * 32 + x) * 4;
                        rgba[i..i + 4].copy_from_slice(&[240, 56, 43, 255]);
                    }
                }
            }
            let tray_done = done.clone();
            TrayIconBuilder::new()
                .icon(tauri::image::Image::new_owned(rgba, 32, 32))
                .tooltip("Scarlett Node")
                .menu(&menu)
                .show_menu_on_left_click(true)
                .on_menu_event(move |app, event| match event.id.as_ref() {
                    "show" => open_window(app),
                    "quit" => quit(app.clone(), tray_done.clone()),
                    _ => {}
                })
                .build(app)?;
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("cannot initialize desktop shell");
    app.run(move |app, event| {
        #[cfg(target_os = "macos")]
        if let tauri::RunEvent::Reopen {
            has_visible_windows: false,
            ..
        } = &event
        {
            open_window(app);
        }
        if let tauri::RunEvent::ExitRequested { api, .. } = event
            && !exit_done.load(Ordering::SeqCst)
        {
            api.prevent_exit();
            quit(app.clone(), exit_done.clone());
        }
    });
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn claude_billing_requires_an_explicit_key_mode() {
        assert_eq!(
            ClaudeBilling {
                mode: "subscription".into(),
                key: None
            }
            .key(),
            Ok(String::new())
        );
        assert_eq!(
            ClaudeBilling {
                mode: "api_key".into(),
                key: Some("synthetic-key".into())
            }
            .key(),
            Ok("synthetic-key".into())
        );
        for billing in [
            ClaudeBilling {
                mode: "subscription".into(),
                key: Some("synthetic-key".into()),
            },
            ClaudeBilling {
                mode: "api_key".into(),
                key: None,
            },
            ClaudeBilling {
                mode: "unknown".into(),
                key: None,
            },
        ] {
            assert_eq!(billing.key(), Err(Error::InvalidInput));
        }
    }
    #[test]
    fn navigation_refuses_remote_and_lookalike_origins() {
        for url in [
            "https://network.scarlett.ai",
            "https://tauri.localhost.evil.test",
            "file:///tmp/x",
            "http://127.0.0.1:9999",
        ] {
            assert!(!local_url(&url.parse().unwrap()));
        }
        assert!(local_url(&"tauri://localhost".parse().unwrap()));
    }
    // Regression for the installed Windows round trip: a fresh app beside a
    // paired identity, two X accounts and an attempt left pending by an earlier
    // process must stop showing Pair node promptly. Its first status therefore
    // never verifies or launches the bundled Claude runtime, even a valid one.
    #[tokio::test]
    async fn status_reports_a_paired_identity_without_the_claude_runtime() {
        use sha2::Digest;
        // Windows creates private directories only through the real node helper.
        let supplied = std::env::var_os("SCARLETT_TEST_NODE_BINARY").map(std::path::PathBuf::from);
        assert!(
            cfg!(unix) || supplied.is_some(),
            "set SCARLETT_TEST_NODE_BINARY to the built scarlett-node.exe"
        );
        let temp = tempfile::tempdir().unwrap();
        let suffix = if cfg!(windows) { ".exe" } else { "" };
        let binary = supplied.clone().unwrap_or_else(|| {
            temp.path()
                .join("absent")
                .join(format!("scarlett-node{suffix}"))
        });
        let state = temp.path().join("state");
        node::private_dir_with_helper(&state, &binary).unwrap();
        let node = Node::new(state.clone(), binary.clone(), binary.clone());
        let resources = temp.path().join("runtime");
        std::fs::create_dir_all(resources.join("claude")).unwrap();
        let runtime = b"synthetic bundled claude runtime";
        std::fs::write(
            resources.join("claude").join(format!("claude{suffix}")),
            runtime,
        )
        .unwrap();
        let target = if cfg!(windows) {
            "x86_64-pc-windows-msvc"
        } else if cfg!(target_arch = "aarch64") {
            "aarch64-apple-darwin"
        } else {
            "x86_64-apple-darwin"
        };
        let manifest = serde_json::json!({"schemaVersion": 1, "target": target, "claudeVersion": "2.1.286",
            "files": [{"path": format!("claude/claude{suffix}"), "bytes": runtime.len(),
                "sha256": format!("{:x}", sha2::Sha256::digest(runtime))}]});
        std::fs::write(resources.join("COMPONENTS.json"), manifest.to_string()).unwrap();
        // The local API's helper is the node binary beside it, as installed.
        let api = LocalApi::new(
            &state,
            binary.with_file_name(format!("open-agent-api{suffix}")),
            resources,
        );
        if supplied.is_some() {
            // Seed protected synthetic inventory without authenticating with X.
            // The helper creates the same private files and ACLs used by the app.
            let homes = state.join("accounts");
            node::private_dir_with_helper(&homes, &binary).unwrap();
            let mut accounts = Vec::new();
            for id in ["browser-firefox", "browser-paste"] {
                let home = homes.join(format!("x_read-{id}"));
                node::private_dir_with_helper(&home, &binary).unwrap();
                let seed = home.join("bearer");
                node::private_helper(&binary, "bearer", &seed).unwrap();
                let session = home.join("session.json");
                std::fs::rename(seed, &session).unwrap();
                std::fs::write(
                    &session,
                    br#"{"auth_token":"synthetic-auth","ct0":"synthetic-csrf"}"#,
                )
                .unwrap();
                accounts.push(serde_json::json!({
                    "id": id, "service": "x_read", "path": session, "concurrency": 1
                }));
            }
            let seed = state.join("bearer");
            node::private_helper(&binary, "bearer", &seed).unwrap();
            let registry = state.join("accounts.json");
            std::fs::rename(seed, &registry).unwrap();
            std::fs::write(
                registry,
                serde_json::to_vec(&serde_json::json!({"version": 1, "accounts": accounts}))
                    .unwrap(),
            )
            .unwrap();
        }
        std::fs::write(
            state.join("identity.json"),
            r#"{"node_id":"synthetic-node","supplier_pubkey":"synthetic-wallet","credential":"synthetic-credential"}"#,
        )
        .unwrap();
        let journal = state.join("attempts");
        node::private_dir_with_helper(&journal, &binary).unwrap();
        std::fs::write(
            journal.join("synthetic-pending.json"),
            serde_json::json!({
                "job_id": "synthetic-upgrade-job", "attempt": "synthetic-upgrade-attempt",
                "fence": "synthetic-upgrade-fence", "fingerprint": "a".repeat(64),
                "deadline": "2099-01-01T02:00:00Z", "updated_at": "2099-01-01T00:00:00Z", "state": "started",
                "provider_account_id": "browser-firefox", "provider_service": "x_read"
            })
            .to_string(),
        )
        .unwrap();
        let snapshot = status(&node, &api).await;
        assert!(snapshot.paired, "paired identity was not recognized");
        assert!(
            !api.claude.integrity_checked(),
            "node status waited on the Claude runtime"
        );
        if supplied.is_some() {
            assert!(snapshot.accounts_available, "account inventory failed");
            assert_eq!(snapshot.accounts.len(), 2);
            assert!(snapshot.observation.is_some(), "local status failed");
        }
        // Claude has its own status, which does verify this valid runtime.
        assert!(api.claude.snapshot().await.available);
        assert!(api.claude.integrity_checked());
    }
}
