#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod local_api;
mod node;
use local_api::LocalApi;
use node::{Error, Node};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tauri::{Emitter, Manager, State, WebviewUrl, WebviewWindow, WebviewWindowBuilder};
use tauri_plugin_opener::OpenerExt;
struct RuntimeControl(tokio::sync::Mutex<()>);

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
    let mut status = node.snapshot().await;
    status.local_api = api.snapshot().await;
    Ok(status)
}
#[tauri::command]
async fn control_local_api(
    window: WebviewWindow,
    node: State<'_, Arc<Node>>,
    api: State<'_, Arc<LocalApi>>,
    action: String,
    port: Option<u16>,
    claude_key: Option<String>,
    runtime: State<'_, RuntimeControl>,
) -> node::Result<()> {
    local_window(&window)?;
    let _guard = runtime.0.lock().await;
    match action.as_str() {
        "start" => {
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
                claude_key.unwrap_or_default(),
            )
            .await
        }
        "stop" => api.stop().await,
        _ => Err(Error::InvalidInput),
    }
}
#[tauri::command]
fn local_api_key(window: WebviewWindow, api: State<'_, Arc<LocalApi>>) -> node::Result<String> {
    local_window(&window)?;
    api.key()
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
async fn connect_codex(
    window: WebviewWindow,
    node: State<'_, Arc<Node>>,
    id: String,
    concurrency: u8,
) -> node::Result<()> {
    local_window(&window)?;
    node.connect_codex(id, concurrency).await
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
            Ok(()) => node.stop().await,
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
fn main() {
    let done = Arc::new(AtomicBool::new(false));
    let exit_done = done.clone();
    let menu_done = done.clone();
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_opener::init())
        .menu(|app| {
            use tauri::menu::{Menu, MenuItem, PredefinedMenuItem, Submenu};
            // The native predefined macOS Quit terminates directly, bypassing
            // asynchronous drain. Both Cmd-Q and the menu must use our handler.
            let quit =
                MenuItem::with_id(app, "app-quit", "Quit Scarlett", true, Some("CmdOrCtrl+Q"))?;
            let application = Submenu::with_items(app, "Scarlett Node", true, &[&quit])?;
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
        .on_menu_event(move |app, event| {
            if event.id.as_ref() == "app-quit" {
                quit(app.clone(), menu_done.clone());
            }
        })
        .invoke_handler(tauri::generate_handler![
            desktop_status,
            pair_node,
            control_node,
            open_network,
            connect_x,
            connect_codex,
            remove_account,
            cancel_login,
            control_local_api,
            local_api_key
        ])
        .setup(move |app| {
            let state = app.path().app_data_dir()?;
            let resources = app.path().resource_dir()?;
            let exe = std::env::current_exe()?;
            let directory = exe.parent().ok_or("missing application directory")?;
            let suffix = if cfg!(windows) { ".exe" } else { "" };
            app.manage(RuntimeControl(tokio::sync::Mutex::new(())));
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
            window.on_window_event(move |event| {
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    let _ = handle.hide();
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
                    "show" => {
                        if let Some(w) = app.get_webview_window("main") {
                            let _ = w.show();
                            let _ = w.set_focus();
                        }
                    }
                    "quit" => quit(app.clone(), tray_done.clone()),
                    _ => {}
                })
                .build(app)?;
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("cannot initialize desktop shell");
    app.run(move |app, event| {
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
}
