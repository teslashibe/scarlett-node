fn main() {
    compile_release_notes();
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "desktop_status",
            "desktop_diagnostics",
            "claude_status",
            "quit_desktop",
            "pair_node",
            "control_node",
            "open_network",
            "connect_x",
            "start_x_login",
            "continue_x_login",
            "cancel_x_login",
            "browser_profiles",
            "import_x_profile",
            "reconnect_x",
            "reimport_x_profile",
            "resume_relay",
            "connect_codex",
            "remove_account",
            "cancel_login",
            "control_local_api",
            "control_claude",
            "local_api_key",
            "desktop_preferences",
            "save_desktop_preferences",
            "desktop_autostart",
            "set_desktop_autostart",
            "update_status",
            "update_check",
            "update_install",
            "update_cancel",
            "update_later",
            "update_ack",
            "update_dismiss",
            "set_update_mode",
        ]),
    ))
    .expect("desktop build configuration");
}

/// Compile release-notes/<this version>.json into the app, so the "Updated to"
/// banner needs no network. A version without notes compiles `null`.
fn compile_release_notes() {
    let manifest = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let config = manifest.join("tauri.conf.json");
    println!("cargo:rerun-if-changed={}", config.display());
    println!("cargo:rerun-if-env-changed=TAURI_CONFIG");
    let read_version = |text: &str| {
        serde_json::from_str::<serde_json::Value>(text)
            .ok()
            .and_then(|v| v.get("version")?.as_str().map(str::to_owned))
    };
    let version = std::env::var("TAURI_CONFIG")
        .ok()
        .and_then(|text| read_version(&text))
        .or_else(|| read_version(&std::fs::read_to_string(&config).ok()?))
        .expect("desktop version");
    let notes = manifest.join("../../release-notes");
    println!("cargo:rerun-if-changed={}", notes.display());
    let compiled = std::fs::read_to_string(notes.join(format!("{version}.json")))
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .filter(|v| v.get("version").and_then(serde_json::Value::as_str) == Some(&version))
        .map(|v| {
            serde_json::json!({"title": v["title"], "date": v["date"], "highlights": v["highlights"]})
        })
        .unwrap_or(serde_json::Value::Null);
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("release-notes.json");
    std::fs::write(out, compiled.to_string()).expect("compiled release notes");
}
