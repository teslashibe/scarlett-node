fn main() {
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "desktop_status",
            "quit_desktop",
            "pair_node",
            "control_node",
            "open_network",
            "connect_x",
            "connect_codex",
            "remove_account",
            "cancel_login",
            "control_local_api",
            "local_api_key",
        ]),
    ))
    .expect("desktop build configuration");
}
