fn main() {
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "desktop_status",
            "pair_node",
            "control_node",
            "open_network",
            "connect_x",
            "browser_profiles",
            "import_x_profile",
            "connect_codex",
            "remove_account",
            "cancel_login",
            "control_local_api",
            "local_api_key",
        ]),
    ))
    .expect("desktop build configuration");
}
