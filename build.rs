const COMMANDS: &[&str] = &[
    "connect",
    "disconnect",
    "status",
    "import_server",
    "validate_profile",
    "list_protocols",
];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .ios_path("ios")
        .build();
}
