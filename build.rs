fn main() {
    println!("cargo:rerun-if-changed=assets/icon.ico");
    // CI passes the release version (from the tag / dispatch input);
    // fall back to Cargo.toml's version for local builds.
    println!("cargo:rerun-if-env-changed=APP_VERSION");
    let version = std::env::var("APP_VERSION")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(|v| v.trim().trim_start_matches('v').to_string())
        .unwrap_or_else(|| {
            std::env::var("CARGO_PKG_VERSION").unwrap_or_default()
        });
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/icon.ico");
        res.set("FileDescription", "GenshinReader — Mora tracker");
        res.set("ProductName", "GenshinReader");
        res.set("FileVersion", &version);
        res.set("ProductVersion", &version);
        res.compile().expect("embedding windows resources");
    }
}
