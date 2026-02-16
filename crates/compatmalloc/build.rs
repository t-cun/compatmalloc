fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    match target_os.as_str() {
        "linux" => {
            let script = format!("{}/linker/version_script.lds", manifest_dir);
            println!("cargo:rustc-cdylib-link-arg=-Wl,--version-script={}", script);
            println!("cargo:rerun-if-changed=linker/version_script.lds");
        }
        "macos" => {
            // On macOS, we'd use -exported_symbols_list
            // For now, all symbols are exported by default on macOS
        }
        "windows" => {
            let def = format!("{}/linker/exports.def", manifest_dir);
            println!("cargo:rustc-cdylib-link-arg=/DEF:{}", def);
            println!("cargo:rerun-if-changed=linker/exports.def");
        }
        _ => {}
    }
}
