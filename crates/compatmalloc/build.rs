fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    match target_os.as_str() {
        "linux" => {
            // Version script to export only malloc-family symbols.
            // Skip in fuzz builds: nightly rustc generates its own version
            // script for cdylib targets, and anonymous + named tags conflict.
            let is_fuzzing = std::env::var("CARGO_CFG_FUZZING").is_ok();
            if !is_fuzzing {
                let script = format!("{}/linker/version_script.lds", manifest_dir);
                println!(
                    "cargo:rustc-cdylib-link-arg=-Wl,--version-script={}",
                    script
                );
                println!("cargo:rerun-if-changed=linker/version_script.lds");
            }

            // Compile C shim for fast TLS access (initial-exec model).
            // This gives us direct fs: segment loads (~1-3 cycles) instead of
            // __tls_get_addr PLT calls (~25 cycles).
            let mut build = cc::Build::new();
            build
                .file(format!("{}/csrc/tls_fast.c", manifest_dir))
                .opt_level(3)
                .flag("-ftls-model=initial-exec")
                .flag("-fvisibility=hidden");

            // Use clang-21 when available for consistent codegen with lld-21.
            // Cross-language LTO (-flto=thin) is only enabled when the caller
            // sets -Clinker-plugin-lto in RUSTFLAGS (release/bench builds).
            // The cc crate auto-detects this and adds -flto=thin; we also add
            // it explicitly for clarity.
            let has_lto = std::env::var("CARGO_ENCODED_RUSTFLAGS")
                .map(|f| f.contains("linker-plugin-lto"))
                .unwrap_or(false);

            if std::process::Command::new("clang-21")
                .arg("--version")
                .output()
                .is_ok_and(|o| o.status.success())
            {
                build.compiler("clang-21");
                if has_lto {
                    build.flag("-flto=thin");
                }
            }

            build.compile("tls_fast");
            println!("cargo:rerun-if-changed=csrc/tls_fast.c");
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
