fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    match target_os.as_str() {
        "linux" => {
            let script = format!("{}/linker/version_script.lds", manifest_dir);
            println!(
                "cargo:rustc-cdylib-link-arg=-Wl,--version-script={}",
                script
            );
            println!("cargo:rerun-if-changed=linker/version_script.lds");

            // Compile C shim for fast TLS access (initial-exec model).
            // This gives us direct fs: segment loads (~1-3 cycles) instead of
            // __tls_get_addr PLT calls (~25 cycles).
            //
            // Cross-language LTO (clang-21 + lld-21): compiles C to LLVM bitcode
            // which lld merges with Rust bitcode, enabling cross-boundary inlining.
            let mut build = cc::Build::new();
            build
                .file(format!("{}/csrc/tls_fast.c", manifest_dir))
                .opt_level(3)
                .flag("-ftls-model=initial-exec")
                .flag("-fvisibility=hidden");

            // Cross-language LTO (release only): use clang-21 + thin LTO so lld
            // can merge C and Rust bitcode, enabling cross-boundary inlining.
            // In debug/test builds we use the default compiler (gcc) to produce
            // native ELF -- the cc crate auto-adds -flto=thin when it sees
            // -Clinker-plugin-lto in CARGO_ENCODED_RUSTFLAGS and the compiler
            // is clang, which produces bitcode TLS variables that lld doesn't
            // properly materialize without full LTO.
            let profile = std::env::var("PROFILE").unwrap_or_default();
            if profile == "release"
                && std::process::Command::new("clang-21")
                    .arg("--version")
                    .output()
                    .is_ok_and(|o| o.status.success())
            {
                build.compiler("clang-21");
                build.flag("-flto=thin");
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
