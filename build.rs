fn main() {
    cc::Build::new()
        .file("src/ffi/variadic.c")
        .compile("archive_variadic");
    println!("cargo:rerun-if-changed=src/ffi/variadic.c");
    // rustc exports only Rust symbols from a cdylib; add the C one explicitly.
    let flag = match std::env::var("CARGO_CFG_TARGET_OS").as_deref() {
        Ok("macos" | "ios") => "-Wl,-exported_symbol,_archive_set_error",
        _ => "-Wl,--export-dynamic-symbol=archive_set_error",
    };
    println!("cargo:rustc-link-arg-cdylib={flag}");
}
