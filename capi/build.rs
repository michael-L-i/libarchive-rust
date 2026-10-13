fn main() {
    // rustc exports only Rust symbols from a cdylib; the C one has to be
    // exported explicitly. On Apple targets `+export-symbols` names C symbols
    // with an extra leading underscore, so the linker is told directly there.
    let apple = std::env::var("CARGO_CFG_TARGET_VENDOR").as_deref() == Ok("apple");
    let mut build = cc::Build::new();
    build.file("variadic.c");
    if !apple {
        build
            .link_lib_modifier("+whole-archive")
            .link_lib_modifier("+export-symbols");
    }
    build.compile("archive_variadic");
    println!("cargo:rerun-if-changed=variadic.c");
    if apple {
        println!("cargo:rustc-link-arg-cdylib=-Wl,-exported_symbol,_archive_set_error");
        println!("cargo:rustc-link-arg-cdylib=-Wl,-install_name,@rpath/libarchive.13.dylib");
        println!("cargo:rustc-link-arg-cdylib=-Wl,-compatibility_version,23.0.0");
        println!("cargo:rustc-link-arg-cdylib=-Wl,-current_version,23.0.0");
    } else if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        println!("cargo:rustc-link-arg-cdylib=-Wl,-soname,libarchive.so.13");
    }
}
