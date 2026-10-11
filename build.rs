/// Backend crates whose `Cargo.lock` version `archive_*_version` reports as
/// "<crate> <version>", by the upstream key they stand for. A crate that is not
/// in the lock file leaves its variable unset, so the backend reports NULL.
const BACKENDS: &[(&str, &str)] = &[
    ("ZLIB", "miniz_oxide"),
    ("LIBLZMA", "lzma-rust2"),
    ("BZLIB", "crabz2"),
    ("LIBLZ4", "lz4_flex"),
    ("LIBZSTD", "ruzstd"),
];

fn main() {
    println!("cargo:rerun-if-changed=Cargo.lock");
    let lock = std::fs::read_to_string("Cargo.lock").unwrap_or_default();
    for (key, krate) in BACKENDS {
        let version = lock.split("[[package]]").find_map(|package| {
            let field = |name: &str| {
                package.lines().find_map(|l| {
                    l.strip_prefix(name)?
                        .strip_prefix(" = \"")?
                        .strip_suffix('"')
                })
            };
            (field("name")? == *krate).then(|| field("version"))?
        });
        if let Some(version) = version {
            println!("cargo:rustc-env=ARCHIVE_{key}_VERSION={krate} {version}");
        }
    }
}
