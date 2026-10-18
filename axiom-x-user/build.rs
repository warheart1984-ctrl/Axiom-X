//! Link every user binary with `user.ld` (fixed user base, W^X segments).

fn main() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("user.ld");
    println!("cargo:rerun-if-changed={}", script.display());
    println!("cargo:rustc-link-arg-bins=-T{}", script.display());
}
