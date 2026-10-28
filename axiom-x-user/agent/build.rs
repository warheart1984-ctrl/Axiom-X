//! Link agent binaries with the shared `user.ld` (fixed user base, W^X
//! segments) — same script as the axiom-x-user bins.

fn main() {
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../user.ld");
    println!("cargo:rerun-if-changed={}", script.display());
    println!("cargo:rustc-link-arg-bins=-T{}", script.display());
}
