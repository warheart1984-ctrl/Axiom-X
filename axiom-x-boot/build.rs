//! Build script: wires the x86_64 linker script into the bootable kernel ELF.
//!
//! `cargo:rustc-link-arg` applies to this package's own linkable targets (the
//! `kernel` bin). It is gated to non-Windows targets so the host (msvc) build
//! of the library never receives a GNU-style `-T` script. The kernel links at
//! 1 MiB and is loaded by QEMU/GRUB as a multiboot2 ELF64 image.
//!
//! Also runs movie asset generation (best-effort) to embed boot movie assets.

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    if target.to_lowercase().contains("windows") {
        return;
    }

    let ws_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let script = ws_root.join("kernel.ld").canonicalize().unwrap();
    println!("cargo:rerun-if-changed={}", script.display());
    println!("cargo:rustc-link-arg=-T{}", script.display());

    // Link pre-assembled trampoline.o (assembled with GNU as on Linux)
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let trampoline_obj = manifest_dir.join("src/trampoline.o");
    if trampoline_obj.exists() {
        println!("cargo:rustc-link-arg={}", trampoline_obj.display());
    } else {
        panic!("trampoline.o not found at {}. Please assemble trampoline.S with GNU as on Linux.", trampoline_obj.display());
    }

    // Movie asset generation (best-effort)
    generate_movie_assets(&ws_root);
}

fn generate_movie_assets(ws_root: &std::path::Path) {
    let script = ws_root.join("axiom-x-boot/scripts/generate_movie_assets.sh");
    if script.exists() {
        println!("cargo:rerun-if-changed={}", script.display());
        // Run asset generation (best-effort, don't fail build)
        let _ = std::process::Command::new("bash")
            .arg(&script)
            .status();
    }
}
