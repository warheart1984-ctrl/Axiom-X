use std::process::Command;
use std::path::PathBuf;

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();

    // The context-switch assembly is currently only provided as an MSVC COFF
    // object (ml64 + lib.exe). That only links into Windows/msvc-flavor
    // targets. For bare-metal (e.g. x86_64-unknown-none, ELF via rust-lld)
    // the ELF implementation of context.asm is a follow-up; skip native
    // linking here so the no_std rlib still builds.
    if !target.to_lowercase().contains("windows") {
        println!("cargo:rerun-if-changed=../context.asm");
        return;
    }

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let context_asm = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../context.asm");
    let context_o = out_dir.join("context.obj");
    let context_lib = out_dir.join("context.lib");

    // Assemble with ml64 (Microsoft assembler)
    let ml64_path = find_ml64().expect("ml64 not found in Visual Studio installation");
    let status = Command::new(&ml64_path)
        .args([
            "/c",
            "/Cp",           // preserve case
            "/Fl",           // generate listing
            "/Fo", context_o.to_str().unwrap(),
            context_asm.to_str().unwrap(),
        ])
        .status()
        .expect("failed to assemble context.asm with ml64");

    if !status.success() {
        panic!("ml64 failed to assemble context.asm");
    }

    // Archive the object into a static library so downstream crates can link it.
    // `cargo:rustc-link-arg` only applies to this crate's own targets, so the
    // object alone would never reach dependents (e.g. the kernel test harness).
    let lib_exe = ml64_path.parent().unwrap().join("lib.exe");
    let status = Command::new(lib_exe)
        .arg(format!("/OUT:{}", context_lib.to_str().unwrap()))
        .arg(context_o.to_str().unwrap())
        .status()
        .expect("failed to create context.lib with lib.exe");

    if !status.success() {
        panic!("lib.exe failed to create context.lib");
    }

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=context");
    println!("cargo:rerun-if-changed=../context.asm");
}

fn find_ml64() -> Option<PathBuf> {
    // Check common VS install locations
    let vs_paths = [
        r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\ml64.exe",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\ml64.exe",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\ml64.exe",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\ml64.exe",
    ];

    for path in vs_paths {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(p);
        }
    }

    // Try to find via vswhere
    if let Ok(output) = std::process::Command::new("vswhere")
        .args(["-latest", "-products", "*", "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"])
        .output()
    {
        if let Ok(path_str) = String::from_utf8(output.stdout) {
            let install_path = path_str.trim();
            let msvc_dir = PathBuf::from(install_path).join("VC").join("Tools").join("MSVC");
            if let Ok(mut entries) = std::fs::read_dir(&msvc_dir) {
                if let Some(latest) = entries.next() {
                    let ml64 = msvc_dir
                        .join(latest.ok()?.file_name())
                        .join("bin")
                        .join("Hostx64")
                        .join("x64")
                        .join("ml64.exe");
                    if ml64.exists() {
                        return Some(ml64);
                    }
                }
            }
        }
    }

    None
}
