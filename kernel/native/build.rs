use std::{env, path::PathBuf, process::Command};
fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let object = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("entry.o");
    assert!(Command::new("nasm")
        .args(["-f", "elf64"])
        .arg(root.join("entry.asm"))
        .arg("-o")
        .arg(&object)
        .status()
        .unwrap()
        .success());
    println!("cargo:rustc-link-arg={}", object.display());
    println!("cargo:rustc-link-arg=-T{}", root.join("link.ld").display());
    println!("cargo:rustc-link-arg=--no-pie");
    println!("cargo:rerun-if-changed=entry.asm");
    println!("cargo:rerun-if-changed=link.ld");
}
