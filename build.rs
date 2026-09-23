use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=swift/passbox-se.swift");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }

    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("passbox-se");
    let status = Command::new("swiftc")
        .args(["-O", "-o"])
        .arg(&out)
        .arg("swift/passbox-se.swift")
        .status()
        .expect("swiftc is missing, install the Command Line Tools");

    assert!(
        status.success(),
        "could not build the Secure Enclave helper"
    );
}
