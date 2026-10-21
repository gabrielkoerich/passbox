use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=swift/passbox-se.swift");

    // Only a host talks to the Secure Enclave, so a client build needs no Swift at all
    if std::env::var_os("CARGO_FEATURE_HOST").is_none()
        || std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos")
    {
        return;
    }

    // swiftc follows the host architecture unless told, which breaks a universal build
    let arch = match std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "x86_64",
        _ => "arm64",
    };

    // EventKit denies a process with no calendar usage key without a prompt, and a remote calendar
    // call runs icalBuddy inside the broker, so the binary carries its own Info.plist
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let plist = out_dir.join("Info.plist");
    let reason = "passbox runs the calendar plugin's agenda tools for you.";
    std::fs::write(
        &plist,
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>com.gabrielkoerich.passbox</string>
	<key>CFBundleName</key>
	<string>passbox</string>
	<key>CFBundleShortVersionString</key>
	<string>{}</string>
	<key>NSCalendarsFullAccessUsageDescription</key>
	<string>{reason}</string>
	<key>NSCalendarsUsageDescription</key>
	<string>{reason}</string>
</dict>
</plist>
"#,
            env!("CARGO_PKG_VERSION")
        ),
    )
    .expect("could not write Info.plist");
    println!(
        "cargo:rustc-link-arg-bins=-Wl,-sectcreate,__TEXT,__info_plist,{}",
        plist.display()
    );

    let out = out_dir.join("passbox-se");
    let status = Command::new("swiftc")
        .args(["-O", "-target", &format!("{arch}-apple-macosx13.0"), "-o"])
        .arg(&out)
        .arg("swift/passbox-se.swift")
        .status()
        .expect("swiftc is missing, install the Command Line Tools");

    assert!(
        status.success(),
        "could not build the Secure Enclave helper"
    );

    // The helper hands back the store key, so it refuses a debugger too. Ad hoc, no account needed
    let signed = Command::new("codesign")
        .args(["-s", "-", "--force", "--options", "runtime"])
        .arg(&out)
        .status()
        .expect("codesign is missing, install the Command Line Tools");
    assert!(signed.success(), "could not sign the Secure Enclave helper");
}
