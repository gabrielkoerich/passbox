//! Round trip against a throwaway store, so it needs no hardware and raises no prompt.
//! Run with `cargo run`, with `passbox` on PATH.

use passbox::Passbox;
use std::io::Write;
use std::process::{Command, Stdio};

fn main() {
    let dir = std::env::temp_dir().join(format!("passbox-example-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    unsafe {
        std::env::set_var("PASSBOX_DIR", &dir);
        std::env::set_var("PASSBOX_PASSPHRASE", "correct horse battery staple");
    }

    assert!(
        Command::new("passbox")
            .arg("init")
            .status()
            .expect("passbox on PATH")
            .success(),
        "init failed"
    );

    let mut add = Command::new("passbox")
        .args(["add", "demo/api"])
        .stdin(Stdio::piped())
        .spawn()
        .expect("add");
    add.stdin
        .as_mut()
        .expect("stdin")
        .write_all(b"s3cret\nusername: bot\nhost: example.com")
        .expect("write");
    assert!(add.wait().expect("add").success(), "add failed");

    let mut box_ = Passbox::new(Some("demo"), Some("self-check"), &["api"]);
    assert!(box_.is_available(), "store should be usable");
    assert_eq!(box_.get("api").unwrap().lines().next(), Some("s3cret"));

    let fields = box_.fields("api").unwrap();
    assert_eq!(fields["password"], "s3cret");
    assert_eq!(fields["username"], "bot");
    assert_eq!(fields["host"], "example.com");

    let out = box_
        .run_with(
            "API_KEY",
            "api",
            &["sh", "-c", "test -n \"$API_KEY\" && echo ok"],
        )
        .unwrap();
    assert_eq!(out.trim(), "ok");

    std::fs::remove_dir_all(&dir).ok();
    println!("all checks passed");
}
