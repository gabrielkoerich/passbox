//! Runs itself under `passbox exec` against a throwaway store, so it needs no hardware and raises
//! no prompt. Run with `cargo run`, with `passbox` on PATH.

use std::io::Write;
use std::process::{Command, Stdio};

fn main() {
    // The second run, launched by passbox, which only reads its environment
    if let Ok(key) = std::env::var("API_KEY") {
        assert_eq!(key.lines().next(), Some("s3cret"));
        return;
    }

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

    let me = std::env::current_exe().expect("current exe");
    let status = Command::new("passbox")
        .args(["exec", "--env", "API_KEY=demo/api", "--"])
        .arg(me)
        .env("PASSBOX_AGENT", "self-check")
        .status()
        .expect("exec");
    assert!(status.success(), "the child did not get API_KEY");

    std::fs::remove_dir_all(&dir).ok();
    println!("all checks passed");
}
