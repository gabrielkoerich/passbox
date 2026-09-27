//! Read secrets from passbox, and hand one to a child process without holding it.
//!
//! No crate to depend on: it shells out to the CLI, so no key material enters this process.
//! Run the self-check with `rustc passbox.rs -o /tmp/passbox-example && /tmp/passbox-example`.

use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};

/// passbox caps a grant at 24 hours and refuses more, so ask for the ceiling. A shorter one
/// only means another prompt sooner, and nobody is at the sensor at 3am.
const GRANT_SECS: u64 = 86_400;

pub struct Passbox {
    /// Prepended to every lookup, so callers ask for `token` and get `github/token`
    pub namespace: Option<String>,
    /// The name the Touch ID prompt shows beside the secret
    pub agent: Option<String>,
    /// Secrets this process reads. One approval covers them all
    pub grant: Vec<String>,
    token: Option<String>,
}

impl Passbox {
    pub fn new(namespace: Option<&str>, agent: Option<&str>, grant: &[&str]) -> Self {
        Self {
            namespace: namespace.map(str::to_string),
            agent: agent.map(str::to_string),
            grant: grant.iter().map(|s| s.to_string()).collect(),
            token: None,
        }
    }

    fn name(&self, path: &str) -> String {
        match &self.namespace {
            Some(ns) => format!("{ns}/{path}"),
            None => path.to_string(),
        }
    }

    /* One approval for everything this process reads, rather than one per secret. An inherited
    PASSBOX_TOKEN wins, which is how a daemon hands one to the jobs it spawns. A grant that
    fails falls back to prompting rather than stopping the job.

    Mint once and keep it: build a fresh client per call and you mint a fresh grant per call,
    which is a fingerprint per read. */
    fn token(&mut self) -> Option<String> {
        if let Ok(inherited) = std::env::var("PASSBOX_TOKEN") {
            if !inherited.is_empty() {
                return Some(inherited);
            }
        }
        if self.token.is_some() || self.grant.is_empty() {
            return self.token.clone();
        }
        let names: Vec<String> = self.grant.iter().map(|n| self.name(n)).collect();
        let out = Command::new("passbox")
            .arg("grant")
            .args(&names)
            .args(["--for", &GRANT_SECS.to_string()])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let token = String::from_utf8_lossy(&out.stdout).trim().to_string();
        self.token = (!token.is_empty()).then_some(token);
        self.token.clone()
    }

    fn command(&mut self, args: &[&str]) -> Command {
        let mut cmd = Command::new("passbox");
        cmd.args(args);
        if let Some(agent) = self.agent.clone() {
            cmd.env("PASSBOX_AGENT", agent);
        }
        if let Some(token) = self.token() {
            cmd.env("PASSBOX_TOKEN", token);
        }
        cmd
    }

    /// The whole value. For a multi-line entry this includes the fields.
    pub fn get(&mut self, path: &str) -> Result<String, String> {
        let name = self.name(path);
        let out = self
            .command(&["get", &name])
            .output()
            .map_err(|e| format!("passbox is not on PATH: {e}"))?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }

    /// First line as `password`, then any `key: value` lines below it.
    pub fn fields(&mut self, path: &str) -> Result<HashMap<String, String>, String> {
        let whole = self.get(path)?;
        let mut out = HashMap::new();
        let mut lines = whole.trim().lines();
        if let Some(first) = lines.next() {
            out.insert("password".to_string(), first.to_string());
        }
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                let (k, v) = (k.trim().to_lowercase(), v.trim());
                if !k.is_empty() && !v.is_empty() {
                    out.insert(k, v.to_string());
                }
            }
        }
        Ok(out)
    }

    /* Prefer this over get(). The value goes from the broker into the child, so a panic or a
    core dump in this process cannot carry it. */
    pub fn run_with(&mut self, var: &str, path: &str, argv: &[&str]) -> Result<String, String> {
        let name = self.name(path);
        let out = self
            .command(&["exec", "--env", &format!("{var}={name}"), "--"])
            .args(argv)
            .output()
            .map_err(|e| format!("passbox is not on PATH: {e}"))?;
        if !out.status.success() {
            return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }

    /* Whether passbox can be used, without reading anything. Deliberately not `passbox ls`,
    which needs the store key and so raises a prompt every time it is asked. */
    pub fn is_available(&self) -> bool {
        let dir = std::env::var("PASSBOX_DIR").map(std::path::PathBuf::from).unwrap_or_else(|_| {
            std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".passbox")
        });
        dir.join("wraps").is_dir()
            && Command::new("passbox")
                .arg("--version")
                .output()
                .is_ok_and(|o| o.status.success())
    }
}

/// Round trip against a throwaway store, so it needs no hardware and raises no prompt.
fn main() {
    let dir = std::env::temp_dir().join(format!("passbox-example-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    unsafe {
        std::env::set_var("PASSBOX_DIR", &dir);
        std::env::set_var("PASSBOX_PASSPHRASE", "correct horse battery staple");
    }

    assert!(
        Command::new("passbox").arg("init").status().expect("passbox on PATH").success(),
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
        .run_with("API_KEY", "api", &["sh", "-c", "test -n \"$API_KEY\" && echo ok"])
        .unwrap();
    assert_eq!(out.trim(), "ok");

    std::fs::remove_dir_all(&dir).ok();
    println!("all checks passed");
}
