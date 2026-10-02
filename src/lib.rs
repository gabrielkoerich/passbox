//! Read secrets from passbox, and hand one to a child process without holding it.
//!
//! It shells out to the `passbox` CLI, so no key material enters this process and the broker,
//! the prompt and the audit log apply as they do to any other caller.
//!
//! This crate also builds the `passbox` CLI. A program that only uses the library adds it with
//! `default-features = false`, which skips the Swift helper and builds on Linux too.

use std::collections::HashMap;
use std::process::Command;

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
        if let Ok(inherited) = std::env::var("PASSBOX_TOKEN")
            && !inherited.is_empty()
        {
            return Some(inherited);
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
        Ok(parse_fields(&self.get(path)?))
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
        let dir = std::env::var("PASSBOX_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".passbox")
            });
        dir.join("wraps").is_dir()
            && Command::new("passbox")
                .arg("--version")
                .output()
                .is_ok_and(|o| o.status.success())
    }
}

/// First line as `password`, then any `key: value` lines below it
pub fn parse_fields(whole: &str) -> HashMap<String, String> {
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
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_split_the_password_from_the_rest() {
        let f = parse_fields("s3cret\nUsername: bot\nurl: https://example.com\nnote:\n");
        assert_eq!(f["password"], "s3cret");
        assert_eq!(f["username"], "bot");
        assert_eq!(f["url"], "https://example.com");
        assert!(!f.contains_key("note"));
    }

    #[test]
    fn a_namespace_prefixes_every_name() {
        assert_eq!(
            Passbox::new(Some("acme"), None, &[]).name("token"),
            "acme/token"
        );
        assert_eq!(Passbox::new(None, None, &[]).name("token"), "token");
    }
}
