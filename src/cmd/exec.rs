//! Running a command with secrets injected, so a value goes to the child and never to the caller.

use crate::store::{self, Store};
use crate::{agent, broker, brokered, read_secret};
use crate::{held_token, without_credentials};
use anyhow::{Context, Result};
use std::io::Write;

/// Long enough for exec to read its batch, short enough that the token is useless after
const EXEC_GRANT_SECS: u64 = 30;

// Two or more broker reads would prompt once each, so grant them together and read through the
// token. A held PASSBOX_TOKEN, or a refused grant, keeps one read per secret
fn batch_token(store: &Store, names: &[&str]) -> Option<String> {
    let mut names: Vec<String> = names.iter().copied().map(String::from).collect();
    names.sort();
    names.dedup();
    if names.len() < 2 || !brokered(store) || held_token().is_some() {
        return None;
    }

    let answer = broker::grant(store, &names, &agent(), EXEC_GRANT_SECS).ok()?;
    answer.lines().next().map(str::to_string)
}

/// A private directory holding injected values as files. It is wiped and removed on drop
struct SecretFiles {
    dir: std::path::PathBuf,
}

impl SecretFiles {
    fn new() -> Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        let dir = std::env::temp_dir().join(format!("passbox-{}", store::new_id()));
        std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
        Ok(SecretFiles { dir })
    }

    fn is_empty(&self) -> bool {
        std::fs::read_dir(&self.dir).is_ok_and(|mut d| d.next().is_none())
    }

    fn write(&self, index: usize, value: &str) -> Result<std::path::PathBuf> {
        let path = self.dir.join(index.to_string());
        let mut bytes = value.as_bytes().to_vec();
        if !bytes.ends_with(b"\n") {
            bytes.push(b'\n');
        }
        store::write_private(&path, &bytes)?;
        zeroize::Zeroize::zeroize(&mut bytes);
        Ok(path)
    }
}

impl Drop for SecretFiles {
    fn drop(&mut self) {
        if let Ok(entries) = std::fs::read_dir(&self.dir) {
            for entry in entries.flatten() {
                let len = entry
                    .metadata()
                    .ok()
                    .and_then(|m| usize::try_from(m.len()).ok())
                    .unwrap_or(0);
                let _ = std::fs::write(entry.path(), vec![0u8; len]);
            }
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn split_pairs(pairs: &[String]) -> Result<Vec<(&str, &str)>> {
    pairs
        .iter()
        .map(|pair| {
            pair.split_once('=')
                .with_context(|| format!("expected VAR=secret, got {pair}"))
        })
        .collect()
}

pub(crate) fn exec(
    store: &Store,
    envs: &[String],
    files: &[String],
    stdin: Option<&str>,
    command: &[String],
) -> Result<()> {
    let (program, args) = command.split_first().context("no command to run")?;
    let mut child = std::process::Command::new(program);
    // Before the injected secrets, so an explicit --env PASSBOX_TOKEN=name still reaches the child
    without_credentials(&mut child).args(args);

    let pairs = split_pairs(envs)?;
    let file_pairs = split_pairs(files)?;

    let names: Vec<&str> = pairs
        .iter()
        .chain(&file_pairs)
        .map(|(_, name)| *name)
        .chain(stdin)
        .collect();
    let token = batch_token(store, &names);
    let read = |name: &str| match &token {
        Some(token) => broker::request_token(store, name, &agent(), token),
        None => read_secret(store, name),
    };

    for (var, name) in pairs {
        child.env(var, read(name)?);
    }

    // Held until the child exits, so the files are gone whatever the child does
    let secret_files = SecretFiles::new()?;
    for (index, (var, name)) in file_pairs.into_iter().enumerate() {
        let mut value = read(name)?;
        let path = secret_files.write(index, &value);
        zeroize::Zeroize::zeroize(&mut value);
        child.env(var, path?);
    }

    let piped = match stdin {
        Some(name) => Some(read(name)?),
        None => None,
    };
    child.stdin(if piped.is_some() {
        std::process::Stdio::piped()
    } else {
        std::process::Stdio::inherit()
    });

    // A handler, not SIG_IGN, because an ignored signal stays ignored in the child. Ctrl-C then
    // reaches the child alone and this process lives to remove the files
    if !secret_files.is_empty() {
        extern "C" fn nothing(_: libc::c_int) {}
        #[expect(
            clippy::as_conversions,
            reason = "signal(2) takes the handler as an address, which only `as` produces"
        )]
        let handler = nothing as extern "C" fn(libc::c_int) as libc::sighandler_t;
        for signal in [libc::SIGINT, libc::SIGHUP, libc::SIGTERM] {
            // SAFETY: the handler does nothing, so it is safe to run at any point
            unsafe { libc::signal(signal, handler) };
        }
    }

    let mut running = child
        .spawn()
        .with_context(|| format!("could not run {program}"))?;
    if let Some(value) = piped {
        running
            .stdin
            .as_mut()
            .expect("piped")
            .write_all(value.as_bytes())?;
        drop(running.stdin.take());
    }

    let status = running.wait()?;
    // exit skips destructors, so the files go first
    drop(secret_files);
    std::process::exit(status.code().unwrap_or(1));
}

/// Captures the child's output instead of inheriting, which is what a tool result needs
pub(crate) fn run_child(
    command: &[String],
    env_var: Option<&str>,
    value: &str,
) -> Result<std::process::Output> {
    let (program, args) = command.split_first().context("no command to run")?;
    let mut child = std::process::Command::new(program);
    without_credentials(&mut child)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    match env_var {
        Some(var) => {
            child.env(var, value);
            child.stdin(std::process::Stdio::null());
        }
        None => {
            child.stdin(std::process::Stdio::piped());
        }
    }

    let mut running = child
        .spawn()
        .with_context(|| format!("could not run {program}"))?;
    if env_var.is_none() {
        running
            .stdin
            .as_mut()
            .expect("piped")
            .write_all(value.as_bytes())?;
        drop(running.stdin.take());
    }
    Ok(running.wait_with_output()?)
}
