mod broker;
mod crypto;
#[cfg(feature = "host")]
mod import;
mod mcp;
#[cfg(feature = "host")]
mod project;
#[cfg(feature = "host")]
mod se;
mod store;
#[cfg(feature = "host")]
mod sync;
mod tree;
#[cfg(feature = "host")]
mod yubikey;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use secrecy::SecretString;
use std::io::{IsTerminal, Read, Write};
use store::{DEFAULT_WINDOW_SECS, Mode, Secret, Store};

const PASSPHRASE_ENV: &str = "PASSBOX_PASSPHRASE";
const MIN_PASSPHRASE: usize = 12;

#[derive(Parser)]
#[command(
    name = "passbox",
    version,
    about = "An age password store that asks before an agent reads it"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create the store, bound to this Mac's Secure Enclave and nothing else
    Init,
    /// Add or replace a secret, reading the value from stdin or a prompt
    Add {
        name: String,
        #[arg(long)]
        mode: Option<Mode>,
        #[arg(long)]
        window: Option<u64>,
    },
    /// Print a secret
    Get {
        name: String,
        /// One field of a multi-line entry, such as `username`. `password` is the first line
        #[arg(long)]
        field: Option<String>,
    },
    /// List secret names
    Ls,
    /// Delete a secret, leaving a tombstone so the delete survives a sync
    Rm { name: String },
    /// Change the permission mode of a secret
    Mode {
        name: String,
        mode: Mode,
        #[arg(long)]
        window: Option<u64>,
        /// Seconds the broker may keep this one value after an approval, for unattended jobs
        #[arg(long)]
        lease: Option<u64>,
    },
    /// List or restore earlier versions of a secret
    Restore {
        name: String,
        /// Version to restore, newest first, starting at 0
        #[arg(long)]
        index: Option<usize>,
    },
    #[cfg(feature = "host")]
    /// Bind this Mac's Secure Enclave to a store that was synced from another machine
    MachineAdd,
    #[cfg(feature = "host")]
    /// Wrap the store key to a YubiKey, so a backup needs the token rather than a passphrase
    YubikeyAdd {
        /// The `age1yubikey1...` recipient from `age-plugin-yubikey --list`
        recipient: String,
    },
    /// Run a command with secrets injected, so the value never reaches the caller
    Exec {
        /// VAR=secret, repeatable
        #[arg(long = "env", value_name = "VAR=SECRET")]
        envs: Vec<String>,
        /// Secret to pipe to the child on stdin
        #[arg(long)]
        stdin: Option<String>,
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    #[cfg(feature = "host")]
    /// Show what the broker has released, newest last
    Audit {
        #[arg(long, default_value_t = 20)]
        tail: usize,
    },
    #[cfg(feature = "host")]
    /// Copy the store to and from another machine through a shared directory
    Sync {
        /// Directory or rclone remote, default $PASSBOX_REMOTE or the iCloud Drive folder
        #[arg(long)]
        remote: Option<String>,
        /// Create the recovery passphrase that syncing needs, turning sync on
        #[arg(long)]
        enable: bool,
    },
    #[cfg(feature = "host")]
    /// Copy entries across from `pass`, all of them or one namespace
    ImportPass {
        /// A namespace such as `bean`, or one entry. Everything, if omitted.
        prefix: Option<String>,
        #[arg(long)]
        mode: Option<Mode>,
        /// Overwrite entries that are already in the store
        #[arg(long)]
        force: bool,
    },
    /// Serve MCP over stdio, so an agent asks through tools rather than a shell
    Mcp,
    /// Run git inside the store, for `passbox git init`, `remote add`, `log` and the rest
    Git {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        args: Vec<String>,
    },
    /// Serve the approval socket, started on demand by the other commands
    #[cfg(feature = "host")]
    #[command(hide = true)]
    Broker,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("passbox: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let store = Store::open()?;

    match cli.command {
        Command::Init => init(&store),
        Command::Add { name, mode, window } => add(&store, &name, mode, window),
        Command::Get { name, field } => get(&store, &name, field.as_deref()),
        Command::Ls => ls(&store),
        Command::Rm { name } => rm(&store, &name),
        Command::Mode {
            name,
            mode,
            window,
            lease,
        } => set_mode(&store, &name, mode, window, lease),
        Command::Restore { name, index } => restore(&store, &name, index),
        #[cfg(feature = "host")]
        Command::MachineAdd => machine_add(&store),
        #[cfg(feature = "host")]
        Command::YubikeyAdd { recipient } => yubikey_add(&store, &recipient),
        Command::Exec {
            envs,
            stdin,
            command,
        } => exec(&store, &envs, stdin.as_deref(), &command),
        #[cfg(feature = "host")]
        Command::Audit { tail } => audit(&store, tail),
        #[cfg(feature = "host")]
        Command::Sync { remote, enable } => run_sync(&store, remote.as_deref(), enable),
        #[cfg(feature = "host")]
        Command::ImportPass {
            prefix,
            mode,
            force,
        } => import_pass(&store, prefix.as_deref(), mode, force),
        Command::Mcp => mcp::serve(store),
        Command::Git { args } => git(&store, &args),
        #[cfg(feature = "host")]
        Command::Broker => broker::serve(store),
    }
}

/* git carries the encrypted secrets and nothing that opens them. The Enclave wraps are useless
off the Mac that made them, so they stay out. The recovery wrap only exists once sync is on, and
then it belongs in the backup, because without it the backup cannot be restored anywhere. */
fn ensure_store_gitignore(store: &Store) -> Result<()> {
    let path = store.dir.join(".gitignore");
    if !path.exists() {
        std::fs::write(
            &path,
            "broker.sock\nstore/.versions/\nwraps/se-*.json\ngrants-*.age\n",
        )?;
    }
    Ok(())
}

/// Saves cd-ing into the store. Values stay encrypted, so git only ever sees opaque files.
fn git(store: &Store, args: &[String]) -> Result<()> {
    ensure_store_gitignore(store)?;
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(&store.dir)
        .args(args)
        .status()
        .context("git is not on PATH")?;
    std::process::exit(status.code().unwrap_or(1));
}

#[cfg(feature = "host")]
fn run_sync(store: &Store, remote: Option<&str>, enable: bool) -> Result<()> {
    if enable {
        enable_sync(store)?;
    // An empty directory is a machine joining, and the wrap it needs arrives with the pull
    } else if store.is_initialised() && !store.has_portable_wrap() {
        bail!(
            "sync is off. No other machine could open this store, because the key is held by \
             this Mac's Secure Enclave alone. Add a way in first: `passbox sync --enable` for \
             a recovery passphrase, or `passbox yubikey-add` for a token."
        );
    }

    let remote = match remote {
        Some(given) => given.to_string(),
        None => sync::default_remote(store)?,
    };

    match sync::classify(&remote) {
        // git carries its own history, so there is no directory to copy into
        sync::Kind::Git => git_push(store),
        sync::Kind::Rclone => {
            sync::sync_via_rclone(store, &remote)?;
            git_push(store);
        }
        sync::Kind::Directory => {
            let report = sync::sync(store, std::path::Path::new(&remote))?;
            eprintln!(
                "{} sent, {} received, {remote}",
                report.pushed, report.pulled
            );
            git_push(store);
        }
    }
    Ok(())
}

/// Optional history alongside the copy. A subject naming an entry would undo the encrypted names.
#[cfg(feature = "host")]
fn git_push(store: &Store) {
    if !store.dir.join(".git").exists() {
        return;
    }
    let _ = ensure_store_gitignore(store);
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(&store.dir)
            .args(args)
            .status()
    };
    let _ = git(&["add", "-A"]);
    let _ = git(&["commit", "-m", "update"]);
    let _ = git(&["push"]);
}

/// Advisory, since the broker cannot verify it. The prompt shows it beside the secret name.
fn agent() -> String {
    std::env::var("PASSBOX_AGENT").unwrap_or_else(|_| "passbox".to_string())
}

fn read_secret(store: &Store, name: &str, for_agent: bool) -> Result<String> {
    read_secret_as(store, name, &agent(), for_agent)
}

pub fn agent_read_secret(store: &Store, name: &str, agent: &str) -> Result<String> {
    read_secret_as(store, name, agent, true)
}

/// The broker owns windows and the audit log, so every read goes through it when it can.
/// Without an Enclave there is nothing to prompt with, and the passphrase becomes the gate.
fn read_secret_as(store: &Store, name: &str, agent: &str, for_agent: bool) -> Result<String> {
    if !headless() && store.has_se_wrap() {
        return broker::request(store, name, agent);
    }
    let key = unlock(store, &format!("release the password for {name}"))?;
    let (_, secret) = store
        .find(name, &key)?
        .with_context(|| format!("no secret named {name}"))?;
    if for_agent && secret.mode == Mode::Never {
        bail!("{name} is marked never, refusing");
    }
    Ok(secret.value.clone())
}

fn exec(store: &Store, envs: &[String], stdin: Option<&str>, command: &[String]) -> Result<()> {
    let (program, args) = command.split_first().context("no command to run")?;
    let mut child = std::process::Command::new(program);
    child.args(args);

    for pair in envs {
        let (var, name) = pair
            .split_once('=')
            .with_context(|| format!("expected VAR=secret, got {pair}"))?;
        child.env(var, read_secret(store, name, true)?);
    }

    let piped = match stdin {
        Some(name) => Some(read_secret(store, name, true)?),
        None => None,
    };
    child.stdin(if piped.is_some() {
        std::process::Stdio::piped()
    } else {
        std::process::Stdio::inherit()
    });

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
    std::process::exit(status.code().unwrap_or(1));
}

#[cfg(feature = "host")]
fn audit(store: &Store, tail: usize) -> Result<()> {
    let path = store.audit_path();
    if !path.exists() {
        eprintln!("nothing released on this machine yet");
        return Ok(());
    }
    let key = unlock(store, "read the audit log")?;
    let text = std::fs::read_to_string(&path)?;
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();

    for line in lines.iter().skip(lines.len().saturating_sub(tail)) {
        match crypto::decrypt_line(line, &key) {
            Ok(record) => println!("{}", String::from_utf8_lossy(&record)),
            Err(e) => eprintln!("unreadable record: {e:#}"),
        }
    }
    Ok(())
}

fn init(store: &Store) -> Result<()> {
    let key = store.init()?;
    eprintln!("store ready at {}", store.dir.display());

    // Without an Enclave there is nothing holding the key, so a passphrase is the only option
    #[cfg(not(feature = "host"))]
    let bound = false;
    #[cfg(feature = "host")]
    let bound = bind_machine(store, &key);
    if headless() || !bound {
        new_passphrase(store, &key)?;
    } else {
        eprintln!();
        eprintln!("This store opens on this Mac only. Lose it and the secrets are gone.");
        eprintln!("`passbox sync --enable` adds a passphrase and a copy on another machine.");
    }
    Ok(())
}

#[cfg(feature = "host")]
fn enable_sync(store: &Store) -> Result<()> {
    // How the copy is opened and where it goes are separate questions
    if store.has_portable_wrap() {
        eprintln!("the store already has a wrap that opens it elsewhere");
        return choose_remote(store);
    }

    eprintln!("Syncing puts a copy of this store where another machine can read it.");
    eprintln!("That copy needs a way in. Two choices:");
    eprintln!();
    eprintln!("  1) A YubiKey. Nothing in the copy can be attacked, and you keep the token.");
    eprintln!("  2) A passphrase. Works anywhere, and anyone holding the copy can grind it.");
    eprintln!();
    eprint!("Which? [1/2] ");

    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    match answer.trim() {
        "1" => enable_with_yubikey(store)?,
        "2" => {
            let key = unlock(store, "turn on sync")?;
            new_passphrase(store, &key)?;
            eprintln!("sync is on, wraps/recovery.age now travels with the store");
        }
        other => bail!("expected 1 or 2, got {other}"),
    }
    choose_remote(store)
}

/// Asked once and remembered, so a later bare `passbox sync` cannot surprise you with iCloud
#[cfg(feature = "host")]
fn choose_remote(store: &Store) -> Result<()> {
    // Only `sync --enable` reaches here, so a destination already set is one to offer changing
    if let Some(already) = sync::configured_remote(store) {
        eprintln!("copies currently go to {already}");
        eprint!("Change that? [y/N] ");
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
            return Ok(());
        }
        std::fs::remove_file(sync::remote_path(store)).ok();
    }

    eprintln!();
    eprintln!("Where should the copy go?");
    eprintln!();
    eprintln!("  1) iCloud Drive, a folder on this Mac that Apple replicates");
    eprintln!("  2) A directory you name, such as a USB stick or Dropbox");
    eprintln!("  3) A git remote, which also gives you history");
    eprintln!("  4) An rclone remote, for S3, B2, Drive and the rest");
    eprintln!();
    eprint!("Which? [1/2/3/4] ");

    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;

    let remote = match answer.trim() {
        "1" => sync::default_remote(store)?,
        "2" => prompt("directory: ")?,
        "3" => {
            let url = prompt("git remote, such as git@github.com:you/passbox-store.git: ")?;
            git(store, &["init".into()]).ok();
            git(
                store,
                &["remote".into(), "add".into(), "origin".into(), url.clone()],
            )
            .ok();
            url
        }
        "4" => prompt("rclone remote, such as b2:passbox: ")?,
        other => bail!("expected 1 to 4, got {other}"),
    };

    store::write_private(&sync::remote_path(store), remote.trim().as_bytes())?;
    eprintln!("copies go to {}", remote.trim());
    Ok(())
}

#[cfg(feature = "host")]
fn prompt(label: &str) -> Result<String> {
    eprint!("{label}");
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    let answer = answer.trim().to_string();
    if answer.is_empty() {
        bail!("nothing given");
    }
    Ok(answer)
}

#[cfg(feature = "host")]
fn enable_with_yubikey(store: &Store) -> Result<()> {
    yubikey::offer_install()?;

    let mut found = yubikey::recipients()?;
    if found.is_empty() {
        eprintln!("No age identity on the token yet. Generating one uses a PIV slot.");
        match yubikey::piv_slots_in_use() {
            Some(slots) if !slots.is_empty() => {
                eprintln!("The PIV applet already holds:");
                for slot in &slots {
                    eprintln!("  {slot}");
                }
                eprintln!("A free slot is used, and your OpenPGP keys are a separate applet.");
            }
            Some(_) => eprintln!("The PIV applet is empty, and OpenPGP is a separate applet."),
            None => eprintln!("Could not read the PIV applet. Install ykman to check it first."),
        }
        // Fail here rather than after the plugin has asked for a PIN it cannot use
        yubikey::management_key_is_supported()?;
        eprint!("Generate one now? [y/N] ");
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
            bail!("run `age-plugin-yubikey --generate` when ready, then try again");
        }
        yubikey::offer_to_stop_scdaemon()?;
        yubikey::generate()?;
        found = yubikey::recipients()?;
    }

    let recipient = found
        .first()
        .context("no YubiKey recipient found, is the token plugged in?")?;
    eprintln!("using {recipient}");

    let key = unlock(store, "turn on sync with a YubiKey")?;
    let total = store.add_yubikey_recipient(&key, recipient)?;
    eprintln!("sync is on, and the copy is useless without one of those {total} token(s)");
    eprintln!("add a second with `passbox yubikey-add`, or losing it loses the way back");
    Ok(())
}

/// Sync needs this: no other machine can open the store without it
fn new_passphrase(store: &Store, key: &age::x25519::Identity) -> Result<()> {
    let pass = ask("recovery passphrase: ")?;
    if pass.chars().count() < MIN_PASSPHRASE {
        bail!("use at least {MIN_PASSPHRASE} characters, a copy of this leaves the Mac");
    }
    if !headless() && ask("again: ")? != pass {
        bail!("passphrases do not match");
    }
    store.create_recovery_wrap_with_factor(key, SecretString::from(pass), test_work_factor())
}

/// Only a debug build will weaken the KDF, so a release binary cannot be talked into it
fn test_work_factor() -> Option<u8> {
    #[cfg(debug_assertions)]
    {
        std::env::var("PASSBOX_SCRYPT_LOG_N")
            .ok()
            .and_then(|v| v.parse().ok())
    }
    #[cfg(not(debug_assertions))]
    {
        None
    }
}

/// True when the Enclave took the key. An older Mac or CI cannot, and falls back to a passphrase.
#[cfg(feature = "host")]
fn bind_machine(store: &Store, key: &age::x25519::Identity) -> bool {
    if headless() {
        return false;
    }
    match store.create_se_wrap(key) {
        Ok(()) => {
            eprintln!("bound to this Mac, reads will ask for your fingerprint");
            true
        }
        Err(e) => {
            eprintln!("no Secure Enclave here ({e:#}), reads will ask for the passphrase");
            false
        }
    }
}

/// `PASSBOX_PASSPHRASE` says nobody is at the keyboard, and a fingerprint needs somebody
fn headless() -> bool {
    std::env::var_os(PASSPHRASE_ENV).is_some()
}

fn unlock(store: &Store, reason: &str) -> Result<age::x25519::Identity> {
    #[cfg(feature = "host")]
    if !headless() && store.has_se_wrap() {
        return store.unlock_with_se(reason);
    }
    let _ = reason;
    store.unlock_with_passphrase(SecretString::from(ask("passphrase: ")?))
}

/* A YubiKey wrap replaces the passphrase for recovery. Nothing in a synced copy can then be
attacked offline, because the private half never leaves the token. */
#[cfg(feature = "host")]
fn yubikey_add(store: &Store, recipient: &str) -> Result<()> {
    yubikey::offer_install()?;
    let key = unlock(store, "wrap the store key to a YubiKey")?;
    let total = store.add_yubikey_recipient(&key, recipient)?;
    eprintln!("wrapped to {recipient}");
    eprintln!("{total} token(s) can now open this store on any machine");
    if total == 1 {
        eprintln!("add a second with `passbox yubikey-add`, or losing it loses the way back");
    }
    Ok(())
}

#[cfg(feature = "host")]
fn machine_add(store: &Store) -> Result<()> {
    if store.has_se_wrap() {
        bail!(
            "this Mac is already bound, its wrap is {}",
            store.se_wrap_path().display()
        );
    }
    let key = if store.has_yubikey_wrap() && yubikey::installed() {
        eprintln!("Touch the YubiKey to bind this Mac.");
        store.unlock_with_yubikey()?
    } else {
        eprintln!("Binding this Mac needs the recovery passphrase once.");
        store.unlock_with_passphrase(SecretString::from(ask("recovery passphrase: ")?))?
    };
    store.create_se_wrap(&key)?;
    eprintln!("bound, reads on this Mac will ask for your fingerprint");
    Ok(())
}

/// `PASSBOX_PASSPHRASE` exists for CI and for headless use, where there is no terminal to type at
fn ask(prompt: &str) -> Result<String> {
    match std::env::var(PASSPHRASE_ENV) {
        Ok(pass) => Ok(pass),
        Err(_) => Ok(rpassword::prompt_password(prompt)?),
    }
}

fn add(store: &Store, name: &str, mode: Option<Mode>, window: Option<u64>) -> Result<()> {
    let recipient = store.recipient()?;
    let value = read_value()?;
    if value.is_empty() {
        bail!("refusing to store an empty value");
    }

    // Replacing needs the name to id map, which only the key can produce
    let existing = if store.ids()?.is_empty() {
        None
    } else {
        let key = unlock(store, &format!("replace {name}"))?;
        store
            .find(name, &key)?
            .map(|(id, s)| (id, s.created, s.mode, s.window_secs, s.lease_secs))
    };

    // A new value must never widen access, so an unnamed mode keeps what the secret already had
    let secret = match existing {
        Some((id, created, old_mode, old_window, old_lease)) => (
            id,
            Secret {
                name: name.to_string(),
                mode: mode.unwrap_or(old_mode),
                window_secs: window.unwrap_or(old_window),
                lease_secs: old_lease,
                value,
                created,
                updated: store::now(),
            },
        ),
        None => (
            store::new_id(),
            Secret {
                name: name.to_string(),
                mode: mode.unwrap_or(Mode::Window),
                window_secs: window.unwrap_or(DEFAULT_WINDOW_SECS),
                lease_secs: 0,
                value,
                created: store::now(),
                updated: store::now(),
            },
        ),
    };
    let (id, secret) = secret;
    store.put(&id, &secret, &recipient)?;
    eprintln!("stored {name} as {}", secret.mode);
    Ok(())
}

#[cfg(feature = "host")]
fn import_pass(store: &Store, prefix: Option<&str>, mode: Option<Mode>, force: bool) -> Result<()> {
    let dir = import::store_dir();
    let all = import::entries(&dir)?;
    if all.is_empty() {
        bail!("no pass entries under {}", dir.display());
    }

    let picked = import::select(&all, prefix);
    if picked.is_empty() {
        bail!(
            "nothing in pass matches {}, of {} entries",
            prefix.unwrap_or("*"),
            all.len()
        );
    }
    eprintln!("importing {} of {} entries", picked.len(), all.len());

    // Spotting duplicates needs the name to id map, which only the key can produce
    let key = if store.ids()?.is_empty() {
        None
    } else {
        Some(unlock(store, "import entries from pass")?)
    };

    let report = import::import(
        store,
        &picked,
        key.as_ref(),
        mode.unwrap_or(Mode::Window),
        force,
    )?;
    eprintln!("imported {}, skipped {}", report.imported, report.skipped);
    Ok(())
}

/* The `pass` layout, which import keeps: the first line is the secret and later `key: value`
lines are fields. Reading one field hands a caller the password without the note beside it. */
fn fields(value: &str) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    let mut lines = value.lines();
    if let Some(first) = lines.next() {
        out.insert("password".to_string(), first.to_string());
    }
    for line in lines {
        if let Some((key, v)) = line.split_once(':') {
            let (key, v) = (key.trim().to_lowercase(), v.trim());
            if !key.is_empty() && !v.is_empty() {
                out.insert(key, v.to_string());
            }
        }
    }
    out
}

fn get(store: &Store, name: &str, field: Option<&str>) -> Result<()> {
    let whole = read_secret(store, name, false)?;
    let value = match field {
        None => whole,
        Some(want) => fields(&whole)
            .remove(want)
            .with_context(|| format!("{name} has no field {want}"))?,
    };
    let mut out = std::io::stdout();
    out.write_all(value.as_bytes())?;
    if out.is_terminal() {
        out.write_all(b"\n")?;
    }
    Ok(())
}

/// Through the broker, so a second listing inside the window does not ask again
pub fn agent_list_names(store: &Store, agent: &str) -> Result<Vec<String>> {
    if !headless() && store.has_se_wrap() {
        return broker::list(store, agent);
    }
    let key = unlock(store, "list your secret names")?;
    store.names(&key)
}

/// Captures the child's output instead of inheriting, which is what a tool result needs
pub fn run_child(
    command: &[String],
    env_var: Option<&str>,
    value: &str,
) -> Result<std::process::Output> {
    let (program, args) = command.split_first().context("no command to run")?;
    let mut child = std::process::Command::new(program);
    child
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

/// A tree for a terminal, one name per line for anything reading the output
fn ls(store: &Store) -> Result<()> {
    let names = agent_list_names(store, &agent())?;
    let mut out = std::io::stdout();
    if out.is_terminal() {
        out.write_all(tree::render(&names, true).as_bytes())?;
    } else {
        for name in names {
            writeln!(out, "{name}")?;
        }
    }
    Ok(())
}

fn rm(store: &Store, name: &str) -> Result<()> {
    let key = unlock(store, &format!("delete {name}"))?;
    let (id, _) = store
        .find(name, &key)?
        .with_context(|| format!("no secret named {name}"))?;
    store.delete(&id)?;
    store.prune_tombs()?;
    eprintln!("deleted {name}, recoverable with `passbox restore {name}`");
    Ok(())
}

fn set_mode(
    store: &Store,
    name: &str,
    mode: Mode,
    window: Option<u64>,
    lease: Option<u64>,
) -> Result<()> {
    let key = unlock(store, &format!("change the permission mode of {name}"))?;
    let recipient = store.recipient()?;
    let (id, mut secret) = store
        .find(name, &key)?
        .with_context(|| format!("no secret named {name}"))?;
    secret.mode = mode;
    if let Some(w) = window {
        secret.window_secs = w;
    }
    if let Some(l) = lease {
        secret.lease_secs = l;
    }
    secret.updated = store::now();
    store.put(&id, &secret, &recipient)?;
    eprintln!("{name} is now {mode}");
    if secret.lease_secs > 0 {
        eprintln!(
            "one approval then holds {name} for {}s, and no other secret",
            secret.lease_secs
        );
    }
    Ok(())
}

fn restore(store: &Store, name: &str, index: Option<usize>) -> Result<()> {
    let key = unlock(store, &format!("restore {name}"))?;
    let id = match store.find(name, &key)? {
        Some((id, _)) => id,
        None => find_deleted(store, name, &key)?,
    };

    // A delete that arrived through a sync left the file behind, so lifting the tombstone is enough
    if store.tomb_path(&id).exists() && store.secret_path(&id).exists() {
        store.untomb(&id)?;
        eprintln!("restored {name}");
        return Ok(());
    }

    // Newest first, so index 0 is the most recent version
    let mut versions = store.versions(&id)?;
    versions.reverse();
    if versions.is_empty() {
        bail!("no earlier versions of {name}");
    }

    let Some(index) = index else {
        for (i, (stamp, path)) in versions.iter().enumerate() {
            let bytes = store
                .load_path(path, &key)
                .map(|s| s.value.len())
                .unwrap_or(0);
            println!("{i}\t{stamp}\t{bytes} bytes");
        }
        eprintln!("restore one with `passbox restore {name} --index N`");
        return Ok(());
    };

    let (_, path) = versions
        .get(index)
        .with_context(|| format!("no version {index}"))?;
    let bytes = std::fs::read(path)?;
    store.keep_version(&id)?;
    store::write_private(&store.secret_path(&id), &bytes)?;
    let tomb = store.tomb_path(&id);
    if tomb.exists() {
        std::fs::remove_file(tomb)?;
    }
    eprintln!("restored {name}");
    Ok(())
}

/// A deleted secret is hidden from `ids`, so look through tombstoned files and then versions.
fn find_deleted(store: &Store, name: &str, key: &age::x25519::Identity) -> Result<String> {
    for id in store.ids_with_files()? {
        if let Ok(secret) = store.load(&id, key)
            && secret.name == name
        {
            return Ok(id);
        }
    }

    let dir = store.versions_dir();
    if dir.exists() {
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            let Some(id) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            for (_, version) in store.versions(id)? {
                if let Ok(secret) = store.load_path(&version, key)
                    && secret.name == name
                {
                    return Ok(id.to_string());
                }
            }
        }
    }
    bail!("no secret named {name}")
}

fn read_value() -> Result<String> {
    if std::io::stdin().is_terminal() {
        let value = rpassword::prompt_password("value: ")?;
        if rpassword::prompt_password("again: ")? != value {
            bail!("values do not match");
        }
        return Ok(value);
    }
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    Ok(buf.trim_end_matches('\n').to_string())
}

#[cfg(test)]
mod tests {
    use super::fields;

    #[test]
    fn the_first_line_is_the_password() {
        let f = fields("s3cret\nusername: bot\nhost: example.com");
        assert_eq!(f["password"], "s3cret");
        assert_eq!(f["username"], "bot");
        assert_eq!(f["host"], "example.com");
    }

    #[test]
    fn a_value_holding_a_colon_survives() {
        let f = fields("pw\nurl: https://example.com:8443/x");
        assert_eq!(f["url"], "https://example.com:8443/x");
    }

    #[test]
    fn a_single_line_secret_has_only_a_password() {
        let f = fields("just-a-token");
        assert_eq!(f["password"], "just-a-token");
        assert_eq!(f.len(), 1);
    }
}
