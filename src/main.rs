mod broker;
mod crypto;
#[cfg(feature = "host")]
mod import;
mod mcp;
#[cfg(feature = "host")]
mod plugin;
#[cfg(feature = "host")]
mod project;
#[cfg(feature = "host")]
mod se;
#[cfg(feature = "host")]
mod ssh;
mod store;
#[cfg(feature = "host")]
mod sync;
#[cfg(feature = "host")]
mod tailnet;
mod tree;
#[cfg(feature = "host")]
mod yubikey;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use std::alloc::{GlobalAlloc, Layout, System};
use zeroize::Zeroize;

/* Every freed block is wiped before the system allocator gets it back. Decrypting, parsing JSON
and decoding keys all pass plaintext through buffers owned by age, serde_json and std, which free
them without wiping, so wiping at the one place every free goes through catches all of them.
The default `realloc` frees through `dealloc`, so a buffer that grows is wiped too. */
struct WipeOnFree<A>(A);

unsafe impl<A: GlobalAlloc> GlobalAlloc for WipeOnFree<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { self.0.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe {
            std::slice::from_raw_parts_mut(ptr, layout.size()).zeroize();
            self.0.dealloc(ptr, layout)
        }
    }
}

#[global_allocator]
static ALLOCATOR: WipeOnFree<System> = WipeOnFree(System);
use secrecy::SecretString;
use std::io::{IsTerminal, Read, Write};
use store::{Secret, Store};

const PASSPHRASE_ENV: &str = "PASSBOX_PASSPHRASE";
const MIN_PASSPHRASE: usize = 12;

// A token opens its grants and the passphrase opens the whole store, so a command passbox runs
// for someone else inherits neither, or it could print them into a transcript
pub fn without_credentials(command: &mut std::process::Command) -> &mut std::process::Command {
    command
        .env_remove("PASSBOX_TOKEN")
        .env_remove(PASSPHRASE_ENV)
}

struct Held {
    token: Option<zeroize::Zeroizing<String>>,
    passphrase: Option<zeroize::Zeroizing<String>>,
}

static HELD: std::sync::OnceLock<Held> = std::sync::OnceLock::new();

/**
 * Moves the token and the passphrase out of the environment before anything else runs, so nothing
 * passbox starts can inherit them, git and the broker included. Unsetting a variable leaves its
 * bytes where exec placed them, and `ps eww` and `/proc/<pid>/environ` read that original block,
 * so the value is overwritten in place first
 **/
fn take_credentials() {
    let _ = HELD.set(Held {
        token: take_env("PASSBOX_TOKEN"),
        passphrase: take_env(PASSPHRASE_ENV),
    });
}

fn take_env(name: &str) -> Option<zeroize::Zeroizing<String>> {
    let value = zeroize::Zeroizing::new(std::env::var(name).ok()?);
    wipe_env_value(name);
    // SAFETY: called first thing in main, while this is the only thread
    unsafe { std::env::remove_var(name) };
    Some(value)
}

fn wipe_env_value(name: &str) {
    use zeroize::Zeroize;
    #[cfg(target_os = "macos")]
    // SAFETY: the C runtime's own pointer to the environment table
    let mut entry = unsafe { *libc::_NSGetEnviron() };
    #[cfg(not(target_os = "macos"))]
    // SAFETY: the C runtime's own pointer to the environment table
    let mut entry = unsafe { environ };
    let prefix = format!("{name}=");

    // SAFETY: walks the NUL terminated table and only writes inside the matched entry's value
    unsafe {
        while !(*entry).is_null() {
            let bytes = std::ffi::CStr::from_ptr(*entry).to_bytes();
            if let Some(value) = bytes.strip_prefix(prefix.as_bytes()) {
                let start = (*entry).add(prefix.len()).cast::<u8>();
                std::slice::from_raw_parts_mut(start, value.len()).zeroize();
            }
            entry = entry.add(1);
        }
    }
}

#[cfg(not(target_os = "macos"))]
unsafe extern "C" {
    static environ: *mut *mut libc::c_char;
}

static STDIN_TOKEN: std::sync::OnceLock<zeroize::Zeroizing<String>> = std::sync::OnceLock::new();

/// The token this process was started with, held outside the environment. `--token-stdin` wins
pub fn held_token() -> Option<&'static str> {
    if let Some(token) = STDIN_TOKEN.get() {
        return Some(token.as_str());
    }

    HELD.get()?.token.as_deref().map(String::as_str)
}

// One line, a byte at a time, so a buffer cannot take input the exec child should get
fn take_stdin_token() -> Result<()> {
    use std::os::unix::io::FromRawFd;
    // SAFETY: fd 0 stays open, ManuallyDrop keeps this File from closing it
    let mut stdin = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(0) });
    let mut token = zeroize::Zeroizing::new(String::new());
    let mut byte = [0u8; 1];
    while stdin.read(&mut byte)? == 1 && byte[0] != b'\n' {
        token.push(byte[0] as char);
    }
    let token = zeroize::Zeroizing::new(token.trim().to_string());
    if token.is_empty() {
        bail!("--token-stdin read no token");
    }

    let _ = STDIN_TOKEN.set(token);
    Ok(())
}

fn held_passphrase() -> Option<&'static str> {
    HELD.get()?.passphrase.as_deref().map(String::as_str)
}

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
    /// Add a secret, reading the value from stdin or a prompt. An existing name is refused
    Add {
        name: String,
        /// After the value, ask for `key: value` fields and notes, one per line
        #[arg(short, long)]
        multiline: bool,
        /// After the value, ask for this field, such as `username`. Repeatable
        #[arg(long = "field", value_name = "NAME")]
        fields: Vec<String>,
    },
    /// Print a secret
    Get {
        name: String,
        /// One field of a multi-line entry, such as `username`. `password` is the first line
        #[arg(long)]
        field: Option<String>,
    },
    /// Copy a secret to the clipboard, which clears after a few seconds and skips clipboard history
    Copy {
        name: String,
        /// One field of a multi-line entry, such as `username`
        #[arg(long)]
        field: Option<String>,
        /// Seconds before the clipboard is cleared, at most a minute so a secret never lingers there
        #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u64).range(1..=60))]
        clear: u64,
    },
    /// Approve named secrets once, and print a token that opens only those
    Grant {
        /// Secret names, such as `acme/api-key acme/signing-key`. A namespace is refused
        #[arg(required = true)]
        names: Vec<String>,
        /// Seconds the token stays valid, capped at 24 hours. Default an hour, or the parent's life
        #[arg(long)]
        r#for: Option<u64>,
        /// Read a parent token from stdin. A subset of its names, ending no later, mints with no prompt
        #[arg(long)]
        token_stdin: bool,
    },
    /// List secret names
    Ls,
    /// Delete a secret, leaving a tombstone so the delete survives a sync
    Rm { name: String },
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
        /// The `age1yubikey1...` recipient, or none to use the plugged token and set it up if needed
        recipient: Option<String>,
    },
    /// Run a command with secrets injected, so the value never reaches the caller
    Exec {
        /// VAR=secret, repeatable
        #[arg(long = "env", value_name = "VAR=SECRET")]
        envs: Vec<String>,
        /// Secret to pipe to the child on stdin
        #[arg(long)]
        stdin: Option<String>,
        /// Read a token from the first line of stdin, so it is never in an environment
        #[arg(long)]
        token_stdin: bool,
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
        /// A namespace such as `acme`, or one entry. Everything, if omitted.
        prefix: Option<String>,
    },
    /// Install, list, remove and run plugins, such as mail and things3
    Plugin {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        args: Vec<String>,
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

#[cfg(all(feature = "mock-enclave", not(debug_assertions)))]
compile_error!(
    "mock-enclave swaps the Secure Enclave for a fake, it is for tests and never builds in release"
);

/**
 * The fallback if a `mock-enclave` build ships anyway. Cargo writes `CACHEDIR.TAG` at the root of
 * every target directory, so a test build always has one above it, and an installed binary never
 * does. It aborts rather than panicking, since a panic on a broker thread ends only that thread
 **/
#[cfg(feature = "mock-enclave")]
fn refuse_outside_cargo() {
    let inside = std::env::current_exe().ok().is_some_and(|exe| {
        exe.ancestors()
            .any(|dir| dir.join("CACHEDIR.TAG").is_file())
    });
    if !inside {
        eprintln!("passbox: this mock-enclave test build is outside a cargo target directory");
        std::process::abort();
    }
}

fn main() {
    #[cfg(feature = "mock-enclave")]
    refuse_outside_cargo();
    take_credentials();
    if let Err(e) = run() {
        eprintln!("passbox: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let store = Store::open()?;
    store.remove_name_index()?;

    match cli.command {
        Command::Init => init(&store),
        Command::Add {
            name,
            multiline,
            fields,
        } => add(&store, &name, multiline, &fields).inspect(|()| written(&store, "add a secret")),
        Command::Get { name, field } => get(&store, &name, field.as_deref()),
        Command::Copy { name, field, clear } => copy(&store, &name, field.as_deref(), clear),
        Command::Grant {
            names,
            r#for,
            token_stdin,
        } => {
            if token_stdin {
                take_stdin_token()?;
            }
            grant(&store, &names, r#for)
        }
        Command::Ls => ls(&store),
        Command::Rm { name } => rm(&store, &name).inspect(|()| written(&store, "remove a secret")),
        Command::Restore { name, index } => restore(&store, &name, index)
            .inspect(|()| written(&store, "restore an earlier version")),
        #[cfg(feature = "host")]
        Command::MachineAdd => machine_add(&store),
        #[cfg(feature = "host")]
        Command::YubikeyAdd { recipient } => yubikey_add(&store, recipient.as_deref())
            .inspect(|()| written(&store, "wrap the store key to a YubiKey")),
        Command::Exec {
            envs,
            stdin,
            token_stdin,
            command,
        } => {
            if token_stdin {
                take_stdin_token()?;
            }
            exec(&store, &envs, stdin.as_deref(), &command)
        }
        #[cfg(feature = "host")]
        Command::Audit { tail } => audit(&store, tail),
        #[cfg(feature = "host")]
        Command::Sync { remote, enable } => run_sync(&store, remote.as_deref(), enable),
        #[cfg(feature = "host")]
        Command::ImportPass { prefix } => {
            import_pass(&store, prefix.as_deref()).inspect(|()| written(&store, "import from pass"))
        }
        Command::Plugin { args } => plugin_cmd(&store, &args),
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
            "broker.sock\nnames\nremote\nconfig.toml\nstore/.versions/\nwraps/se-*.json\ngrants-*.age\nwindows-*.json\n",
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

    let sync::Destination { kind, target } = match remote {
        Some(given) => sync::Destination::guess(given),
        None => sync::default_destination(store)?,
    };
    let remote = target;

    match kind {
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

/// One place for everything a write should trigger, so a new command cannot forget half of it
fn written(store: &Store, what: &str) {
    commit(store, what);
    mirror(store);
    push(store);
}

/// Optional history alongside the copy. A subject naming an entry would undo the encrypted names.
fn in_git(store: &Store) -> bool {
    store.dir.join(".git").exists()
}

fn git_quietly(store: &Store, args: &[&str]) {
    let _ = std::process::Command::new("git")
        .arg("-C")
        .arg(&store.dir)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/* Commit on every write, the way `pass` does once its store is a repo. Nothing is committed
until someone runs `passbox git init`, so this is a choice rather than a surprise, and it is
worth knowing what the choice costs: git history is permanent, so a secret removed from the
store stays in the history, still readable by the store key.

Subjects name the operation and not the entry, since a subject naming a secret would undo the
work of keeping names out of filenames. */
fn commit(store: &Store, what: &str) {
    if !in_git(store) {
        return;
    }
    let _ = ensure_store_gitignore(store);
    git_quietly(store, &["add", "-A"]);
    git_quietly(store, &["commit", "-m", what]);
}

/* A write that is only on this Mac is a write you can lose. Committing gives history, but the
copy elsewhere is what survives the machine, so a write updates it too.

Only a directory that was already chosen. An rclone remote is a slow round trip and stays on
`passbox sync`, git pushes separately in `push`.

Best effort by design. The value is already written and encrypted; failing the command because a
USB stick was unplugged would be the tail wagging the dog. Set PASSBOX_NO_AUTOSYNC to turn it
off for a script that writes in a loop. */
#[cfg(feature = "host")]
fn mirror(store: &Store) {
    if std::env::var_os("PASSBOX_NO_AUTOSYNC").is_some() {
        return;
    }
    let remote = match sync::configured(store) {
        Ok(Some(chosen)) if chosen.kind == sync::Kind::Directory => chosen.target,
        Ok(_) => return,
        Err(e) => {
            eprintln!("not copied: {e:#}");
            return;
        }
    };
    match sync::sync(store, std::path::Path::new(&remote)) {
        Ok(report) if report.pushed > 0 => eprintln!("{} copied to {remote}", report.pushed),
        Ok(_) => {}
        Err(e) => eprintln!("not copied to {remote}: {e:#}"),
    }
}

#[cfg(not(feature = "host"))]
fn mirror(_store: &Store) {}

#[cfg(feature = "host")]
fn git_push(store: &Store) {
    if !in_git(store) {
        return;
    }
    commit(store, "update");
    push(store);
}

/// A commit only on this Mac is lost with it, so a repo with a remote pushes on every write.
/// Best effort like the mirror, and `-u` so a remote added with no upstream still works
fn push(store: &Store) {
    if !in_git(store) {
        return;
    }
    let remotes = std::process::Command::new("git")
        .arg("-C")
        .arg(&store.dir)
        .arg("remote")
        .output();
    let Some(remote) = remotes.ok().and_then(|o| {
        String::from_utf8_lossy(&o.stdout)
            .lines()
            .next()
            .map(str::to_string)
    }) else {
        return;
    };
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(&store.dir)
        .args(["push", "-q", "-u", &remote, "HEAD"])
        .output();
    match out {
        Ok(o) if o.status.success() => {}
        Ok(o) => eprintln!(
            "not pushed to {remote}: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => eprintln!("not pushed to {remote}: {e}"),
    }
}

/// Advisory, since the broker cannot verify it. The prompt shows it beside the secret name.
fn agent() -> String {
    std::env::var("PASSBOX_AGENT").unwrap_or_default()
}

fn read_secret(store: &Store, name: &str, for_agent: bool) -> Result<String> {
    read_secret_as(store, name, &agent(), for_agent)
}

pub fn agent_read_secret(store: &Store, name: &str, agent: &str) -> Result<String> {
    read_secret_as(store, name, agent, true)
}

// A configured host wins over this disk, or a client with no wraps falls through to asking
// for a passphrase it does not have
fn brokered(store: &Store) -> bool {
    store.host().is_some() || (!headless() && store.has_se_wrap())
}

/// The broker owns windows and the audit log, so every read goes through it when it can.
/// Without an Enclave there is nothing to prompt with, and the passphrase becomes the gate.
fn read_secret_as(store: &Store, name: &str, agent: &str, for_agent: bool) -> Result<String> {
    if brokered(store) {
        return broker::request(store, name, agent);
    }
    let key = unlock(store, &format!("release the password for {name}"))?;
    let (_, secret) = store
        .find(name, &key)?
        .with_context(|| format!("no secret named {name}"))?;
    let _ = for_agent;
    let caller = broker::ancestry(std::process::id() as libc::pid_t);
    broker::append_audit(store, agent, name, "released", &caller, "")?;
    Ok(secret.value.clone())
}

/// Long enough for exec to read its batch, short enough that the token is useless after
const EXEC_GRANT_SECS: u64 = 30;

// Two or more broker reads would prompt once each, so grant them together and read through the
// token. A held PASSBOX_TOKEN, or a refused grant, keeps one read per secret
fn batch_token(store: &Store, names: &[&str]) -> Option<String> {
    let mut names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
    names.sort();
    names.dedup();
    if names.len() < 2 || !brokered(store) || held_token().is_some() {
        return None;
    }

    let answer = broker::grant(store, &names, &agent(), EXEC_GRANT_SECS).ok()?;
    answer.lines().next().map(str::to_string)
}

fn exec(store: &Store, envs: &[String], stdin: Option<&str>, command: &[String]) -> Result<()> {
    let (program, args) = command.split_first().context("no command to run")?;
    let mut child = std::process::Command::new(program);
    // Before the injected secrets, so an explicit --env PASSBOX_TOKEN=name still reaches the child
    without_credentials(&mut child).args(args);

    let mut pairs = Vec::new();
    for pair in envs {
        let (var, name) = pair
            .split_once('=')
            .with_context(|| format!("expected VAR=secret, got {pair}"))?;
        pairs.push((var, name));
    }

    let names: Vec<&str> = pairs.iter().map(|(_, name)| *name).chain(stdin).collect();
    let token = batch_token(store, &names);
    let read = |name: &str| match &token {
        Some(token) => broker::request_token(store, name, &agent(), token),
        None => read_secret(store, name, true),
    };

    for (var, name) in pairs {
        child.env(var, read(name)?);
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
    if let Some(moved) = sync::migrate(store)? {
        eprintln!(
            "{} now names {}, the old remote file is gone",
            sync::config_path(store).display(),
            moved.target
        );
        return Ok(());
    }

    // Only `sync --enable` reaches here, so a destination already set is one to offer changing
    // A broken file is one to replace, so it does not block choosing again
    if let Some(already) = sync::configured(store).unwrap_or(None) {
        eprintln!("copies currently go to {}", already.target);
        eprint!("Change that? [y/N] ");
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
            return Ok(());
        }
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

    let engine = match answer.trim() {
        "1" => sync::Engine::Icloud { directory: None },
        "2" => {
            let dir = prompt("directory: ")?;
            let path = match (dir.strip_prefix("~/"), std::env::var_os("HOME")) {
                (Some(rest), Some(home)) => std::path::Path::new(&home)
                    .join(rest)
                    .to_string_lossy()
                    .to_string(),
                _ => dir,
            };
            sync::Engine::Directory { path }
        }
        "3" => sync::Engine::Git {
            remote: prompt("git remote, such as git@github.com:you/passbox-store.git: ")?,
        },
        "4" => sync::Engine::Rclone {
            remote: prompt("rclone remote, such as b2:passbox: ")?,
        },
        other => bail!("expected 1 to 4, got {other}"),
    };

    // Checked before anything is created, so a bad answer leaves no folder or repo behind
    let destination = engine.resolve()?;
    match destination.kind {
        sync::Kind::Directory => std::fs::create_dir_all(&destination.target)?,
        sync::Kind::Git => {
            ensure_store_gitignore(store)?;
            git_quietly(store, &["init"]);
            git_quietly(store, &["remote", "add", "origin", &destination.target]);
        }
        sync::Kind::Rclone => {}
    }
    sync::choose(store, engine)?;
    eprintln!(
        "copies go to {}, set in {}",
        destination.target,
        sync::config_path(store).display()
    );
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
    let recipient = new_token(store)?;
    let key = unlock(store, "turn on sync with a YubiKey")?;
    let total = store.add_yubikey_recipient(&key, &recipient)?;
    eprintln!("sync is on, and the copy is useless without one of those {total} token(s)");
    eprintln!("add a second with `passbox yubikey-add`, or losing it loses the way back");
    Ok(())
}

/**
 * The plugged token the store does not hold yet. Setup runs only when no plugged token has an
 * identity, since generating on a token already added spends a slot and backs up nothing
 **/
#[cfg(feature = "host")]
fn new_token(store: &Store) -> Result<String> {
    yubikey::offer_install()?;
    let stored = store.yubikey_recipients();

    let plugged = yubikey::recipients()?;
    let found = if plugged.is_empty() {
        set_up_token()?;
        yubikey::recipients()?
    } else {
        plugged
    };
    let seen = found.len();
    let found = yubikey::not_added(found, &stored);
    let terminal = std::io::IsTerminal::is_terminal(&std::io::stdin());
    yubikey::choose(found, seen, terminal, || {
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        Ok(answer)
    })
}

#[cfg(feature = "host")]
fn set_up_token() -> Result<()> {
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
    yubikey::generate()
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
    held_passphrase().is_some()
}

fn unlock(store: &Store, reason: &str) -> Result<age::x25519::Identity> {
    #[cfg(feature = "host")]
    if !headless() && store.has_se_wrap() {
        return store.unlock_with_se(reason);
    }
    let _ = reason;
    store.unlock_with_passphrase(SecretString::from(ask("passphrase: ")?))
}

/**
 * A YubiKey wrap replaces the passphrase for recovery. Nothing in a synced copy can then be
 * attacked offline, because the private half never leaves the token
 **/
#[cfg(feature = "host")]
fn yubikey_add(store: &Store, recipient: Option<&str>) -> Result<()> {
    let recipient = match recipient {
        Some(r) => {
            yubikey::offer_install()?;
            r.to_string()
        }
        None => new_token(store)?,
    };
    let key = unlock(store, "wrap the store key to a YubiKey")?;
    let total = store.add_yubikey_recipient(&key, &recipient)?;
    eprintln!("wrapped to {recipient}");
    eprintln!("{total} token(s) can now open this store on any machine");
    if total == 1 {
        eprintln!("add a second with `passbox yubikey-add`, or losing it loses the way back");
    }
    check_token(store, &key, &recipient)
}

/// Opens the wrap with the new token alone, the one proof that it is a way back
#[cfg(feature = "host")]
fn check_token(store: &Store, key: &age::x25519::Identity, recipient: &str) -> Result<()> {
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return Ok(());
    }
    eprint!("Check the new token now? Unplug every other YubiKey first. [y/N] ");
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    if !matches!(answer.trim().to_lowercase().as_str(), "y" | "yes") {
        return Ok(());
    }

    // The plugin opens with whichever token it finds, so a second one would pass for this one
    let plugged = yubikey::recipients()?;
    if plugged.len() != 1 || plugged[0].recipient != recipient {
        bail!("plug in only the new token, then run `passbox yubikey-add {recipient}` again");
    }
    eprintln!("Touch the YubiKey.");
    if store.unlock_with_yubikey()?.to_public() != key.to_public() {
        bail!("the new token opened a different key, do not rely on it");
    }
    eprintln!("the new token opens this store");
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
    match held_passphrase() {
        Some(pass) => Ok(pass.to_string()),
        None => Ok(rpassword::prompt_password(prompt)?),
    }
}

fn add(store: &Store, name: &str, multiline: bool, fields: &[String]) -> Result<()> {
    let recipient = store.recipient()?;
    let value = read_value(multiline, fields)?;
    if value.is_empty() {
        bail!("refusing to store an empty value");
    }

    // Spotting a duplicate needs the name to id map, which only the key can produce
    let id = if store.ids_with_files()?.is_empty() && !store.versions_dir().exists() {
        store::new_id()
    } else {
        let key = unlock(store, &format!("add {name}"))?;
        if store.find(name, &key)?.is_some() {
            bail!("{name} already exists, run `passbox rm {name}` first to replace it");
        }
        // A name added back after rm keeps its id, so restore still reaches the old versions
        find_deleted(store, name, &key).unwrap_or_else(|_| store::new_id())
    };

    let secret = Secret {
        name: name.to_string(),
        value,
        created: store::now(),
        updated: store::now(),
    };
    store.put(&id, &secret, &recipient)?;
    eprintln!("stored {name}");
    #[cfg(feature = "host")]
    ssh::remember(store, &secret.value)?;
    Ok(())
}

#[cfg(feature = "host")]
fn import_pass(store: &Store, prefix: Option<&str>) -> Result<()> {
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

    let report = import::import(store, &picked, key.as_ref())?;
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

fn read_field(store: &Store, name: &str, field: Option<&str>) -> Result<String> {
    let whole = read_secret(store, name, false)?;
    match field {
        None => Ok(whole),
        Some(want) => fields(&whole)
            .remove(want)
            .with_context(|| format!("{name} has no field {want}")),
    }
}

// get writes the value to stdout, which lands in an agent's context, so it refuses unless
// stdout is a terminal, with no flag to override it. copy and exec stay clean
fn get(store: &Store, name: &str, field: Option<&str>) -> Result<()> {
    let mut out = std::io::stdout();
    if !out.is_terminal() {
        bail!(
            "passbox get writes a secret to stdout and this is not a terminal\n\
             use `passbox copy {name}`, `passbox exec --stdin {name} -- CMD`, or the \
             run_with_secret MCP tool"
        );
    }
    let value = read_field(store, name, field)?;
    out.write_all(value.as_bytes())?;
    out.write_all(b"\n")?;
    Ok(())
}

#[cfg(feature = "host")]
fn copy(store: &Store, name: &str, field: Option<&str>, clear: u64) -> Result<()> {
    let value = read_field(store, name, field)?;
    se::clip(&value, clear)?;
    eprintln!("copied {name} to the clipboard, clears in {clear}s");
    Ok(())
}

// A client build has no Enclave helper to drive the pasteboard, so copy is host only
#[cfg(not(feature = "host"))]
fn copy(_store: &Store, _name: &str, _field: Option<&str>, _clear: u64) -> Result<()> {
    bail!("copy needs the host build")
}

/// Through the broker, so a second listing inside the window does not ask again
pub fn agent_list_names(store: &Store, agent: &str) -> Result<Vec<String>> {
    // A configured host has the key and the names, same as for a read
    if store.host().is_some() || (!headless() && store.has_se_wrap()) {
        return broker::list(store, agent);
    }
    let key = unlock(store, "list your secret names")?;
    store.names(&key)
}

fn plugin_cmd(store: &Store, args: &[String]) -> Result<()> {
    let (head, rest) = args
        .split_first()
        .context("usage: passbox plugin <list|add|update|remove|NAME> ...")?;
    match head.as_str() {
        "list" | "add" | "update" | "remove" => plugin_manage(store, head, rest),
        name => plugin_run(store, name, rest),
    }
}

// Installing and listing read and write plugin files, which live only on the host
#[cfg(feature = "host")]
fn plugin_manage(store: &Store, verb: &str, rest: &[String]) -> Result<()> {
    match verb {
        "list" => plugin_list(store),
        "add" => plugin_install(store, rest, false),
        "update" => plugin_install(store, rest, true),
        "remove" => plugin_remove(store, rest),
        _ => unreachable!(),
    }
}

#[cfg(not(feature = "host"))]
fn plugin_manage(_store: &Store, _verb: &str, _rest: &[String]) -> Result<()> {
    bail!("manage plugins on the Mac that holds them, not on a client")
}

#[cfg(feature = "host")]
fn plugin_list(store: &Store) -> Result<()> {
    let plugins = plugin::installed(store)?;
    if plugins.is_empty() {
        println!("no plugins, add one with `passbox plugin add <dir>`");
        return Ok(());
    }
    for manifest in plugins {
        println!(
            "{} {}  {}{}",
            manifest.name,
            manifest.version(),
            manifest.description,
            stale_note(&manifest)
        );
        for tool in &manifest.tools {
            println!("  {} {}  {}", manifest.name, tool.name, tool.description);
        }
    }
    Ok(())
}

/// A first-party plugin whose bundled version differs from the installed one can be refreshed
#[cfg(feature = "host")]
fn stale_note(manifest: &plugin::Manifest) -> String {
    let Some(files) = first_party(&manifest.name) else {
        return String::new();
    };
    let Some(bundled) = files
        .iter()
        .find(|(name, _)| *name == "plugin.toml")
        .and_then(|(_, toml)| toml::from_str::<plugin::Manifest>(toml).ok())
    else {
        return String::new();
    };
    if bundled.version() != manifest.version() {
        return format!(
            "  (update available: {} -> {}, run `passbox plugin update {}`)",
            manifest.version(),
            bundled.version(),
            manifest.name
        );
    }
    String::new()
}

/* A plugin is a directory holding plugin.toml. Installing copies it under the store so a later
edit to the source does not silently change what runs. The manifest is parsed first, so a broken
one is refused before anything is copied. */
#[cfg(feature = "host")]
fn plugin_install(store: &Store, rest: &[String], overwrite: bool) -> Result<()> {
    let verb = if overwrite { "update" } else { "add" };
    let arg = rest
        .first()
        .with_context(|| format!("usage: passbox plugin {verb} <name|dir>"))?;

    // The destination is wiped before an overwrite, so a renamed or dropped file does not linger
    let fresh = |to: &std::path::Path| -> Result<()> {
        if to.exists() {
            if !overwrite {
                bail!("already installed, run `passbox plugin update` to refresh it");
            }
            std::fs::remove_dir_all(to)?;
        }
        Ok(())
    };

    if let Some(files) = first_party(arg) {
        let to = store.plugins_dir().join(arg);
        fresh(&to)?;
        std::fs::create_dir_all(&to)?;
        for (name, contents) in files {
            std::fs::write(to.join(name), contents)?;
        }
        eprintln!("{}ed {arg}", if overwrite { "updat" } else { "install" });
        return Ok(());
    }

    let from = std::path::Path::new(arg);
    let text = std::fs::read_to_string(from.join("plugin.toml"))
        .with_context(|| format!("no first-party plugin {arg}, and no plugin.toml in {arg}"))?;
    let manifest: plugin::Manifest = toml::from_str(&text).context("plugin.toml")?;
    let to = store.plugins_dir().join(&manifest.name);
    fresh(&to)?;
    copy_dir(from, &to)?;
    eprintln!(
        "{}ed {} {} with {} tool(s)",
        if overwrite { "updat" } else { "install" },
        manifest.name,
        manifest.version(),
        manifest.tools.len()
    );
    Ok(())
}

/* The first-party plugins ship inside the binary, so `plugin add mail` needs no network and no
repo checkout. Each entry is one file written into the plugin directory on install */
#[cfg(feature = "host")]
fn first_party(name: &str) -> Option<&'static [(&'static str, &'static str)]> {
    match name {
        "mail" => Some(&[
            ("plugin.toml", include_str!("../plugins/mail/plugin.toml")),
            (
                "recent.applescript",
                include_str!("../plugins/mail/recent.applescript"),
            ),
            (
                "search.applescript",
                include_str!("../plugins/mail/search.applescript"),
            ),
        ]),
        "calendar" => Some(&[
            (
                "plugin.toml",
                include_str!("../plugins/calendar/plugin.toml"),
            ),
            ("agenda.sh", include_str!("../plugins/calendar/agenda.sh")),
        ]),
        "things3" => Some(&[(
            "plugin.toml",
            include_str!("../plugins/things3/plugin.toml"),
        )]),
        "imap" => Some(&[
            ("plugin.toml", include_str!("../plugins/imap/plugin.toml")),
            ("imap.py", include_str!("../plugins/imap/imap.py")),
        ]),
        _ => None,
    }
}

#[cfg(feature = "host")]
fn plugin_remove(store: &Store, rest: &[String]) -> Result<()> {
    let name = rest
        .first()
        .context("usage: passbox plugin remove <name>")?;
    plugin::valid_name(name)?;
    let dir = store.plugins_dir().join(name);
    if !dir.exists() {
        bail!("no plugin named {name}");
    }
    std::fs::remove_dir_all(&dir)?;
    eprintln!("removed {name}");
    Ok(())
}

// A remote client has the host run the tool and return its output, otherwise it runs here
fn plugin_run(store: &Store, name: &str, rest: &[String]) -> Result<()> {
    let (action, rest) = rest
        .split_first()
        .context("usage: passbox plugin <name> <action> [--key value]")?;
    let params = parse_params(rest)?;

    if store.host().is_some() {
        let pairs: Vec<(String, String)> = params.into_iter().collect();
        print_output(&broker::plugin_run_remote(
            store,
            name,
            action,
            &pairs,
            &agent(),
        )?);
        return Ok(());
    }

    #[cfg(feature = "host")]
    {
        plugin_run_local(store, name, action, params)
    }
    #[cfg(not(feature = "host"))]
    {
        let _ = (name, action, params);
        bail!("no host set, put a Mac's tailnet address in ~/.passbox/host")
    }
}

fn print_output(output: &str) {
    print!("{output}");
    if !output.ends_with('\n') {
        println!();
    }
}

// The broker approves and audits, then the command runs here, keeping this process's GUI session
#[cfg(feature = "host")]
fn plugin_run_local(
    store: &Store,
    name: &str,
    action: &str,
    params: std::collections::HashMap<String, String>,
) -> Result<()> {
    let manifest = plugin::load(store, name)?;
    if manifest.stdin.is_some() {
        return plugin_run_fed(store, name, action, params);
    }
    let tool = manifest
        .tool(action)
        .with_context(|| format!("{name} has no action {action}"))?;
    manifest.ensure_available()?;
    let mut command = tool.command(&params)?;
    if !manifest.runs_in_caller_dir() {
        command.current_dir(store.plugins_dir().join(name));
    }

    if !headless() && store.has_se_wrap() {
        // The same params the command was built from, so the prompt shows what runs
        broker::plugin_approve(store, name, action, &params, &agent())?;
    } else {
        unlock(store, &manifest.approval(action, &agent(), &params))?;
    }
    let status = command
        .status()
        .with_context(|| format!("could not run {name} {action}"))?;
    std::process::exit(status.code().unwrap_or(1));
}

/* A plugin with `stdin` runs in the broker, which keeps its secret. With no broker this process
holds the key anyway, so it feeds the child itself and prints the same scrubbed output */
#[cfg(feature = "host")]
fn plugin_run_fed(
    store: &Store,
    name: &str,
    action: &str,
    params: std::collections::HashMap<String, String>,
) -> Result<()> {
    if !headless() && store.has_se_wrap() {
        let pairs: Vec<(String, String)> = params.into_iter().collect();
        print_output(&broker::plugin_run_remote(
            store,
            name,
            action,
            &pairs,
            &agent(),
        )?);
        return Ok(());
    }

    let (manifest, command) = plugin::fed_command(store, name, action, &params)?;
    let secret = manifest
        .stdin
        .as_deref()
        .with_context(|| format!("{name} reads no secret in its bundled copy"))?;
    let key = unlock(store, &manifest.approval(action, &agent(), &params))?;
    let Some((_, entry)) = store.find(secret, &key)? else {
        return Err(plugin::missing(name, secret));
    };
    let caller = broker::ancestry(std::process::id() as libc::pid_t);
    let args = manifest
        .tool(action)
        .map(|t| t.shown(&params))
        .unwrap_or_default();
    broker::append_audit(store, &agent(), secret, "released", &caller, &args)?;
    print_output(&plugin::run_fed(command, &entry.value)?);
    Ok(())
}

fn parse_params(rest: &[String]) -> Result<std::collections::HashMap<String, String>> {
    let mut out = std::collections::HashMap::new();
    let mut tokens = rest.iter();
    while let Some(token) = tokens.next() {
        let key = token
            .strip_prefix("--")
            .with_context(|| format!("expected --key, got {token}"))?;
        if let Some((k, v)) = key.split_once('=') {
            out.insert(k.to_string(), v.to_string());
        } else {
            let value = tokens
                .next()
                .with_context(|| format!("--{key} needs a value"))?;
            out.insert(key.to_string(), value.clone());
        }
    }
    Ok(out)
}

#[cfg(feature = "host")]
fn copy_dir(from: &std::path::Path, to: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

/// Captures the child's output instead of inheriting, which is what a tool result needs
pub fn run_child(
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

/// A tree for a terminal, one name per line for anything reading the output
/* The token goes to stdout and the rest to stderr, so `TOKEN=$(passbox grant acme/api-key)` picks up
the token alone while a person still sees what it covers. */
fn grant(store: &Store, names: &[String], ttl: Option<u64>) -> Result<()> {
    // A token lives in the broker, local or a configured host, and a passphrase store has none
    if !brokered(store) {
        bail!("a token needs the broker, which this store does not use");
    }

    // Zero asks for the parent's expiry, when a held token makes this a child
    let ttl = ttl.unwrap_or(if held_token().is_some() { 0 } else { 3600 });
    let answer = broker::grant(store, names, &agent(), ttl)?;
    let mut lines = answer.lines();
    let token = lines.next().context("the broker returned no token")?;
    let covered: Vec<&str> = lines.collect();

    // The token goes to stdout only, since stderr lands in scrollback, CI logs and transcripts
    println!("{token}");
    match ttl {
        0 => eprintln!("opens {} secret(s):", covered.len()),
        _ => eprintln!("opens {} secret(s) for {ttl}s:", covered.len()),
    }
    for name in &covered {
        eprintln!("  {name}");
    }
    eprintln!("pass the token on stdout back as PASSBOX_TOKEN, it stops working when it lapses");
    Ok(())
}

fn ls(store: &Store) -> Result<()> {
    // Through the broker like a read, so listing is approved and audited
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

fn read_value(multiline: bool, fields: &[String]) -> Result<String> {
    for field in fields {
        let lower = field.trim().to_lowercase();
        if lower.is_empty() || lower == "password" || field.contains([':', '\n']) {
            bail!("{field:?} cannot be a field name, the first line is the password");
        }
    }
    if std::io::stdin().is_terminal() {
        let mut value = rpassword::prompt_password("value: ")?;
        if rpassword::prompt_password("again: ")? != value {
            bail!("values do not match");
        }
        for line in named_fields(fields, std::io::stdin().lock(), |f| eprint!("{f}: "))? {
            value.push('\n');
            value.push_str(&line);
        }
        if multiline {
            eprintln!("fields and notes, one per line, empty line to finish:");
            for line in extra_lines(std::io::stdin().lock())? {
                value.push('\n');
                value.push_str(&line);
            }
        }
        return Ok(value);
    }
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    Ok(buf.trim_end_matches('\n').to_string())
}

/// One `name: value` line per field asked for. A field left empty is skipped
fn named_fields(
    names: &[String],
    mut input: impl std::io::BufRead,
    prompt: impl Fn(&str),
) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for name in names {
        prompt(name);
        let mut line = String::new();
        input.read_line(&mut line)?;
        let value = line.trim();
        if !value.is_empty() {
            out.push(format!("{}: {value}", name.trim()));
        }
    }
    Ok(out)
}

/// Lines after the value, up to an empty line or end of input. They echo, since they are the
/// username and notes beside the secret, which is the layout `fields` reads
fn extra_lines(input: impl std::io::BufRead) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for line in input.lines() {
        let line = line?;
        if line.trim().is_empty() {
            break;
        }
        out.push(line);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{extra_lines, fields, named_fields};

    #[test]
    fn each_named_field_is_asked_once_and_reads_back() {
        let names = ["username".to_string(), "url".to_string(), "otp".to_string()];
        let lines = named_fields(&names, "admin\nhttps://db\n\n".as_bytes(), |_| {}).unwrap();
        assert_eq!(lines, ["username: admin", "url: https://db"]);

        let entry = format!("pw\n{}", lines.join("\n"));
        assert_eq!(fields(&entry)["username"], "admin");
        assert_eq!(fields(&entry)["url"], "https://db");
    }

    #[test]
    fn extra_lines_stop_at_the_first_empty_line_and_read_as_fields() {
        let typed = "username: admin\nrotated quarterly\n\nnot part of it\n";
        let lines = extra_lines(typed.as_bytes()).unwrap();
        assert_eq!(lines, ["username: admin", "rotated quarterly"]);

        let entry = format!("pw\n{}", lines.join("\n"));
        assert_eq!(fields(&entry)["username"], "admin");
        assert_eq!(fields(&entry)["password"], "pw");
    }

    use super::WipeOnFree;
    use std::alloc::{GlobalAlloc, Layout, System};

    /// Stands in for the system allocator and records whether a block was zero when it got it back
    struct Spy(std::sync::atomic::AtomicBool);

    unsafe impl GlobalAlloc for Spy {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            let zero = unsafe { std::slice::from_raw_parts(ptr, layout.size()) }
                .iter()
                .all(|&b| b == 0);
            self.0.store(zero, std::sync::atomic::Ordering::SeqCst);
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    /* A freed block must reach the system allocator zeroed, or a secret the broker decrypted would
    linger in memory a debugger or core dump could reach. The spy sees the block at the moment it
    is handed back, so the check does not depend on the allocator reusing the block */
    #[test]
    fn freed_memory_is_wiped() {
        let wiper = WipeOnFree(Spy(std::sync::atomic::AtomicBool::new(false)));
        for size in [1, 31, 4099, 1 << 20] {
            let layout = Layout::from_size_align(size, 1).unwrap();
            unsafe {
                let p = wiper.alloc(layout);
                std::slice::from_raw_parts_mut(p, size).fill(0xAB);
                wiper.0.0.store(false, std::sync::atomic::Ordering::SeqCst);
                wiper.dealloc(p, layout);
            }
            assert!(
                wiper.0.0.load(std::sync::atomic::Ordering::SeqCst),
                "a freed block of {size} bytes was not wiped"
            );
        }
    }

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
