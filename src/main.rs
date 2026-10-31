//! An age password store that asks before an agent reads a secret.
#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a CLI talks on stdout and stderr, and the broker logs to stderr for launchd"
)]

mod broker;
mod cmd;
mod credentials;
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
mod skill;
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

pub(crate) use cmd::exec::run_child;
#[cfg(feature = "host")]
pub(crate) use cmd::plugins::first_party;
pub(crate) use credentials::{held_token, without_credentials};

use age::x25519;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use cmd::exec::exec;
use cmd::git::{git, written};
#[cfg(feature = "host")]
use cmd::imports::{Manager, import};
use cmd::plugins::plugin_cmd;
#[cfg(feature = "host")]
use cmd::secrets::audit;
use cmd::secrets::{Existing, Input, Notes, add, copy, get, grant, ls, restore, rm};
use cmd::setup::init;
#[cfg(feature = "host")]
use cmd::setup::{enable_sync, machine_add, run_sync, yubikey_add};
use credentials::{held_passphrase, take_credentials, take_stdin_token};
#[cfg(feature = "host")]
use import::Mode;
use secrecy::SecretString;
use std::alloc::{GlobalAlloc, Layout, System};
use store::Store;
use zeroize::Zeroize;

/* Every freed block is wiped before the system allocator gets it back. Decrypting, parsing JSON
and decoding keys all pass plaintext through buffers owned by age, serde_json and std, which free
them without wiping, so wiping at the one place every free goes through catches all of them.
The default `realloc` frees through `dealloc`, so a buffer that grows is wiped too. */
struct WipeOnFree<A>(A);

// SAFETY: every block comes from the inner allocator and goes back to it with the same layout
unsafe impl<A: GlobalAlloc> GlobalAlloc for WipeOnFree<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's layout contract passes straight through
        unsafe { self.0.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller hands back a live block of `layout.size()` bytes that nothing else uses
        let block = unsafe { std::slice::from_raw_parts_mut(ptr, layout.size()) };
        block.zeroize();
        // SAFETY: the block came from the inner allocator with this layout
        unsafe { self.0.dealloc(ptr, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: WipeOnFree<System> = WipeOnFree(System);

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
    Add(AddArgs),
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
        /// VAR=secret, written to a temporary file the child reads by path, removed when it exits.
        /// Repeatable
        #[arg(long = "file", value_name = "VAR=SECRET")]
        files: Vec<String>,
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
        /// Directory or rclone remote, default `$PASSBOX_REMOTE` or the iCloud Drive folder
        #[arg(long)]
        remote: Option<String>,
        /// Create the recovery passphrase that syncing needs, turning sync on
        #[arg(long)]
        enable: bool,
    },
    #[cfg(feature = "host")]
    /// Copy secrets across from pass, or from 1Password through its signed-in `op` CLI
    Import {
        /// Where the secrets come from
        manager: Manager,
        /// For pass a namespace such as `acme` or one entry, for 1password one vault by name or
        /// id. Everything, if omitted
        from: Option<String>,
        /// Put every name under this namespace, such as `1p`
        #[arg(long)]
        prefix: Option<String>,
        /// List each entry, its new name and why it would be skipped, with no values, and write nothing
        #[arg(long)]
        dry_run: bool,
    },
    /// Install, list, remove and run plugins, such as mail and things3
    Plugin {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        args: Vec<String>,
    },
    /// Serve MCP over stdio, so an agent asks through tools rather than a shell
    Mcp,
    /// Install or check the agent skill that matches this version of passbox
    Skill {
        #[command(subcommand)]
        action: SkillAction,
    },
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

#[derive(clap::Args)]
struct AddArgs {
    name: String,
    /// After the value, ask for `key: value` fields and notes, one per line
    #[arg(short, long)]
    multiline: bool,
    /// After the value, ask for this field, such as `username`. Repeatable
    #[arg(long = "field", value_name = "NAME")]
    fields: Vec<String>,
    /// Store the whole text, such as a certificate or a JSON key, and never read it as fields.
    /// At a terminal, paste it and end with Ctrl-D
    #[arg(long, conflicts_with_all = ["multiline", "fields"])]
    blob: bool,
    /// Store this file as a blob
    #[arg(long, value_name = "PATH", conflicts_with_all = ["multiline", "fields"])]
    file: Option<std::path::PathBuf>,
    /// Replace an existing secret. A blob stays a blob
    #[arg(long)]
    replace: bool,
}

impl AddArgs {
    fn input(&self) -> Input<'_> {
        match (self.file.as_deref(), self.blob) {
            (Some(path), _) => Input::File(path),
            (None, true) => Input::Blob,
            (None, false) => Input::Fields {
                names: &self.fields,
                notes: if self.multiline {
                    Notes::Ask
                } else {
                    Notes::Skip
                },
            },
        }
    }

    fn existing(&self) -> Existing {
        if self.replace {
            Existing::Replace
        } else {
            Existing::Refuse
        }
    }
}

#[derive(Subcommand)]
enum SkillAction {
    /// Write the SKILL.md for this version, to ~/.claude/skills/passbox by default
    Install {
        #[arg(long)]
        dir: Option<std::path::PathBuf>,
    },
    /// Exit 1 if the installed SKILL.md is missing, older or different from this version's
    Check {
        #[arg(long)]
        dir: Option<std::path::PathBuf>,
    },
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
    let inside = std::env::current_exe().is_ok_and(|exe| {
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
    if let Command::Skill { action } = cli.command {
        return match action {
            SkillAction::Install { dir } => skill::install(dir),
            SkillAction::Check { dir } => skill::check(dir),
        };
    }
    let store = Store::open()?;
    store.remove_name_index()?;

    match cli.command {
        Command::Init => init(&store),
        Command::Add(args) => add(&store, &args.name, args.input(), args.existing())
            .inspect(|()| written(&store, "add a secret")),
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
            files,
            token_stdin,
            command,
        } => {
            if token_stdin {
                take_stdin_token()?;
            }
            exec(&store, &envs, &files, stdin.as_deref(), &command)
        }
        #[cfg(feature = "host")]
        Command::Audit { tail } => audit(&store, tail),
        #[cfg(feature = "host")]
        Command::Sync { remote, enable } => {
            if enable {
                enable_sync(&store)?;
            }

            run_sync(&store, remote.as_deref())
        }
        #[cfg(feature = "host")]
        Command::Import {
            manager,
            from,
            prefix,
            dry_run,
        } => {
            let mode = if dry_run { Mode::DryRun } else { Mode::Write };
            import(&store, manager, from.as_deref(), prefix.as_deref(), mode).inspect(|()| {
                if mode == Mode::Write {
                    written(&store, "import from another password manager");
                }
            })
        }
        Command::Plugin { args } => plugin_cmd(&store, &args),
        Command::Mcp => mcp::serve(&store),
        Command::Git { args } => git(&store, &args),
        Command::Skill { .. } => unreachable!("handled before the store opens"),
        #[cfg(feature = "host")]
        Command::Broker => broker::serve(store),
    }
}

/// Advisory, since the broker cannot verify it. The prompt shows it beside the secret name.
fn agent() -> String {
    std::env::var("PASSBOX_AGENT").unwrap_or_default()
}

fn read_secret(store: &Store, name: &str) -> Result<String> {
    read_secret_as(store, name, &agent())
}

pub(crate) fn agent_read_secret(store: &Store, name: &str, agent: &str) -> Result<String> {
    read_secret_as(store, name, agent)
}

// A configured host wins over this disk, or a client with no wraps falls through to asking
// for a passphrase it does not have
fn brokered(store: &Store) -> bool {
    store.host().is_some() || (!headless() && store.has_se_wrap())
}

/// The broker owns windows and the audit log, so every read goes through it when it can.
/// Without an Enclave there is nothing to prompt with, and the passphrase becomes the gate.
fn read_secret_as(store: &Store, name: &str, agent: &str) -> Result<String> {
    if brokered(store) {
        return broker::request(store, name, agent);
    }
    let key = unlock(store, &format!("release the password for {name}"))?;
    let (_, secret) = store
        .find(name, &key)?
        .with_context(|| format!("no secret named {name}"))?;
    let caller = broker::own_ancestry();
    broker::append_audit(store, agent, name, "released", &caller, "")?;
    Ok(secret.value.clone())
}

/// `PASSBOX_PASSPHRASE` says nobody is at the keyboard, and a fingerprint needs somebody
fn headless() -> bool {
    held_passphrase().is_some()
}

fn unlock(store: &Store, reason: &str) -> Result<x25519::Identity> {
    #[cfg(feature = "host")]
    if !headless() && store.has_se_wrap() {
        return store.unlock_with_se(reason);
    }
    let _ = reason;
    store.unlock_with_passphrase(SecretString::from(ask("passphrase: ")?))
}

/// `PASSBOX_PASSPHRASE` exists for CI and for headless use, where there is no terminal to type at
fn ask(prompt: &str) -> Result<String> {
    match held_passphrase() {
        Some(pass) => Ok(pass.to_string()),
        None => Ok(rpassword::prompt_password(prompt)?),
    }
}

/// Through the broker, so a second listing inside the window does not ask again
pub(crate) fn agent_list_names(store: &Store, agent: &str) -> Result<Vec<String>> {
    // A configured host has the key and the names, same as for a read
    if store.host().is_some() || (!headless() && store.has_se_wrap()) {
        return broker::list(store, agent);
    }
    let key = unlock(store, "list your secret names")?;
    store.names(&key)
}

#[cfg(test)]
mod tests {
    use super::WipeOnFree;

    use std::alloc::{GlobalAlloc, Layout, System};

    /// Stands in for the system allocator and records whether a block was zero when it got it back
    struct Spy(std::sync::atomic::AtomicBool);

    // SAFETY: every block comes from System and goes back to it with the same layout
    unsafe impl GlobalAlloc for Spy {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: the caller's layout contract passes straight through
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            // SAFETY: the caller hands back a live block of `layout.size()` bytes
            let zero = unsafe { std::slice::from_raw_parts(ptr, layout.size()) }
                .iter()
                .all(|&b| b == 0);
            self.0.store(zero, std::sync::atomic::Ordering::SeqCst);
            // SAFETY: the block came from System with this layout
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
            // SAFETY: the layout has a non-zero size
            let p = unsafe { wiper.alloc(layout) };
            // SAFETY: `p` is a fresh block of `size` bytes
            unsafe { std::slice::from_raw_parts_mut(p, size) }.fill(0xAB);
            wiper.0.0.store(false, std::sync::atomic::Ordering::SeqCst);
            // SAFETY: `p` came from this allocator with this layout
            unsafe { wiper.dealloc(p, layout) };
            assert!(
                wiper.0.0.load(std::sync::atomic::Ordering::SeqCst),
                "a freed block of {size} bytes was not wiped"
            );
        }
    }
}
