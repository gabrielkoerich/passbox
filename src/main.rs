mod crypto;
mod store;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use secrecy::SecretString;
use std::io::{IsTerminal, Read, Write};
use store::{DEFAULT_WINDOW_SECS, Mode, Secret, Store};

const PASSPHRASE_ENV: &str = "PASSBOX_PASSPHRASE";

#[derive(Parser)]
#[command(name = "passbox", version, about = "An age password store that asks before an agent reads it")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create the store and its recovery wrap
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
    Get { name: String },
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
    },
    /// List or restore earlier versions of a secret
    Restore {
        name: String,
        /// Version to restore, newest first, starting at 0
        #[arg(long)]
        index: Option<usize>,
    },
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
        Command::Get { name } => get(&store, &name),
        Command::Ls => ls(&store),
        Command::Rm { name } => rm(&store, &name),
        Command::Mode { name, mode, window } => set_mode(&store, &name, mode, window),
        Command::Restore { name, index } => restore(&store, &name, index),
    }
}

fn init(store: &Store) -> Result<()> {
    eprintln!("The recovery passphrase is the only way back if you lose this Mac.");
    let pass = ask("recovery passphrase: ")?;
    if pass.is_empty() {
        bail!("refusing an empty recovery passphrase");
    }
    if std::env::var_os(PASSPHRASE_ENV).is_none() && ask("again: ")? != pass {
        bail!("passphrases do not match");
    }
    store.init(SecretString::from(pass))?;
    eprintln!("store ready at {}", store.dir.display());
    Ok(())
}

fn unlock(store: &Store) -> Result<age::x25519::Identity> {
    store.unlock_with_passphrase(SecretString::from(ask("passphrase: ")?))
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
        let key = unlock(store)?;
        store
            .find(name, &key)?
            .map(|(id, s)| (id, s.created, s.mode, s.window_secs))
    };

    // A new value must never widen access, so an unnamed mode keeps what the secret already had
    let secret = match existing {
        Some((id, created, old_mode, old_window)) => (
            id,
            Secret {
                name: name.to_string(),
                mode: mode.unwrap_or(old_mode),
                window_secs: window.unwrap_or(old_window),
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

fn get(store: &Store, name: &str) -> Result<()> {
    let key = unlock(store)?;
    let (_, secret) = store
        .find(name, &key)?
        .with_context(|| format!("no secret named {name}"))?;
    let mut out = std::io::stdout();
    out.write_all(secret.value.as_bytes())?;
    if out.is_terminal() {
        out.write_all(b"\n")?;
    }
    Ok(())
}

fn ls(store: &Store) -> Result<()> {
    let key = unlock(store)?;
    for name in store.names(&key)? {
        println!("{name}");
    }
    Ok(())
}

fn rm(store: &Store, name: &str) -> Result<()> {
    let key = unlock(store)?;
    let (id, _) = store
        .find(name, &key)?
        .with_context(|| format!("no secret named {name}"))?;
    store.delete(&id)?;
    eprintln!("deleted {name}, recoverable with `passbox restore {name}`");
    Ok(())
}

fn set_mode(store: &Store, name: &str, mode: Mode, window: Option<u64>) -> Result<()> {
    let key = unlock(store)?;
    let recipient = store.recipient()?;
    let (id, mut secret) = store
        .find(name, &key)?
        .with_context(|| format!("no secret named {name}"))?;
    secret.mode = mode;
    if let Some(w) = window {
        secret.window_secs = w;
    }
    secret.updated = store::now();
    store.put(&id, &secret, &recipient)?;
    eprintln!("{name} is now {mode}");
    Ok(())
}

fn restore(store: &Store, name: &str, index: Option<usize>) -> Result<()> {
    let key = unlock(store)?;
    let id = match store.find(name, &key)? {
        Some((id, _)) => id,
        None => find_deleted(store, name, &key)?,
    };

    // Newest first, so index 0 is the most recent version
    let mut versions = store.versions(&id)?;
    versions.reverse();
    if versions.is_empty() {
        bail!("no earlier versions of {name}");
    }

    let Some(index) = index else {
        for (i, (stamp, path)) in versions.iter().enumerate() {
            let bytes = store.load_path(path, &key).map(|s| s.value.len()).unwrap_or(0);
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

/// A deleted secret has no live file, so its id only shows up through its versions.
fn find_deleted(store: &Store, name: &str, key: &age::x25519::Identity) -> Result<String> {
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
