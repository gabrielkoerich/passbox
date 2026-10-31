//! The plugin commands: list, add, update, remove, and running a tool here or on the host.

#[cfg(feature = "host")]
use crate::plugin;
use crate::store::Store;
use crate::{agent, broker};
#[cfg(feature = "host")]
use crate::{headless, unlock};
use anyhow::{Context, Result, bail};

pub(crate) fn plugin_cmd(store: &Store, args: &[String]) -> Result<()> {
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
        "add" => plugin_install(store, rest, Install::Add),
        "update" => plugin_install(store, rest, Install::Update),
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

/// `plugin add` refuses a plugin already there, `plugin update` replaces it
#[cfg(feature = "host")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Install {
    Add,
    Update,
}

#[cfg(feature = "host")]
impl Install {
    fn verb(self) -> &'static str {
        match self {
            Install::Add => "add",
            Install::Update => "update",
        }
    }

    fn done(self) -> &'static str {
        match self {
            Install::Add => "installed",
            Install::Update => "updated",
        }
    }
}

/* A plugin is a directory holding plugin.toml. Installing copies it under the store so a later
edit to the source does not silently change what runs. The manifest is parsed first, so a broken
one is refused before anything is copied. */
#[cfg(feature = "host")]
fn plugin_install(store: &Store, rest: &[String], install: Install) -> Result<()> {
    let verb = install.verb();
    let arg = rest
        .first()
        .with_context(|| format!("usage: passbox plugin {verb} <name|dir>"))?;

    // The destination is wiped before an overwrite, so a renamed or dropped file does not linger
    let fresh = |to: &std::path::Path| -> Result<()> {
        if to.exists() {
            if install == Install::Add {
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
        eprintln!("{} {arg}", install.done());
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
        "{} {} {} with {} tool(s)",
        install.done(),
        manifest.name,
        manifest.version(),
        manifest.tools.len()
    );
    Ok(())
}

/* The first-party plugins ship inside the binary, so `plugin add mail` needs no network and no
repo checkout. Each entry is one file written into the plugin directory on install */
#[cfg(feature = "host")]
pub(crate) fn first_party(name: &str) -> Option<&'static [(&'static str, &'static str)]> {
    match name {
        "mail" => Some(&[
            (
                "plugin.toml",
                include_str!("../../plugins/mail/plugin.toml"),
            ),
            (
                "recent.applescript",
                include_str!("../../plugins/mail/recent.applescript"),
            ),
            (
                "search.applescript",
                include_str!("../../plugins/mail/search.applescript"),
            ),
        ]),
        "calendar" => Some(&[
            (
                "plugin.toml",
                include_str!("../../plugins/calendar/plugin.toml"),
            ),
            (
                "agenda.sh",
                include_str!("../../plugins/calendar/agenda.sh"),
            ),
        ]),
        "things3" => Some(&[(
            "plugin.toml",
            include_str!("../../plugins/things3/plugin.toml"),
        )]),
        "imap" => Some(&[
            (
                "plugin.toml",
                include_str!("../../plugins/imap/plugin.toml"),
            ),
            ("imap.py", include_str!("../../plugins/imap/imap.py")),
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
    let caller = broker::own_ancestry();
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
