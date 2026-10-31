//! Commands on one secret or the list of them: add, get, copy, ls, rm, restore, grant and audit.

#[cfg(feature = "host")]
use crate::crypto;
use crate::store::{self, Secret, Store};
use crate::{agent, broker, brokered, read_secret, unlock};
use crate::{agent_list_names, held_token, tree};
#[cfg(feature = "host")]
use crate::{se, ssh};
use age::x25519;
use anyhow::{Context, Result, bail};
use std::io::{IsTerminal, Read, Write};

#[cfg(feature = "host")]
pub(crate) fn audit(store: &Store, tail: usize) -> Result<()> {
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

/// Where `add` reads the value, in the shapes its flags allow together
#[derive(Clone, Copy)]
pub(crate) enum Input<'a> {
    /// The value, then each named field, then free lines if `notes` asks for them
    Fields { names: &'a [String], notes: Notes },
    /// The whole of stdin, kept as one blob
    Blob,
    /// A file, kept as one blob
    File(&'a std::path::Path),
}

/// Whether `add` asks for free lines after the named fields, which `--multiline` turns on
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Notes {
    Skip,
    Ask,
}

/// What `add` does when the name is already taken
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Existing {
    Refuse,
    Replace,
}

pub(crate) fn add(store: &Store, name: &str, input: Input<'_>, existing: Existing) -> Result<()> {
    let recipient = store.recipient()?;
    let mut blob = !matches!(input, Input::Fields { .. });
    // A replace opens the store first, to learn whether the old entry is a blob
    let mut replaced = None;
    let mut key = None;
    if existing == Existing::Replace {
        let k = unlock(store, &format!("replace {name}"))?;
        let (id, old) = store
            .find(name, &k)?
            .with_context(|| format!("{name} does not exist, drop --replace to add it"))?;
        blob = blob || old.blob;
        replaced = Some(id);
        key = Some(k);
    }
    let value = match input {
        Input::File(path) => read_file(path)?,
        Input::Fields { names, notes } if !blob => read_value(notes, names)?,
        Input::Fields { .. } | Input::Blob => read_blob()?,
    };
    if value.is_empty() {
        bail!("refusing to store an empty value");
    }

    // Spotting a duplicate needs the name to id map, which only the key can produce
    let id = if let Some(id) = replaced {
        id
    } else if store.ids_with_files()?.is_empty() && !store.versions_dir().exists() {
        store::new_id()
    } else {
        let key = match key {
            Some(key) => key,
            None => unlock(store, &format!("add {name}"))?,
        };
        if store.find(name, &key)?.is_some() {
            bail!("{name} already exists, use --replace or run `passbox rm {name}` first");
        }
        // A name added back after rm keeps its id, so restore still reaches the old versions
        find_deleted(store, name, &key).unwrap_or_else(|_| store::new_id())
    };

    let secret = Secret {
        name: name.to_string(),
        value,
        created: store::now(),
        updated: store::now(),
        blob,
    };
    store.put(&id, &secret, &recipient)?;
    eprintln!("stored {name}");
    #[cfg(feature = "host")]
    ssh::remember(store, &secret.value)?;
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
    let whole = read_secret(store, name)?;
    match field {
        None => Ok(whole),
        Some(want) => fields(&whole)
            .remove(want)
            .with_context(|| format!("{name} has no field {want}")),
    }
}

// get writes the value to stdout, which lands in an agent's context, so it refuses unless
// stdout is a terminal, with no flag to override it. copy and exec stay clean
pub(crate) fn get(store: &Store, name: &str, field: Option<&str>) -> Result<()> {
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
pub(crate) fn copy(store: &Store, name: &str, field: Option<&str>, clear: u64) -> Result<()> {
    let value = read_field(store, name, field)?;
    se::clip(&value, clear)?;
    eprintln!("copied {name} to the clipboard, clears in {clear}s");
    Ok(())
}

// A client build has no Enclave helper to drive the pasteboard, so copy is host only
#[cfg(not(feature = "host"))]
pub(crate) fn copy(_store: &Store, _name: &str, _field: Option<&str>, _clear: u64) -> Result<()> {
    bail!("copy needs the host build")
}

/// A tree for a terminal, one name per line for anything reading the output
/* The token goes to stdout and the rest to stderr, so `TOKEN=$(passbox grant acme/api-key)` picks up
the token alone while a person still sees what it covers. */
pub(crate) fn grant(store: &Store, names: &[String], ttl: Option<u64>) -> Result<()> {
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

pub(crate) fn ls(store: &Store) -> Result<()> {
    // Through the broker like a read, so listing is approved and audited
    let names = agent_list_names(store, &agent())?;
    let mut out = std::io::stdout();
    if out.is_terminal() {
        out.write_all(tree::render(&names).as_bytes())?;
    } else {
        for name in names {
            writeln!(out, "{name}")?;
        }
    }
    Ok(())
}

pub(crate) fn rm(store: &Store, name: &str) -> Result<()> {
    let key = unlock(store, &format!("delete {name}"))?;
    let (id, _) = store
        .find(name, &key)?
        .with_context(|| format!("no secret named {name}"))?;
    store.delete(&id)?;
    store.prune_tombs()?;
    eprintln!("deleted {name}, recoverable with `passbox restore {name}`");
    offer_ssh_keys(store, &key);
    Ok(())
}

/// The secret is already written, so a failed rebuild warns rather than fails the command
fn offer_ssh_keys(store: &Store, key: &x25519::Identity) {
    #[cfg(feature = "host")]
    if let Err(e) = ssh::rebuild(store, key) {
        eprintln!("could not refresh the SSH keys: {e:#}");
    }
    #[cfg(not(feature = "host"))]
    let _ = (store, key);
}

pub(crate) fn restore(store: &Store, name: &str, index: Option<usize>) -> Result<()> {
    let key = unlock(store, &format!("restore {name}"))?;
    restore_version(store, &key, name, index)?;
    offer_ssh_keys(store, &key);
    Ok(())
}

fn restore_version(
    store: &Store,
    key: &x25519::Identity,
    name: &str,
    index: Option<usize>,
) -> Result<()> {
    let id = match store.find(name, key)? {
        Some((id, _)) => id,
        None => find_deleted(store, name, key)?,
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
            let bytes = store::load_path(path, key).map_or(0, |s| s.value.len());
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
fn find_deleted(store: &Store, name: &str, key: &x25519::Identity) -> Result<String> {
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
                if let Ok(secret) = store::load_path(&version, key)
                    && secret.name == name
                {
                    return Ok(id.to_string());
                }
            }
        }
    }
    bail!("no secret named {name}")
}

fn read_file(path: &std::path::Path) -> Result<String> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("could not read {}", path.display()))?;
    Ok(text.trim_end_matches('\n').to_string())
}

/// The whole of stdin. At a terminal the text echoes as it is pasted, and Ctrl-D ends it
fn read_blob() -> Result<String> {
    if std::io::stdin().is_terminal() {
        eprintln!("paste the value, then press Ctrl-D on an empty line:");
    }
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    Ok(buf.trim_end_matches('\n').to_string())
}

fn read_value(notes: Notes, fields: &[String]) -> Result<String> {
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
        if notes == Notes::Ask {
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
