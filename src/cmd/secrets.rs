//! Commands on one secret or the list of them: add, get, copy, ls, rm, restore, grant and audit.

use super::tree;
#[cfg(feature = "host")]
use crate::broker::ssh;
use crate::broker::sshkey;
#[cfg(feature = "host")]
use crate::crypto;
#[cfg(feature = "host")]
use crate::se;
use crate::store::{self, Secret, Store};
use crate::{agent, broker, brokered, read_entry, read_secret, read_secret_field, unlock};
use crate::{agent_list_names, held_token};
use age::x25519;
use anyhow::{Context, Result, bail};
use std::fmt::Write as _;
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

    // Stored decrypted, as 1Password does, since the store encrypts it and every signature prompts
    let value = sshkey::decrypt(&value, || {
        rpassword::prompt_password("SSH key passphrase: ")
            .context("could not ask for the SSH key passphrase")
    })?
    .unwrap_or(value);

    // The key signs the file, and spotting a duplicate needs the name to id map only it can produce
    let key = match key {
        Some(key) => key,
        None => unlock(store, &format!("add {name}"))?,
    };
    let id = if let Some(id) = replaced {
        id
    } else {
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
    store.put(&id, &secret, &key)?;
    eprintln!("stored {name}");
    // A client has no agent, so only the host offers the key or says why not
    #[cfg(feature = "host")]
    {
        ssh::remember(store, &secret.value)?;
        if let Some(why) = sshkey::unoffered(name, &secret.value) {
            eprintln!("{why}");
        }
    }
    Ok(())
}

fn read_field(store: &Store, name: &str, field: Option<&str>) -> Result<String> {
    match field {
        None => read_secret(store, name),
        Some(want) => read_secret_field(store, name, want),
    }
}

/// How `get` prints an entry
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Format {
    Text,
    Json,
    Yaml,
}

/// Whether `get` prints the values or only the field names
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Show {
    Hidden,
    Revealed,
}

impl From<bool> for Show {
    /// `--reveal`
    fn from(reveal: bool) -> Self {
        if reveal { Show::Revealed } else { Show::Hidden }
    }
}

/// What `get` shows: each field by name, with its value only when revealed
struct Shown {
    show: Show,
    name: String,
    note: bool,
    fields: Vec<(String, Option<String>)>,
    notes: Option<String>,
    /// The whole value as stored, which revealed text prints untouched
    raw: Option<String>,
}

/* Without `--reveal`, get shows the field names and hides every value, so a terminal's
scrollback, a shared screen or an agent driving a terminal sees no secret. The names come from
the same list `passbox fields` reads, so no value leaves the broker. A revealed value lands in
whatever reads the terminal, so `--reveal` refuses unless stdout is one, with no flag to
override it. copy and exec stay clean */
pub(crate) fn get(
    store: &Store,
    name: &str,
    field: Option<&str>,
    show: Show,
    format: Format,
) -> Result<()> {
    let shown = if show == Show::Revealed {
        if !std::io::stdout().is_terminal() {
            bail!(
                "passbox get --reveal writes a secret to stdout and this is not a terminal\n\
                 use `passbox copy {name}`, `passbox exec --stdin {name} -- CMD`, or the \
                 run_with_secret MCP tool"
            );
        }
        revealed(store, name, field)?
    } else {
        hidden(store, name, field)?
    };
    let text = match format {
        Format::Text => text_of(&shown),
        Format::Json => {
            let mut json = serde_json::to_string_pretty(&json_of(&shown))?;
            json.push('\n');
            json
        }
        Format::Yaml => yaml_of(&shown),
    };
    std::io::stdout().write_all(text.as_bytes())?;
    if show == Show::Hidden && std::io::stderr().is_terminal() {
        eprintln!("values hidden, `--reveal` prints them and `passbox copy {name}` copies one");
    }
    Ok(())
}

fn hidden(store: &Store, name: &str, field: Option<&str>) -> Result<Shown> {
    // An entry whose lines read as no field lists none, and it is not a note either
    let (labels, note) = match field_labels(store, name) {
        Ok(labels) => {
            let note = labels.is_empty();
            (labels, note)
        }
        Err(e) if e.to_string() == format!("{name} has no field to copy") => (Vec::new(), false),
        Err(e) => return Err(e),
    };
    let names = match field {
        Some(want) if labels.iter().any(|l| l == want) => vec![want.to_string()],
        Some(want) => bail!(
            "{name} lists no field {want}, `passbox get {name} --reveal --field {want}` reads a \
             field by its exact name"
        ),
        None => labels,
    };
    Ok(Shown {
        show: Show::Hidden,
        name: name.to_string(),
        note,
        fields: names.into_iter().map(|n| (n, None)).collect(),
        notes: None,
        raw: None,
    })
}

fn revealed(store: &Store, name: &str, field: Option<&str>) -> Result<Shown> {
    if let Some(want) = field {
        let value = read_field(store, name, Some(want))?;
        return Ok(Shown {
            show: Show::Revealed,
            name: name.to_string(),
            note: false,
            fields: vec![(want.to_string(), Some(value))],
            notes: None,
            raw: None,
        });
    }
    let (value, blob) = read_entry(store, name)?;
    if blob == Some(true) {
        return Ok(Shown {
            show: Show::Revealed,
            name: name.to_string(),
            note: true,
            fields: Vec::new(),
            notes: Some(value.clone()),
            raw: Some(value),
        });
    }
    let (fields, notes) = store::parts(&value);
    let notes = notes.join("\n").trim().to_string();
    Ok(Shown {
        show: Show::Revealed,
        name: name.to_string(),
        note: false,
        // An entry with fields and no password starts with its empty password line
        fields: fields
            .into_iter()
            .filter(|(k, v)| !(k == "password" && v.is_empty()))
            .map(|(k, v)| (k, Some(v)))
            .collect(),
        notes: (!notes.is_empty()).then_some(notes),
        // An entry with fields and no password starts with its empty password line
        raw: Some(value.strip_prefix('\n').unwrap_or(&value).to_string()),
    })
}

const HIDDEN: &str = "••••••••";

fn text_of(shown: &Shown) -> String {
    // Revealed text prints the value as stored, or the one field asked for, as get always has
    if shown.show == Show::Revealed {
        let value = match (&shown.raw, shown.fields.as_slice()) {
            (Some(raw), _) => raw.as_str(),
            (None, [(_, Some(value))]) => value.as_str(),
            _ => "",
        };
        return format!("{value}\n");
    }
    let mut out = format!("{}\n", shown.name);
    if shown.note {
        let _ = writeln!(out, "  note  {HIDDEN}");
        return out;
    }
    let width = shown
        .fields
        .iter()
        .map(|(k, _)| k.chars().count())
        .max()
        .unwrap_or(0);
    for (key, value) in &shown.fields {
        let value = value.as_deref().unwrap_or(HIDDEN);
        let mut lines = value.lines();
        let _ = writeln!(out, "  {key:width$}  {}", lines.next().unwrap_or_default());
        for more in lines {
            let _ = writeln!(out, "  {:width$}  {more}", "");
        }
    }
    if let Some(notes) = &shown.notes {
        out.push('\n');
        out.push_str(notes);
        out.push('\n');
    }
    out
}

fn json_of(shown: &Shown) -> serde_json::Value {
    serde_json::json!({
        "name": shown.name,
        "kind": if shown.note { "note" } else { "fields" },
        "fields": shown.fields.iter()
            .map(|(k, v)| serde_json::json!({ "name": k, "value": v }))
            .collect::<Vec<_>>(),
        "notes": shown.notes,
    })
}

/// A YAML double-quoted string, escaping every character YAML does not allow raw, such as DEL,
/// the C1 controls and the line breaks it would fold
fn yaml_quoted(text: &str) -> String {
    let mut out = String::from('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() || matches!(c, '\u{2028}' | '\u{2029}' | '\u{feff}') => {
                let _ = write!(out, "\\u{:04X}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// YAML by hand, every string double quoted, so `null`, `yes` or `- x` stay strings
fn yaml_of(shown: &Shown) -> String {
    let quote = |s: &str| yaml_quoted(s);
    let or_null = |v: Option<&str>| v.map_or_else(|| "null".to_string(), quote);
    let mut out = format!(
        "name: {}\nkind: {}\n",
        quote(&shown.name),
        if shown.note { "note" } else { "fields" }
    );
    if shown.fields.is_empty() {
        out.push_str("fields: []\n");
    } else {
        out.push_str("fields:\n");
        for (k, v) in &shown.fields {
            let _ = writeln!(
                out,
                "  - name: {}\n    value: {}",
                quote(k),
                or_null(v.as_deref())
            );
        }
    }
    let _ = writeln!(out, "notes: {}", or_null(shown.notes.as_deref()));
    out
}

// The passphrase is asked before the broker is, so the export costs one Touch ID prompt
pub(crate) fn get_encrypted(store: &Store, name: &str) -> Result<()> {
    let mut out = std::io::stdout();
    if !out.is_terminal() {
        bail!("passbox get --encrypt writes the key to stdout and this is not a terminal");
    }

    if !brokered(store) {
        bail!("exporting an SSH key needs the broker, which this store does not use");
    }

    let passphrase = zeroize::Zeroizing::new(rpassword::prompt_password("new passphrase: ")?);
    if passphrase.is_empty() {
        bail!("an exported SSH key needs a passphrase");
    }

    if *rpassword::prompt_password("again: ")? != *passphrase {
        bail!("passphrases do not match");
    }

    let key = broker::export(store, name, &agent(), &passphrase)?;
    out.write_all(key.as_bytes())?;
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

/// One label a line, and no value, so Alfred can offer each field to `copy --field`
pub(crate) fn list_fields(store: &Store, name: &str) -> Result<()> {
    let labels = field_labels(store, name)?;
    let mut out = std::io::stdout();
    for label in labels {
        writeln!(out, "{label}")?;
    }
    Ok(())
}

/// The field names of an entry, none for a note, with no value leaving the broker
fn field_labels(store: &Store, name: &str) -> Result<Vec<String>> {
    let labels = if brokered(store) {
        broker::fields(store, name, &agent())?
    } else {
        let key = unlock(store, &format!("list the fields of {name}"))?;
        let (_, secret) = store
            .find(name, &key)?
            .with_context(|| format!("no secret named {name}"))?;
        let names = secret.field_names();
        let decision = if names.is_ok() {
            "fields listed"
        } else {
            "withheld"
        };
        broker::append_audit(store, &agent(), name, decision, &broker::own_ancestry(), "")?;
        names?
    };
    Ok(labels)
}

pub(crate) fn rm(store: &Store, name: &str) -> Result<()> {
    let key = unlock(store, &format!("delete {name}"))?;
    let (id, _) = store
        .find(name, &key)?
        .with_context(|| format!("no secret named {name}"))?;
    store.delete(&id, &key)?;
    store.prune_tombs(&key)?;
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
    store.restore_version(&id, path, key)?;
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

    /// YAML refuses DEL and the C1 controls even quoted, and folds NEL into a space
    #[test]
    fn yaml_quotes_escape_what_yaml_does_not_allow_raw() {
        assert_eq!(super::yaml_quoted("null"), "\"null\"");
        assert_eq!(super::yaml_quoted("a\u{7f}b"), "\"a\\u007Fb\"");
        assert_eq!(super::yaml_quoted("a\u{85}b"), "\"a\\u0085b\"");
        assert_eq!(super::yaml_quoted("q\"\\\n"), "\"q\\\"\\\\\\n\"");
        assert_eq!(super::yaml_quoted("ação"), "\"ação\"");
    }
    use super::{extra_lines, named_fields};
    use crate::store;

    fn fields(value: &str) -> std::collections::HashMap<String, String> {
        store::fields(value).into_iter().collect()
    }

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
