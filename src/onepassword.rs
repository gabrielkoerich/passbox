//! Bring items across from 1Password through the `op` CLI, which the user has signed in

use crate::store::{Secret, Store, new_id, now};
use age::x25519;
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};

#[derive(Deserialize)]
pub struct Vault {
    pub id: String,
    pub name: String,
}

#[derive(Deserialize)]
pub struct Summary {
    pub id: String,
    #[serde(default)]
    pub title: String,
}

#[derive(Deserialize, Default)]
pub struct Item {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub fields: Vec<Field>,
    #[serde(default)]
    pub urls: Vec<Url>,
}

#[derive(Deserialize, Default)]
pub struct Field {
    #[serde(default)]
    pub id: String,
    #[serde(default, rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub purpose: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub section: Option<Section>,
    #[serde(default)]
    pub ssh_formats: Option<SshFormats>,
}

#[derive(Deserialize, Default)]
pub struct Section {
    #[serde(default)]
    pub label: String,
}

#[derive(Deserialize, Default)]
pub struct SshFormats {
    pub openssh: Option<Format>,
}

#[derive(Deserialize, Default)]
pub struct Format {
    pub value: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct Url {
    #[serde(default)]
    pub href: String,
    #[serde(default)]
    pub primary: bool,
}

/// What one item becomes. Notes name parts of an imported item that were left out
pub enum Plan {
    Value(String, Vec<String>),
    SshKey(String),
    Document,
    Skip(String),
}

fn op(args: &[&str]) -> Result<Vec<u8>> {
    let mut command = std::process::Command::new("op");
    let out = crate::without_credentials(&mut command)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .context("op is not on PATH, install the 1Password CLI and sign in")?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        bail!("op {}: {}", args[..2].join(" "), err.trim());
    }
    Ok(out.stdout)
}

fn op_json<T: for<'a> Deserialize<'a>>(args: &[&str]) -> Result<T> {
    let raw = op(args)?;
    serde_json::from_slice(&raw)
        .with_context(|| format!("op {} gave unexpected JSON", args[..2].join(" ")))
}

pub fn vaults() -> Result<Vec<Vault>> {
    op_json(&["vault", "list", "--format", "json"])
}

pub fn items(vault: &Vault) -> Result<Vec<Summary>> {
    let mut all: Vec<Summary> =
        op_json(&["item", "list", "--vault", &vault.id, "--format", "json"])?;
    all.sort_by_key(|a| a.title.to_lowercase());
    Ok(all)
}

pub fn item(vault: &Vault, id: &str) -> Result<Item> {
    op_json(&["item", "get", id, "--vault", &vault.id, "--format", "json"])
}

/// `--vault` matches a vault's name, case aside, or its id
pub fn pick<'a>(all: &'a [Vault], wanted: Option<&str>) -> Vec<&'a Vault> {
    all.iter()
        .filter(|v| wanted.is_none_or(|w| v.id == w || v.name.eq_ignore_ascii_case(w)))
        .collect()
}

/// Lowercase, with every run of characters that are not letters, digits, `.` or `_` made one `-`
pub fn slug(text: &str) -> String {
    let mut out = String::new();
    for c in text.trim().chars().flat_map(char::to_lowercase) {
        if c.is_alphanumeric() || c == '.' || c == '_' {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches(['-', '.']).to_string()
}

pub fn name(prefix: Option<&str>, vault: &str, title: &str, id: &str) -> String {
    let title = match slug(title) {
        t if t.is_empty() => id.to_lowercase(),
        t => t,
    };
    let vault = match slug(vault) {
        v if v.is_empty() => "vault".to_string(),
        v => v,
    };
    match prefix
        .map(|p| p.trim_matches('/'))
        .filter(|p| !p.is_empty())
    {
        Some(p) => format!("{p}/{vault}/{title}"),
        None => format!("{vault}/{title}"),
    }
}

/**
 * The value keeps the layout `add -m` writes and `get --field` reads: the password on the first
 * line, then a `key: value` line per field and URL, then the notes. A key that repeats gets its
 * section in front, then a number, so no field shadows another
 **/
pub fn plan(item: &Item) -> Plan {
    match item.category.as_str() {
        "SSH_KEY" => ssh_key(item),
        "DOCUMENT" => Plan::Document,
        "SECURE_NOTE" => match notes(item) {
            Some(text) => Plan::Value(text.to_string(), Vec::new()),
            None => Plan::Skip("the note is empty".into()),
        },
        _ => record(item),
    }
}

fn notes(item: &Item) -> Option<&str> {
    item.fields
        .iter()
        .find(|f| f.purpose == "NOTES")
        .and_then(|f| f.value.as_deref())
        .map(|v| v.trim_end_matches('\n'))
        .filter(|v| !v.trim().is_empty())
}

fn ssh_key(item: &Item) -> Plan {
    let private = item
        .fields
        .iter()
        .find(|f| f.kind == "SSHKEY" || f.id == "private_key");
    let openssh = private
        .and_then(|f| f.ssh_formats.as_ref())
        .and_then(|s| s.openssh.as_ref())
        .and_then(|o| o.value.clone());
    match openssh {
        Some(text) => Plan::SshKey(text),
        None => Plan::SshKey(String::new()),
    }
}

fn record(item: &Item) -> Plan {
    let fields = &item.fields;
    let first = fields
        .iter()
        .position(|f| f.purpose == "PASSWORD" && has_value(f))
        .or_else(|| {
            fields
                .iter()
                .position(|f| f.kind == "CONCEALED" && has_value(f))
        });
    let password = first
        .and_then(|i| fields[i].value.as_deref())
        .unwrap_or_default();
    if password.contains('\n') {
        return Plan::Skip("the password has more than one line".into());
    }

    let mut taken: HashSet<String> = HashSet::from(["password".to_string()]);
    let mut lines = Vec::new();
    let mut notes_left = Vec::new();
    let mut add =
        |key: String, value: &str, section: Option<&str>, notes_left: &mut Vec<String>| {
            if value.contains('\n') {
                notes_left.push(format!("field {key} has more than one line, not imported"));
                return;
            }
            lines.push(format!(
                "{}: {}",
                unique(&mut taken, &key, section),
                value.trim()
            ));
        };

    let username = fields
        .iter()
        .position(|f| f.purpose == "USERNAME" && has_value(f));
    if let Some(i) = username {
        let value = fields[i].value.as_deref().unwrap_or_default();
        add("username".into(), value, None, &mut notes_left);
    }

    let mut urls: Vec<&Url> = item
        .urls
        .iter()
        .filter(|u| !u.href.trim().is_empty())
        .collect();
    urls.sort_by_key(|u| !u.primary);
    for url in urls {
        add("url".into(), &url.href, None, &mut notes_left);
    }

    for (i, f) in fields.iter().enumerate() {
        if Some(i) == first || Some(i) == username || f.purpose == "NOTES" || !has_value(f) {
            continue;
        }
        let key = field_key(f);
        if f.kind == "OTP" {
            notes_left.push(format!("{key} is a TOTP seed, passbox has no TOTP support"));
            continue;
        }
        let section = f.section.as_ref().map(|s| s.label.as_str());
        add(
            key,
            f.value.as_deref().unwrap_or_default(),
            section,
            &mut notes_left,
        );
    }

    let mut value = password.to_string();
    for line in lines {
        value.push('\n');
        value.push_str(&line);
    }
    if let Some(text) = notes(item) {
        value.push('\n');
        value.push_str(text);
    }
    if value.trim().is_empty() {
        return Plan::Skip("the item has no values".into());
    }
    Plan::Value(value, notes_left)
}

fn has_value(f: &Field) -> bool {
    f.value.as_deref().is_some_and(|v| !v.trim().is_empty())
}

/// A key cannot hold `:` or a line break, since either would change how `fields` splits the line
fn field_key(f: &Field) -> String {
    let clean = |s: &str| {
        s.replace([':', '\n', '\r'], " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase()
    };
    match clean(&f.label) {
        k if k.is_empty() => clean(&f.id),
        k => k,
    }
}

fn unique(taken: &mut HashSet<String>, key: &str, section: Option<&str>) -> String {
    let mut candidates = vec![key.to_string()];
    if let Some(s) = section
        .map(|s| s.trim().to_lowercase().replace(':', " "))
        .filter(|s| !s.is_empty())
    {
        candidates.push(format!("{s} {key}"));
    }
    let base = candidates.last().cloned().unwrap_or_default();
    let mut n = 2;
    loop {
        if let Some(free) = candidates.iter().find(|c| !taken.contains(*c)) {
            let free = free.clone();
            taken.insert(free.clone());
            return free;
        }
        candidates = vec![format!("{base} {n}")];
        n += 1;
    }
}

pub enum Outcome {
    Imported(Vec<String>),
    Exists,
    Skipped(String),
}

pub struct Line {
    pub item: String,
    pub name: String,
    pub outcome: Outcome,
}

pub struct Options<'a> {
    pub vault: Option<&'a str>,
    pub prefix: Option<&'a str>,
    pub dry_run: bool,
}

/// Values go from `op` to the store in this process and are never printed. A dry run reads the
/// same items, so its skips are the real ones, and writes nothing
pub fn import(
    store: &Store,
    options: &Options,
    key: Option<&x25519::Identity>,
) -> Result<Vec<Line>> {
    let all = vaults()?;
    let picked = pick(&all, options.vault);
    if picked.is_empty() {
        let names: Vec<&str> = all.iter().map(|v| v.name.as_str()).collect();
        bail!(
            "no vault named {}, the vaults are: {}",
            options.vault.unwrap_or("*"),
            names.join(", ")
        );
    }

    let taken: HashSet<String> = match key {
        Some(key) => store.names(key)?.into_iter().collect(),
        None => HashSet::new(),
    };
    // Names this run gave out, so a second item that slugs the same is not reported as in the store
    let mut claimed: HashMap<String, String> = HashMap::new();
    let recipient = store.recipient()?;
    let mut report = Vec::new();

    for vault in picked {
        for summary in items(vault)? {
            let label = format!("{}/{}", vault.name, summary.title);
            let name = name(options.prefix, &vault.name, &summary.title, &summary.id);
            if taken.contains(&name) {
                report.push(Line {
                    item: label,
                    name,
                    outcome: Outcome::Exists,
                });
                continue;
            }

            if let Some(first) = claimed.get(&name) {
                report.push(Line {
                    outcome: Outcome::Skipped(format!("{name} is already taken by {first}")),
                    item: label,
                    name,
                });
                continue;
            }

            let outcome = match fetch(vault, &summary) {
                Err(e) => Outcome::Skipped(format!("{e:#}")),
                Ok(Err(reason)) => Outcome::Skipped(reason),
                Ok(Ok((value, notes, blob))) => {
                    if !options.dry_run {
                        let secret = Secret {
                            name: name.clone(),
                            value,
                            created: now(),
                            updated: now(),
                            blob,
                        };
                        store.put(&new_id(), &secret, &recipient)?;
                        crate::ssh::remember(store, &secret.value)?;
                    }
                    Outcome::Imported(notes)
                }
            };
            if matches!(outcome, Outcome::Imported(_)) {
                claimed.insert(name.clone(), label.clone());
            }
            report.push(Line {
                item: label,
                name,
                outcome,
            });
        }
    }
    Ok(report)
}

// The flag marks a whole text, such as a note or a key, stored as a blob
type Fetched = std::result::Result<(String, Vec<String>, bool), String>;

fn fetch(vault: &Vault, summary: &Summary) -> Result<Fetched> {
    let item = item(vault, &summary.id)?;
    Ok(match plan(&item) {
        Plan::Value(value, notes) => Ok((value, notes, item.category == "SECURE_NOTE")),
        Plan::Skip(reason) => Err(reason),
        Plan::Document => {
            let raw = op(&["document", "get", &item.id, "--vault", &vault.id])?;
            match String::from_utf8(raw) {
                Ok(text) if !text.trim().is_empty() => {
                    Ok((text.trim_end_matches('\n').to_string(), Vec::new(), true))
                }
                Ok(_) => Err("the document is empty".into()),
                Err(_) => Err("the document is binary, passbox holds text".into()),
            }
        }
        Plan::SshKey(text) => {
            let text = if text.is_empty() {
                let reference = format!(
                    "op://{}/{}/private key?ssh-format=openssh",
                    vault.id, item.id
                );
                String::from_utf8(op(&["read", &reference])?).context("the key is not text")?
            } else {
                text
            };
            let text = text.trim_end_matches('\n').to_string();
            if crate::ssh::parse(&text).is_some() {
                Ok((text, Vec::new(), true))
            } else {
                Err("the SSH agent signs with unencrypted Ed25519 or P-256 keys only".into())
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> Item {
        serde_json::from_str(json).unwrap()
    }

    fn value(plan: Plan) -> (String, Vec<String>) {
        match plan {
            Plan::Value(v, n) => (v, n),
            _ => panic!("expected a value"),
        }
    }

    #[test]
    fn titles_become_slugged_names_under_the_vault() {
        assert_eq!(
            name(None, "Personal", "GitHub (work)", "x"),
            "personal/github-work"
        );
        assert_eq!(
            name(Some("1p/"), "Private Vault", "AWS: root", "x"),
            "1p/private-vault/aws-root"
        );
        assert_eq!(
            name(None, "Personal", "Café Wi-Fi", "x"),
            "personal/café-wi-fi"
        );
        assert_eq!(name(None, "Personal", "!!!", "AbC"), "personal/abc");
    }

    #[test]
    fn a_vault_is_picked_by_name_or_id() {
        let all = vec![
            Vault {
                id: "v1".into(),
                name: "Personal".into(),
            },
            Vault {
                id: "v2".into(),
                name: "Work".into(),
            },
        ];
        assert_eq!(pick(&all, None).len(), 2);
        assert_eq!(pick(&all, Some("work"))[0].id, "v2");
        assert_eq!(pick(&all, Some("v1"))[0].name, "Personal");
        assert!(pick(&all, Some("nope")).is_empty());
    }

    #[test]
    fn a_login_keeps_the_layout_add_writes() {
        let item = parse(
            r#"{"id":"i","title":"GitHub","category":"LOGIN",
            "fields":[
              {"id":"username","type":"STRING","purpose":"USERNAME","label":"username","value":"gb"},
              {"id":"password","type":"CONCEALED","purpose":"PASSWORD","label":"password","value":"hunter2"},
              {"id":"notesPlain","type":"STRING","purpose":"NOTES","label":"notesPlain","value":"line one\nline two\n"},
              {"id":"a","type":"STRING","label":"Recovery: email","value":"me@x","section":{"id":"s","label":"Extra"}},
              {"id":"b","type":"OTP","label":"one-time password","value":"otpauth://totp/x"},
              {"id":"c","type":"STRING","label":"empty","value":""}
            ],
            "urls":[{"href":"https://other"},{"href":"https://github.com","primary":true}]}"#,
        );
        let (value, notes) = value(plan(&item));
        assert_eq!(
            value,
            "hunter2\nusername: gb\nurl: https://github.com\nurl 2: https://other\n\
             recovery email: me@x\nline one\nline two"
        );
        assert_eq!(
            notes,
            ["one-time password is a TOTP seed, passbox has no TOTP support"]
        );
    }

    /// Two fields named alike must both survive, or `get --field` would read only one
    #[test]
    fn a_repeated_label_takes_its_section_then_a_number() {
        let item = parse(
            r#"{"category":"DATABASE","fields":[
              {"id":"p","type":"CONCEALED","label":"password","value":"pw"},
              {"id":"h","type":"STRING","label":"host","value":"a"},
              {"id":"h2","type":"STRING","label":"host","value":"b","section":{"label":"Replica"}},
              {"id":"h3","type":"STRING","label":"host","value":"c","section":{"label":"Replica"}},
              {"id":"x","type":"CONCEALED","label":"Password","value":"second"}
            ]}"#,
        );
        let (value, _) = value(plan(&item));
        assert_eq!(
            value,
            "pw\nhost: a\nreplica host: b\nreplica host 2: c\npassword 2: second"
        );
    }

    #[test]
    fn a_secure_note_is_its_text() {
        let item = parse(
            r#"{"category":"SECURE_NOTE","fields":[
              {"id":"notesPlain","purpose":"NOTES","value":"-----BEGIN CERT-----\nabc\n-----END CERT-----\n"}]}"#,
        );
        let (value, _) = value(plan(&item));
        assert_eq!(value, "-----BEGIN CERT-----\nabc\n-----END CERT-----");
        let empty = parse(r#"{"category":"SECURE_NOTE","fields":[]}"#);
        assert!(matches!(plan(&empty), Plan::Skip(_)));
    }

    #[test]
    fn an_ssh_key_takes_the_openssh_text() {
        let item = parse(
            r#"{"category":"SSH_KEY","fields":[
              {"id":"private_key","type":"SSHKEY","label":"private key","value":"pkcs8",
               "ssh_formats":{"openssh":{"value":"-----BEGIN OPENSSH PRIVATE KEY-----\n"}}}]}"#,
        );
        assert!(matches!(plan(&item), Plan::SshKey(t) if t.starts_with("-----BEGIN OPENSSH")));
    }

    #[test]
    fn a_multi_line_field_is_reported_not_folded_in() {
        let item = parse(
            r#"{"category":"API_CREDENTIAL","fields":[
              {"id":"credential","type":"CONCEALED","label":"credential","value":"tok"},
              {"id":"k","type":"STRING","label":"cert","value":"a\nb"}]}"#,
        );
        let (value, notes) = value(plan(&item));
        assert_eq!(value, "tok");
        assert_eq!(notes, ["field cert has more than one line, not imported"]);
    }

    #[test]
    fn an_item_with_nothing_in_it_is_skipped() {
        let item = parse(
            r#"{"category":"LOGIN","fields":[{"id":"password","purpose":"PASSWORD","value":""}]}"#,
        );
        assert!(matches!(plan(&item), Plan::Skip(_)));
    }
}
