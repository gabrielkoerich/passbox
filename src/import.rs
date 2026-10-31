//! Copying secrets across from another password manager: one loop, and a `Source` for each manager.

mod onepassword;
mod pass;

pub(crate) use onepassword::OnePassword;
pub(crate) use pass::Pass;

use crate::ssh;
use crate::store::{Secret, Store, new_id, now};
use age::x25519;
use anyhow::Result;
use std::collections::{HashMap, HashSet};

/// A password manager passbox can copy secrets out of
pub(crate) trait Source {
    /// What the source needs to read one entry's value later
    type Handle;

    /// How the unlock prompt names the source, such as `1Password`
    fn name(&self) -> &'static str;

    /// Every entry `from` selects, named as it lands in the store under `prefix`. Reads no value
    fn entries(&self, from: Option<&str>, prefix: Option<&str>)
    -> Result<Vec<Entry<Self::Handle>>>;

    /// One entry's value, read only when it is about to be written
    fn fetch(&self, handle: &Self::Handle) -> Result<Fetched>;
}

/// One entry a source offers
pub(crate) struct Entry<H> {
    /// How the source shows it, such as `Personal/GitHub`
    pub(crate) label: String,
    /// The name it gets in the store
    pub(crate) name: String,
    pub(crate) handle: H,
}

/// What a fetch found: a value to store, or why the entry stays behind
pub(crate) enum Fetched {
    /// Notes name parts of the entry that were left out. A blob is a whole text, such as a key
    Value {
        value: String,
        notes: Vec<String>,
        blob: bool,
    },
    Skip(String),
}

pub(crate) enum Outcome {
    Imported(Vec<String>),
    Exists,
    Skipped(String),
}

/// What happened to one entry, for the report
pub(crate) struct Line {
    pub(crate) item: String,
    pub(crate) name: String,
    pub(crate) outcome: Outcome,
}

/// Whether the import writes, or only reports what it would write
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Write,
    DryRun,
}

/// Values go from the source to the store in this process and are never printed. A dry run reads
/// the same values, so its skips are the real ones, and writes nothing
pub(crate) fn import<S: Source>(
    store: &Store,
    source: &S,
    entries: Vec<Entry<S::Handle>>,
    mode: Mode,
    key: Option<&x25519::Identity>,
) -> Result<Vec<Line>> {
    let taken: HashSet<String> = match key {
        Some(key) => store.names(key)?.into_iter().collect(),
        None => HashSet::new(),
    };
    // Names this run gave out, so a second entry that maps to the same name is not reported as in the store
    let mut claimed: HashMap<String, String> = HashMap::new();
    let recipient = store.recipient()?;
    let mut report = Vec::new();

    for entry in entries {
        let Entry {
            label,
            name,
            handle,
        } = entry;
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

        let outcome = match source.fetch(&handle) {
            Err(e) => Outcome::Skipped(format!("{e:#}")),
            Ok(Fetched::Skip(reason)) => Outcome::Skipped(reason),
            Ok(Fetched::Value { value, notes, blob }) => {
                if mode == Mode::Write {
                    let secret = Secret {
                        name: name.clone(),
                        value,
                        created: now(),
                        updated: now(),
                        blob,
                    };
                    store.put(&new_id(), &secret, &recipient)?;
                    ssh::remember(store, &secret.value)?;
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
    Ok(report)
}

/// The name an entry gets under `prefix`, with no empty segment however the prefix is written
pub(crate) fn under(prefix: Option<&str>, name: &str) -> String {
    match prefix
        .map(|p| p.trim_matches('/'))
        .filter(|p| !p.is_empty())
    {
        Some(p) => format!("{p}/{name}"),
        None => name.to_string(),
    }
}
