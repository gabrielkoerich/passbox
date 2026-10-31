//! `passbox import`: copying secrets across from pass or from 1Password.

use crate::import::{self, Line, Mode, OnePassword, Outcome, Pass, Source};
use crate::store::Store;
use crate::unlock;
use anyhow::Result;

/// The password manager `passbox import` copies from
#[derive(Clone, Copy, clap::ValueEnum)]
pub(crate) enum Manager {
    Pass,
    #[value(name = "1password")]
    OnePassword,
}

pub(crate) fn import(
    store: &Store,
    manager: Manager,
    from: Option<&str>,
    prefix: Option<&str>,
    mode: Mode,
) -> Result<()> {
    match manager {
        Manager::Pass => run(store, &Pass, from, prefix, mode),
        Manager::OnePassword => run(store, &OnePassword, from, prefix, mode),
    }
}

fn run<S: Source>(
    store: &Store,
    source: &S,
    from: Option<&str>,
    prefix: Option<&str>,
    mode: Mode,
) -> Result<()> {
    // Listing reads no value, so a bad selection fails before any prompt
    let entries = source.entries(from, prefix)?;
    // One approval covers the whole import, it only reads the names to refuse a duplicate
    let key = if store.ids()?.is_empty() {
        None
    } else {
        Some(unlock(store, &format!("import from {}", source.name()))?)
    };
    let report = import::import(store, source, entries, mode, key.as_ref())?;
    print_report(&report, mode);
    Ok(())
}

fn print_report(report: &[Line], mode: Mode) {
    let (mut imported, mut exists, mut skipped) = (0, Vec::new(), 0);
    for line in report {
        match &line.outcome {
            Outcome::Imported(notes) => {
                imported += 1;
                if mode == Mode::DryRun {
                    eprintln!("{} -> {}", line.item, line.name);
                }
                for note in notes {
                    eprintln!("  {}: {note}", line.name);
                }
            }
            Outcome::Skipped(why) => {
                skipped += 1;
                eprintln!("skipped {}, {why}", line.item);
            }
            Outcome::Exists => exists.push(&line.name),
        }
    }
    for name in &exists {
        eprintln!("refused {name}, already in the store");
    }
    let verb = match mode {
        Mode::Write => "imported",
        Mode::DryRun => "would import",
    };
    eprintln!(
        "{verb} {imported}, skipped {skipped}, refused {} already there",
        exists.len()
    );
}
