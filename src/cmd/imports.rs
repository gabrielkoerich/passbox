//! Copying secrets across from pass and from 1Password.

use crate::store::Store;
use crate::unlock;
use crate::{import, onepassword};
use anyhow::{Result, bail};

pub(crate) fn import_pass(store: &Store, prefix: Option<&str>) -> Result<()> {
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

pub(crate) fn import_1password(store: &Store, options: &onepassword::Options<'_>) -> Result<()> {
    // One approval covers the whole import, it only reads the names to refuse a duplicate
    let key = if store.ids()?.is_empty() {
        None
    } else {
        Some(unlock(store, "import items from 1Password")?)
    };
    let report = onepassword::import(store, options, key.as_ref())?;

    let (mut imported, mut exists, mut skipped) = (0, Vec::new(), 0);
    for line in &report {
        match &line.outcome {
            onepassword::Outcome::Imported(notes) => {
                imported += 1;
                if options.dry_run {
                    eprintln!("{} -> {}", line.item, line.name);
                }
                for note in notes {
                    eprintln!("  {}: {note}", line.name);
                }
            }
            onepassword::Outcome::Skipped(why) => {
                skipped += 1;
                eprintln!("skipped {}, {why}", line.item);
            }
            onepassword::Outcome::Exists => exists.push(&line.name),
        }
    }
    for name in &exists {
        eprintln!("refused {name}, already in the store");
    }
    let verb = if options.dry_run {
        "would import"
    } else {
        "imported"
    };
    eprintln!(
        "{verb} {imported}, skipped {skipped}, refused {} already there",
        exists.len()
    );
    Ok(())
}
