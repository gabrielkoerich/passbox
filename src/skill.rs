use anyhow::{Context, Result, bail};
use std::path::PathBuf;

const SKILL: &str = include_str!("../SKILL.md");
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The embedded SKILL.md with the running version added to the front matter
fn render() -> String {
    SKILL.replacen(
        "\n---\n",
        &format!("\npassbox_version: {VERSION}\n---\n"),
        1,
    )
}

fn installed_version(text: &str) -> Option<&str> {
    text.lines()
        .skip(1)
        .take_while(|l| *l != "---")
        .find_map(|l| l.strip_prefix("passbox_version:"))
        .map(str::trim)
}

fn path(dir: Option<PathBuf>) -> Result<PathBuf> {
    let dir = match dir {
        Some(dir) => dir,
        None => PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?)
            .join(".claude/skills/passbox"),
    };
    Ok(dir.join("SKILL.md"))
}

pub(crate) fn install(dir: Option<PathBuf>) -> Result<()> {
    let file = path(dir)?;
    let parent = file.parent().context("no parent directory")?;
    std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    std::fs::write(&file, render()).with_context(|| format!("write {}", file.display()))?;
    println!("installed SKILL.md {VERSION} at {}", file.display());
    Ok(())
}

pub(crate) fn check(dir: Option<PathBuf>) -> Result<()> {
    let file = path(dir)?;
    let text = match std::fs::read_to_string(&file) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!(
                "no skill at {}, run `passbox skill install`",
                file.display()
            )
        }
        Err(e) => return Err(e).with_context(|| format!("read {}", file.display())),
    };
    if text == render() {
        println!("SKILL.md is current ({VERSION})");
        return Ok(());
    }
    match installed_version(&text) {
        Some(v) if v != VERSION => bail!(
            "SKILL.md at {} is for passbox {v}, this is {VERSION}, run `passbox skill install`",
            file.display()
        ),
        Some(_) => bail!(
            "SKILL.md at {} differs from the embedded {VERSION} copy, run `passbox skill install`",
            file.display()
        ),
        None => bail!(
            "SKILL.md at {} names no version, run `passbox skill install`",
            file.display()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_names_the_version_in_front_matter() {
        let text = render();
        assert!(text.starts_with("---\nname: passbox\n"));
        assert_eq!(installed_version(&text), Some(VERSION));
    }

    #[test]
    fn install_then_check_passes_and_stale_fails() {
        let dir = std::env::temp_dir().join(format!("passbox-skill-{}", std::process::id()));
        install(Some(dir.clone())).unwrap();
        check(Some(dir.clone())).unwrap();
        let file = dir.join("SKILL.md");
        let old = std::fs::read_to_string(&file).unwrap().replace(
            &format!("passbox_version: {VERSION}"),
            "passbox_version: 0.0.1",
        );
        std::fs::write(&file, old).unwrap();
        assert!(check(Some(dir.clone())).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
