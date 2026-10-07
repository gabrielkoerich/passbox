/*! Plugins add gated actions on local apps, such as Mail and Things3.

A plugin is a directory under `~/.passbox/plugins/<name>/` holding a `plugin.toml`. Each tool
names a command template and an approval mode. The broker approves and audits a call; the
caller runs the command, so the command keeps the caller's GUI session and the broker never
drives an app itself. */

use crate::store::{Mode, Store};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::HashMap;
use std::process::Command;

#[derive(Deserialize)]
pub struct Manifest {
    pub name: String,
    pub description: String,
    #[serde(default, rename = "tool")]
    pub tools: Vec<Tool>,
}

#[derive(Deserialize)]
pub struct Tool {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub mode: Mode,
    /// Parameter names in call order. A trailing `?` marks one optional
    #[serde(default)]
    pub params: Vec<String>,
    /// Command and arguments. `{param}` is replaced with the bound value
    pub run: Vec<String>,
}

impl Manifest {
    pub fn tool(&self, action: &str) -> Option<&Tool> {
        self.tools.iter().find(|t| t.name == action)
    }
}

impl Tool {
    fn required(&self) -> impl Iterator<Item = &str> {
        self.params
            .iter()
            .filter(|p| !p.ends_with('?'))
            .map(String::as_str)
    }

    fn known(&self, key: &str) -> bool {
        self.params.iter().any(|p| p.trim_end_matches('?') == key)
    }

    /* Build the command with `{param}` placeholders filled from `args`. A missing required
    parameter or an unknown one is refused, so a typo fails here rather than running a command
    with an empty value spliced in. */
    pub fn command(&self, args: &HashMap<String, String>) -> Result<Command> {
        for name in self.required() {
            if !args.contains_key(name) {
                bail!("{} needs --{name}", self.name);
            }
        }
        for key in args.keys() {
            if !self.known(key) {
                bail!("{} has no parameter {key}", self.name);
            }
        }
        let (program, rest) = self.run.split_first().context("tool has no command")?;
        let mut command = Command::new(program);
        for part in rest {
            command.arg(fill(part, args));
        }
        Ok(command)
    }
}

/// Replace every `{name}` with its bound value, or the empty string for an absent optional
fn fill(template: &str, args: &HashMap<String, String>) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let Some(end) = rest[start..].find('}') else {
            out.push_str(&rest[start..]);
            return out;
        };
        let key = &rest[start + 1..start + end];
        out.push_str(args.get(key).map(String::as_str).unwrap_or(""));
        rest = &rest[start + end + 1..];
    }
    out.push_str(rest);
    out
}

pub fn load(store: &Store, name: &str) -> Result<Manifest> {
    let path = store.plugins_dir().join(name).join("plugin.toml");
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("no plugin named {name}, run `passbox plugin add {name}`"))?;
    let manifest: Manifest = toml::from_str(&text).with_context(|| format!("{name} manifest"))?;
    if manifest.name != name {
        bail!("plugin dir {name} holds a manifest named {}", manifest.name);
    }
    Ok(manifest)
}

pub fn installed(store: &Store) -> Result<Vec<Manifest>> {
    let dir = store.plugins_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let path = entry?.path();
        if path.is_dir()
            && let Some(name) = path.file_name().and_then(|n| n.to_str())
            && let Ok(manifest) = load(store, name)
        {
            out.push(manifest);
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool() -> Tool {
        Tool {
            name: "send".into(),
            description: String::new(),
            mode: Mode::Always,
            params: vec!["to".into(), "subject".into(), "body?".into()],
            run: vec![
                "osascript".into(),
                "-e".into(),
                "to={to} body={body}".into(),
            ],
        }
    }

    fn args(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn placeholders_are_filled_and_absent_optionals_blank() {
        let cmd = tool()
            .command(&args(&[("to", "a@b.com"), ("subject", "hi")]))
            .unwrap();
        let rendered: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(rendered, vec!["-e", "to=a@b.com body="]);
    }

    #[test]
    fn a_missing_required_parameter_is_refused() {
        let err = tool().command(&args(&[("to", "a@b.com")])).unwrap_err();
        assert!(err.to_string().contains("needs --subject"), "{err}");
    }

    #[test]
    fn an_unknown_parameter_is_refused() {
        let err = tool()
            .command(&args(&[("to", "a"), ("subject", "b"), ("cc", "x")]))
            .unwrap_err();
        assert!(err.to_string().contains("no parameter cc"), "{err}");
    }

    #[test]
    fn a_brace_with_no_close_is_left_alone() {
        assert_eq!(fill("a {to} {oops", &args(&[("to", "x")])), "a x {oops");
    }
}
