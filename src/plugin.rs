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
    /// A command the plugin shells out to, which must be on PATH
    #[serde(default)]
    pub requires: Option<String>,
    /// How to get that command, shown when it is missing
    #[serde(default)]
    pub install: Option<String>,
    /// "caller" runs tools in the invoking directory, the default runs them in the plugin dir
    #[serde(default)]
    pub cwd: Option<String>,
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

/// Whether a command resolves, by its own path or on PATH, without running it
fn on_path(command: &str) -> bool {
    if command.contains('/') {
        return std::path::Path::new(command).exists();
    }
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(command).exists()))
        .unwrap_or(false)
}

impl Manifest {
    /// Refuse before prompting when a declared command is missing, and say how to get it
    pub fn ensure_available(&self) -> Result<()> {
        if let Some(command) = &self.requires
            && !on_path(command)
        {
            let hint = self
                .install
                .as_deref()
                .map(|i| format!("\ninstall it with: {i}"))
                .unwrap_or_default();
            bail!(
                "the {} plugin needs `{command}`, which is not on PATH{hint}",
                self.name
            );
        }
        Ok(())
    }

    /// Whether tools run where they were invoked rather than in the plugin directory
    pub fn runs_in_caller_dir(&self) -> bool {
        self.cwd.as_deref() == Some("caller")
    }

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
            command.arg(self.bind(part, args)?);
        }
        Ok(command)
    }

    /* A placeholder stands for a whole argument, never part of one. Each value becomes one argv
    element, so a plugin passes it to its program as data, such as `osascript script.scpt {body}`
    read through `on run argv`. Interpolating into a larger string would let a value break out and
    become code when an interpreter parses it, which is the injection this refuses. */
    fn bind(&self, part: &str, args: &HashMap<String, String>) -> Result<String> {
        if let Some(name) = part.strip_prefix('{').and_then(|p| p.strip_suffix('}'))
            && self.known(name)
        {
            return Ok(args.get(name).cloned().unwrap_or_default());
        }
        for param in &self.params {
            let bare = param.trim_end_matches('?');
            if part.contains(&format!("{{{bare}}}")) {
                bail!(
                    "{}: {bare} must be a whole argument, not embedded in {part:?}",
                    self.name
                );
            }
        }
        Ok(part.to_string())
    }
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
                "send.scpt".into(),
                "{to}".into(),
                "{subject}".into(),
                "{body}".into(),
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
    fn each_value_is_a_whole_argument_and_an_absent_optional_is_empty() {
        let cmd = tool()
            .command(&args(&[("to", "a@b.com"), ("subject", "hi; rm -rf ~")]))
            .unwrap();
        let rendered: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        // The value with shell metacharacters is one argv element, never parsed, body blank
        assert_eq!(rendered, vec!["send.scpt", "a@b.com", "hi; rm -rf ~", ""]);
    }

    #[test]
    fn a_value_embedded_in_a_larger_argument_is_refused() {
        let mut t = tool();
        t.run = vec![
            "osascript".into(),
            "-e".into(),
            "set b to \"{subject}\"".into(),
        ];
        let err = t
            .command(&args(&[("to", "a"), ("subject", "b")]))
            .unwrap_err();
        assert!(err.to_string().contains("whole argument"), "{err}");
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
    fn first_party_write_tools_build_the_expected_command() {
        fn built(plugin: &str, action: &str, pairs: &[(&str, &str)]) -> Vec<String> {
            let text = std::fs::read_to_string(format!("plugins/{plugin}/plugin.toml")).unwrap();
            let manifest: Manifest = toml::from_str(&text).unwrap();
            let cmd = manifest
                .tool(action)
                .unwrap()
                .command(&args(pairs))
                .unwrap();
            let mut out = vec![cmd.get_program().to_string_lossy().into_owned()];
            out.extend(cmd.get_args().map(|a| a.to_string_lossy().into_owned()));
            out
        }
        assert_eq!(built("git", "push", &[]), vec!["git", "push"]);
        assert_eq!(
            built("gh", "pr", &[("title", "T"), ("body", "B")]),
            vec!["gh", "pr", "create", "--title", "T", "--body", "B"]
        );
        assert_eq!(
            built("things3", "add", &[("title", "buy milk")]),
            vec!["things", "add", "--notes", "", "--", "buy milk"]
        );
        assert_eq!(
            built(
                "mail",
                "send",
                &[("to", "a@b"), ("subject", "S"), ("body", "hi")]
            ),
            vec!["osascript", "send.applescript", "a@b", "S", "hi"]
        );
    }

    #[test]
    fn a_literal_brace_that_is_not_a_parameter_passes_through() {
        // AppleScript records use braces, so a literal {a, b} must survive untouched
        let mut t = tool();
        t.run = vec!["osascript".into(), "-e".into(), "{1, 2}".into()];
        let cmd = t.command(&args(&[("to", "a"), ("subject", "b")])).unwrap();
        let rendered: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(rendered, vec!["-e", "{1, 2}"]);
    }
}
