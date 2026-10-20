/*! Plugins add gated reads of local apps, such as Mail and Things3.

A plugin is a directory under `~/.passbox/plugins/<name>/` holding a `plugin.toml`. Each tool
names a command template. The broker prompts and audits a call; the caller runs the command, so
it keeps the caller's GUI session and the broker never drives an app itself. A plugin with `stdin`
is the exception: it reads a secret, so it runs only inside the broker and only as its bundled copy. */

use crate::store::Store;
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::process::{Command, Stdio};

#[derive(Deserialize)]
pub struct Manifest {
    pub name: String,
    pub description: String,
    /// Bumped when the plugin's behaviour changes, so a stale install can be spotted
    #[serde(default)]
    pub version: Option<String>,
    /// A command the plugin shells out to, which must be on PATH
    #[serde(default)]
    pub requires: Option<String>,
    /// How to get that command, shown when it is missing
    #[serde(default)]
    pub install: Option<String>,
    /// "caller" runs tools in the invoking directory, the default runs them in the plugin dir
    #[serde(default)]
    pub cwd: Option<String>,
    /// A secret written to the tool's stdin, which makes the plugin run only on the broker
    #[serde(default)]
    pub stdin: Option<String>,
    #[serde(default, rename = "tool")]
    pub tools: Vec<Tool>,
}

#[derive(Deserialize)]
pub struct Tool {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Parameter names in call order. A trailing `?` marks one optional
    #[serde(default)]
    pub params: Vec<String>,
    /// Command and arguments. `{param}` is replaced with the bound value
    pub run: Vec<String>,
    /// Only a tool marked as a read can be named in `[plugins.windows]`
    #[serde(default)]
    pub readonly: bool,
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

    pub fn version(&self) -> &str {
        self.version.as_deref().unwrap_or("0")
    }

    pub fn tool(&self, action: &str) -> Option<&Tool> {
        self.tools.iter().find(|t| t.name == action)
    }

    /// The prompt text, which names the secret the run releases
    pub fn approval(&self, action: &str, agent: &str) -> String {
        let mut text = format!("run plugin:{}.{action} for {agent}", self.name);
        if let Some(secret) = &self.stdin {
            text.push_str(&format!(", releasing {secret}"));
        }
        text
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
        self.command_with(args, &[])
    }

    /// As `command`, with a literal argument naming one of `scripts` swapped for that file's bytes
    pub fn command_with(
        &self,
        args: &HashMap<String, String>,
        scripts: &[(&str, &str)],
    ) -> Result<Command> {
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
        // Every plugin run, local, MCP or remote, starts here, so this one call covers them all
        crate::without_credentials(&mut command);
        for part in rest {
            match scripts.iter().find(|(file, _)| file == part) {
                Some((_, code)) => command.arg(code),
                None => command.arg(self.bind(part, args)?),
            };
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

/* Blank the secret, and its first line, from a run's output before it reaches an agent. Not
every field, as `run_with_secret` does, since an account entry's user and host are what a mail
tool prints */
pub fn scrub(text: &str, secret: &str) -> String {
    let mut out = text.to_string();
    for piece in [secret, secret.lines().next().unwrap_or_default()] {
        if piece.len() >= 4 {
            out = out.replace(piece, "[redacted by passbox]");
        }
    }
    out
}

/// stdout, then stderr and the exit code when the command failed
pub fn render(output: &std::process::Output) -> String {
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    let err = String::from_utf8_lossy(&output.stderr);
    if !err.trim().is_empty() {
        text.push_str("\nstderr:\n");
        text.push_str(&err);
    }
    if !output.status.success() {
        text.push_str(&format!("\nexit: {}", output.status.code().unwrap_or(1)));
    }
    text
}

/* The command for a plugin with `stdin`, built from the copy bundled in this binary once every
bundled file matches the installed one byte for byte. The script runs from the bundled bytes, so
a file swapped on disk after the check never runs */
pub fn fed_command(
    store: &Store,
    name: &str,
    action: &str,
    params: &HashMap<String, String>,
) -> Result<(Manifest, Command)> {
    let refuse = || {
        anyhow!(
            "the {name} plugin reads a secret, so only its bundled copy runs, \
             reinstall it with `passbox plugin update {name}`"
        )
    };
    let files = crate::first_party(name).ok_or_else(refuse)?;
    let dir = store.plugins_dir().join(name);
    for (file, bytes) in files {
        if std::fs::read(dir.join(file)).ok().as_deref() != Some(bytes.as_bytes()) {
            return Err(refuse());
        }
    }
    let (_, toml) = files
        .iter()
        .find(|(file, _)| *file == "plugin.toml")
        .ok_or_else(refuse)?;
    let manifest: Manifest = toml::from_str(toml).context("bundled manifest")?;
    let tool = manifest
        .tool(action)
        .with_context(|| format!("{name} has no action {action}"))?;
    manifest.ensure_available()?;
    let mut command = tool.command_with(params, files)?;
    command.current_dir(dir);
    Ok((manifest, command))
}

pub fn missing(plugin: &str, secret: &str) -> anyhow::Error {
    anyhow!("the {plugin} plugin needs the secret {secret}, add it with `passbox add {secret}`")
}

/// Run a tool with `secret` on its stdin, never its env or argv, and return the scrubbed output
pub fn run_fed(mut command: Command, secret: &str) -> Result<String> {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .context("could not run the plugin command")?;
    // Dropping the handle closes stdin, and a child that exits before reading reports that itself
    let _ = child
        .stdin
        .take()
        .expect("piped")
        .write_all(secret.as_bytes());
    let output = child.wait_with_output()?;
    Ok(scrub(&render(&output), secret))
}

/// A plugin name becomes a directory under the store, so it must not climb out of it
pub fn valid_name(name: &str) -> Result<()> {
    let safe = !name.is_empty()
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if !safe {
        bail!("invalid plugin name {name:?}, use letters, digits, dash and underscore");
    }
    Ok(())
}

pub fn load(store: &Store, name: &str) -> Result<Manifest> {
    valid_name(name)?;
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

/// The `[plugins.windows]` section of config.toml, each tool checked against its manifest
#[derive(Default)]
pub struct Windows {
    /// Seconds a `<plugin>.<tool>` stays open after an approved call
    pub tools: BTreeMap<String, u64>,
    /// Covers each window and the command it names, so editing either one asks again
    pub hash: String,
}

impl Windows {
    /// As the approval prompt lists them, such as `things3.logbook 24h, imap.search 1h`
    pub fn shown(&self) -> String {
        let span = |secs: u64| match secs {
            s if s % 3600 == 0 => format!("{}h", s / 3600),
            s if s % 60 == 0 => format!("{}m", s / 60),
            s => format!("{s}s"),
        };
        self.tools
            .iter()
            .map(|(tool, secs)| format!("{tool} {}", span(*secs)))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

pub fn windows(store: &Store) -> Result<Windows> {
    let path = crate::sync::config_path(store);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(Windows::default());
    };
    parse_windows(&text, |name| load(store, name))
        .with_context(|| format!("{} is not valid", path.display()))
}

/// `90s`, `30m` or `24h`
fn duration(text: &str) -> Result<u64> {
    let refuse = || anyhow!("{text:?} is not a duration such as \"90s\", \"30m\" or \"24h\"");
    let unit = match text.chars().last() {
        Some('s') => 1,
        Some('m') => 60,
        Some('h') => 3600,
        _ => return Err(refuse()),
    };
    let count: u64 = text[..text.len() - 1]
        .parse()
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(refuse)?;
    Ok(count.saturating_mul(unit))
}

// One plugin and one tool, so a window never covers a tool added later, and only a readonly tool,
// since a window on an action would let any caller act as the owner
fn parse_windows(text: &str, manifest: impl Fn(&str) -> Result<Manifest>) -> Result<Windows> {
    let config: toml::Table = toml::from_str(text)?;
    let Some(plugins) = config.get("plugins") else {
        return Ok(Windows::default());
    };
    let plugins = plugins.as_table().context("plugins must be a table")?;
    if let Some(other) = plugins.keys().find(|k| *k != "windows") {
        bail!("unknown key plugins.{other}, the only one is plugins.windows");
    }
    let Some(section) = plugins.get("windows") else {
        return Ok(Windows::default());
    };
    let section = section
        .as_table()
        .context("plugins.windows must be a table")?;

    let part_ok = |p: &str| {
        !p.is_empty()
            && p.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
    };
    let mut out = Windows::default();
    let mut hashed = String::new();
    for (key, value) in section {
        let (plugin, action) = key
            .split_once('.')
            .filter(|(p, t)| part_ok(p) && part_ok(t))
            .with_context(|| {
                format!(
                    "{key:?} must name one plugin and one tool, quoted, such as \"things3.logbook\""
                )
            })?;
        let span = value
            .as_str()
            .with_context(|| format!("{key} must be a duration such as \"30m\""))?;
        let secs = duration(span)
            .with_context(|| key.clone())?
            .min(crate::broker::MAX_GRANT_SECS);
        let manifest = manifest(plugin)
            .with_context(|| format!("{key} names a plugin that is not installed"))?;
        let tool = manifest
            .tool(action)
            .with_context(|| format!("{key}: {plugin} has no tool {action}"))?;
        if !tool.readonly {
            bail!("{key} is not marked readonly in its manifest, so it prompts on every call");
        }
        hashed.push_str(&format!(
            "{key}={secs} stdin={:?} run={:?}\n",
            manifest.stdin, tool.run
        ));
        out.tools.insert(key.clone(), secs);
    }
    out.hash = crate::project::hash(hashed.as_bytes());
    Ok(out)
}

// Plain text like the section, so a MAC under the store key stops a process forging its own
#[derive(Serialize, Deserialize)]
pub struct Approval {
    pub hash: String,
    mac: String,
}

fn approval_path(store: &Store) -> std::path::PathBuf {
    store
        .dir
        .join(format!("windows-{}.json", crate::store::hostname()))
}

fn mac(key: &age::x25519::Identity, hash: &str) -> String {
    use age::secrecy::ExposeSecret;
    let mut digest = Sha256::new();
    digest.update(b"passbox plugin windows\n");
    digest.update(key.to_string().expose_secret().as_bytes());
    digest.update(b"\n");
    digest.update(hash.as_bytes());
    hex::encode(digest.finalize())
}

/// Read before the prompt to word it, and trusted only once `verify` passes
pub fn approved(store: &Store) -> Option<Approval> {
    serde_json::from_slice(&std::fs::read(approval_path(store)).ok()?).ok()
}

pub fn approve(store: &Store, key: &age::x25519::Identity, hash: &str) -> Result<()> {
    let record = Approval {
        hash: hash.to_string(),
        mac: mac(key, hash),
    };
    crate::store::write_private(&approval_path(store), &serde_json::to_vec(&record)?)
}

impl Approval {
    pub fn verify(&self, key: &age::x25519::Identity) -> bool {
        self.mac == mac(key, &self.hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool() -> Tool {
        Tool {
            name: "send".into(),
            description: String::new(),
            params: vec!["to".into(), "subject".into(), "body?".into()],
            run: vec![
                "osascript".into(),
                "send.scpt".into(),
                "{to}".into(),
                "{subject}".into(),
                "{body}".into(),
            ],
            readonly: false,
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
    fn a_plugin_command_never_inherits_the_token_or_the_passphrase() {
        let cmd = tool()
            .command(&args(&[("to", "a"), ("subject", "b")]))
            .unwrap();
        let removed: Vec<_> = cmd
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .map(|(key, _)| key.to_string_lossy().into_owned())
            .collect();
        assert!(
            removed.contains(&"PASSBOX_TOKEN".to_string()),
            "{removed:?}"
        );
        assert!(
            removed.contains(&"PASSBOX_PASSPHRASE".to_string()),
            "{removed:?}"
        );
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
    fn a_things3_job_tool_needs_its_limit_or_date() {
        let text = std::fs::read_to_string("plugins/things3/plugin.toml").unwrap();
        let manifest: Manifest = toml::from_str(&text).unwrap();
        for (action, param) in [
            ("inbox_json", "limit"),
            ("completed", "modified_after"),
            ("search_json", "query"),
        ] {
            let err = manifest
                .tool(action)
                .unwrap()
                .command(&args(&[]))
                .unwrap_err();
            assert!(
                err.to_string().contains(&format!("needs --{param}")),
                "{action}: {err}"
            );
        }
        // A query that looks like a flag stays after `--`, so it is searched for, not parsed
        let cmd = manifest
            .tool("search_json")
            .unwrap()
            .command(&args(&[("query", "--limit=1")]))
            .unwrap();
        let argv: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(argv, ["search", "--json", "--", "--limit=1"]);
    }

    #[test]
    fn every_first_party_tool_builds_the_expected_command() {
        fn built(plugin: &str, action: &str, pairs: &[(&str, &str)]) -> Vec<String> {
            let text = std::fs::read_to_string(format!("plugins/{plugin}/plugin.toml")).unwrap();
            let manifest: Manifest = toml::from_str(&text).unwrap();
            let cmd = manifest
                .tool(action)
                .unwrap_or_else(|| panic!("{plugin} has no {action}"))
                .command(&args(pairs))
                .unwrap();
            let mut out = vec![cmd.get_program().to_string_lossy().into_owned()];
            out.extend(cmd.get_args().map(|a| a.to_string_lossy().into_owned()));
            out
        }
        type Case = (
            &'static str,
            &'static str,
            &'static [(&'static str, &'static str)],
            &'static [&'static str],
        );
        let cases: &[Case] = &[
            (
                "mail",
                "recent",
                &[("count", "5")],
                &["osascript", "recent.applescript", "5"],
            ),
            (
                "mail",
                "recent",
                &[],
                &["osascript", "recent.applescript", ""],
            ),
            (
                "mail",
                "search",
                &[("query", "inv")],
                &["osascript", "search.applescript", "inv"],
            ),
            ("calendar", "today", &[], &["bash", "agenda.sh", "0"]),
            (
                "calendar",
                "agenda",
                &[("days", "3")],
                &["bash", "agenda.sh", "3"],
            ),
            ("things3", "inbox", &[], &["things", "inbox"]),
            ("things3", "today", &[], &["things", "today"]),
            (
                "things3",
                "search",
                &[("query", "q")],
                &["things", "search", "--", "q"],
            ),
            (
                "things3",
                "today_json",
                &[],
                &["things", "today", "--json", "--recursive"],
            ),
            (
                "things3",
                "inbox_json",
                &[("limit", "20")],
                &["things", "inbox", "--json", "--recursive", "--limit", "20"],
            ),
            (
                "things3",
                "search_json",
                &[("query", "q")],
                &["things", "search", "--json", "--", "q"],
            ),
            (
                "things3",
                "upcoming",
                &[],
                &["things", "upcoming", "--json", "--recursive"],
            ),
            ("things3", "logbook", &[], &["things", "logbook", "--json"]),
            (
                "things3",
                "completed",
                &[("modified_after", "2026-01-31")],
                &[
                    "things",
                    "completed",
                    "--json",
                    "--modified-after",
                    "2026-01-31",
                ],
            ),
            ("things3", "all", &[], &["things", "all"]),
            ("things3", "trash", &[], &["things", "trash"]),
            (
                "imap",
                "recent",
                &[("count", "5")],
                &["/usr/bin/python3", "-I", "-c", "imap.py", "recent", "5", ""],
            ),
            (
                "imap",
                "search",
                &[("query", "invoice"), ("mailbox", "Archive")],
                &[
                    "/usr/bin/python3",
                    "-I",
                    "-c",
                    "imap.py",
                    "search",
                    "invoice",
                    "Archive",
                ],
            ),
            (
                "imap",
                "read",
                &[("id", "42")],
                &["/usr/bin/python3", "-I", "-c", "imap.py", "read", "42", ""],
            ),
            (
                "imap",
                "attachments",
                &[("id", "42")],
                &[
                    "/usr/bin/python3",
                    "-I",
                    "-c",
                    "imap.py",
                    "attachments",
                    "42",
                    "",
                ],
            ),
        ];
        for (plugin, action, pairs, expected) in cases {
            assert_eq!(&built(plugin, action, pairs), expected, "{plugin} {action}");
        }
    }

    fn fed() -> Manifest {
        toml::from_str(
            "name = \"demo\"\ndescription = \"test\"\nstdin = \"mail/imap\"\n\
             [[tool]]\nname = \"recent\"\nparams = [\"q\"]\n\
             run = [\"sh\", \"-c\", \"run.sh\", \"run.sh\", \"{q}\"]\n",
        )
        .unwrap()
    }

    #[test]
    fn the_prompt_names_the_secret_the_run_releases() {
        let mut manifest = fed();
        assert_eq!(
            manifest.approval("recent", "claude"),
            "run plugin:demo.recent for claude, releasing mail/imap"
        );
        manifest.stdin = None;
        assert_eq!(
            manifest.approval("recent", "claude"),
            "run plugin:demo.recent for claude"
        );
    }

    #[test]
    fn a_script_name_in_the_template_becomes_its_bytes_and_a_param_value_does_not() {
        let manifest = fed();
        let cmd = manifest
            .tool("recent")
            .unwrap()
            .command_with(&args(&[("q", "run.sh")]), &[("run.sh", "echo {q}")])
            .unwrap();
        let rendered: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(rendered, ["-c", "echo {q}", "echo {q}", "run.sh"]);
    }

    #[test]
    fn the_child_gets_the_secret_on_stdin_and_not_in_its_env() {
        let manifest = fed();
        let script = "read -r pw; echo \"got $pw\" >&2; env";
        let cmd = manifest
            .tool("recent")
            .unwrap()
            .command_with(&args(&[("q", "x")]), &[("run.sh", script)])
            .unwrap();
        let out = run_fed(cmd, "hunter22-pw\nhost: h").unwrap();
        // The child read it, and passbox blanked it on the way out
        assert!(out.contains("got [redacted by passbox]"), "{out}");
        let env = out.split("stderr:").next().unwrap();
        assert!(!env.contains("hunter22"), "{env}");
        assert!(!env.contains("redacted"), "{env}");
        assert!(!out.contains("hunter22"), "{out}");
    }

    #[test]
    fn a_password_is_scrubbed_and_its_fields_are_left() {
        let secret = "hunter22\nuser: me@example.com";
        assert_eq!(
            scrub("me@example.com said hunter22", secret),
            "me@example.com said [redacted by passbox]"
        );
        assert_eq!(
            scrub(&format!("entry: {secret}"), secret),
            "entry: [redacted by passbox]"
        );
    }

    #[test]
    fn a_name_that_climbs_out_of_the_plugins_dir_is_rejected() {
        for bad in ["../victim", "..", "a/b", "a/../b", "", "x/../../y"] {
            assert!(valid_name(bad).is_err(), "{bad} should be rejected");
        }
        for good in ["mail", "things3", "my-plugin", "my_plugin", "a.b"] {
            assert!(valid_name(good).is_ok(), "{good} should be allowed");
        }
    }

    fn installed_demo(name: &str) -> Result<Manifest> {
        if name != "demo" {
            bail!("no plugin named {name}");
        }
        Ok(toml::from_str(
            "name = \"demo\"\ndescription = \"test\"\n\
             [[tool]]\nname = \"read\"\nreadonly = true\nrun = [\"true\"]\n\
             [[tool]]\nname = \"act\"\nrun = [\"true\"]\n",
        )
        .unwrap())
    }

    fn parsed(section: &str) -> Result<Windows> {
        parse_windows(&format!("[plugins.windows]\n{section}\n"), installed_demo)
    }

    #[test]
    fn a_window_names_exactly_one_installed_readonly_tool() {
        let ok = parsed("\"demo.read\" = \"90s\"").unwrap();
        assert_eq!(ok.tools["demo.read"], 90);
        for (bad, why) in [
            ("demo = \"1h\"", "one plugin and one tool"),
            ("\"*\" = \"1h\"", "one plugin and one tool"),
            ("\"demo.*\" = \"1h\"", "one plugin and one tool"),
            ("\"*.read\" = \"1h\"", "one plugin and one tool"),
            ("\"demo.read.x\" = \"1h\"", "one plugin and one tool"),
            ("\"demo.\" = \"1h\"", "one plugin and one tool"),
            ("allow_writes = true", "one plugin and one tool"),
            ("\"demo.act\" = \"1h\"", "not marked readonly"),
            ("\"demo.nope\" = \"1h\"", "demo has no tool nope"),
            ("\"other.read\" = \"1h\"", "not installed"),
            ("\"demo.read\" = \"1d\"", "not a duration"),
            ("\"demo.read\" = \"0s\"", "not a duration"),
            ("\"demo.read\" = 60", "must be a duration"),
        ] {
            let err = format!("{:#}", parsed(bad).err().expect(bad));
            assert!(err.contains(why), "{bad}: {err}");
        }
        let err = parse_windows("[plugins]\nallow_writes = true\n", installed_demo)
            .err()
            .unwrap();
        assert!(err.to_string().contains("unknown key plugins.allow_writes"));
    }

    #[test]
    fn a_window_is_capped_at_a_day_and_shown_as_set() {
        let w = parsed("\"demo.read\" = \"48h\"").unwrap();
        assert_eq!(w.tools["demo.read"], crate::broker::MAX_GRANT_SECS);
        assert_eq!(w.shown(), "demo.read 24h");
        assert_eq!(
            parsed("\"demo.read\" = \"30m\"").unwrap().shown(),
            "demo.read 30m"
        );
        assert_eq!(
            parsed("\"demo.read\" = \"90s\"").unwrap().shown(),
            "demo.read 90s"
        );
    }

    #[test]
    fn no_section_opens_no_window_and_an_edit_changes_the_hash() {
        assert!(parse_windows("", installed_demo).unwrap().tools.is_empty());
        assert!(
            parse_windows("[sync]\nengine = \"icloud\"\n", installed_demo)
                .unwrap()
                .tools
                .is_empty()
        );
        let a = parsed("\"demo.read\" = \"1h\"").unwrap().hash;
        assert_eq!(a, parsed("\"demo.read\" = \"60m\"").unwrap().hash);
        assert_ne!(a, parsed("\"demo.read\" = \"2h\"").unwrap().hash);
    }

    #[test]
    fn an_approval_record_verifies_only_under_the_key_that_made_it() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store {
            dir: tmp.path().to_path_buf(),
        };
        let key = age::x25519::Identity::generate();
        approve(&store, &key, "h1").unwrap();
        let record = approved(&store).unwrap();
        assert_eq!(record.hash, "h1");
        assert!(record.verify(&key));
        assert!(!record.verify(&age::x25519::Identity::generate()));
        let forged = Approval {
            hash: "h2".into(),
            mac: record.mac.clone(),
        };
        assert!(!forged.verify(&key));
    }

    #[test]
    fn every_first_party_tool_is_a_read() {
        for plugin in ["mail", "calendar", "things3", "imap"] {
            let text = std::fs::read_to_string(format!("plugins/{plugin}/plugin.toml")).unwrap();
            let manifest: Manifest = toml::from_str(&text).unwrap();
            for tool in &manifest.tools {
                assert!(tool.readonly, "{plugin}.{} is not readonly", tool.name);
            }
        }
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
