//! Plugin calls: the prompt or window that approves one, and running it when the broker must.

use super::windows::{Window, open_window, window_open};
use super::{Broker, Request};
use crate::{plugin, store};
use anyhow::{Context, Result, anyhow, bail};
use std::collections::HashMap;

// Run a built plugin command and return stdout, with stderr and the exit code on failure
fn run_plugin_command(mut command: std::process::Command) -> Result<String> {
    let out = command
        .output()
        .context("could not run the plugin command")?;
    Ok(plugin::render(&out))
}

impl Broker {
    /* The prompt for one plugin call, or the window that covers that exact call. A changed
    `[plugins.windows]` section is listed in this one prompt, and approving it records the new hash.
    Returns the value of a fed plugin's secret, read from the store after a prompt or held by the
    window */
    fn plugin_approval(
        &mut self,
        request: &Request,
        caller: &str,
        scope: &str,
        manifest: &plugin::Manifest,
        bound: &HashMap<String, String>,
    ) -> Result<Option<String>> {
        let secret = manifest.stdin.as_deref();
        let reason = manifest.approval(&request.action, &request.agent, bound);
        let (args, call) = manifest
            .tool(&request.action)
            .map(|t| (t.shown(bound), t.call(bound)))
            .ok_or_else(|| anyhow!("{} has no action {}", request.name, request.action))?;
        let tool = format!("{}.{}", request.name, request.action);
        let slot = format!("plugin:{tool}");
        let policy = plugin::windows(&self.store)?;
        if let Some(window) = window_open(
            &self.windows,
            &policy,
            self.approved.as_deref(),
            scope,
            &tool,
            &call,
            store::now(),
        ) {
            let held = window.secret.clone();
            self.audit_by(&request.agent, &slot, "by window", caller, &args)?;
            return Ok(held);
        }

        let stored = plugin::approved(&self.store);
        let changed =
            !policy.tools.is_empty() && stored.as_ref().map(|a| &a.hash) != Some(&policy.hash);
        let reason = if changed {
            format!(
                "allow plugin windows {} for {}, then {reason}",
                policy.shown(),
                request.agent
            )
        } else {
            reason
        };
        let mut asked = vec![slot.as_str()];
        asked.extend(secret);
        self.ask(&reason)
            .map_err(|e| self.refused(&request.agent, &asked, e, caller))?;
        let key = self.key.clone().expect("just unlocked");
        // Windows opened under the old section do not carry over to the new one
        if changed {
            plugin::approve(&self.store, &key, &policy.hash)?;
            self.windows.clear();
        }
        // A record this broker did not sign is ignored, so a forged one opens nothing
        let trusted = changed || stored.is_some_and(|a| a.hash == policy.hash && a.verify(&key));
        self.approved = trusted.then(|| policy.hash.clone());
        self.audit_by(&request.agent, &slot, "approved", caller, &args)?;

        let value = match secret {
            Some(name) => match self.store.find(name, &key)? {
                Some((_, entry)) => Some(entry.value.clone()),
                None => return Err(plugin::missing(&request.name, name)),
            },
            None => None,
        };
        if trusted && policy.tools.contains_key(&tool) {
            open_window(
                &mut self.windows,
                (scope.to_string(), tool, call),
                Window {
                    opened: store::now(),
                    secret: value.clone(),
                },
            );
        }
        Ok(value)
    }

    /* A plugin action prompts unless a window from config.toml covers it. Approval and audit are
    the whole job here, the caller runs the command, because it holds the GUI session the broker
    does not. */
    pub(super) fn handle_plugin(
        &mut self,
        request: &Request,
        caller: &str,
        scope: &str,
    ) -> Result<String> {
        let manifest = plugin::load(&self.store, &request.name)?;
        if manifest.stdin.is_some() {
            return self.handle_fed_plugin(request, caller, scope);
        }

        let tool = manifest
            .tool(&request.action)
            .ok_or_else(|| anyhow!("{} has no action {}", request.name, request.action))?;
        // Built before the prompt, so a missing or unknown parameter is refused without one
        let bound: HashMap<String, String> = request.params.iter().cloned().collect();
        let mut command = tool.command(&bound)?;
        self.plugin_approval(request, caller, scope, &manifest, &bound)?;
        if !request.run {
            return Ok("ok".to_string());
        }

        // A caller-directory tool acts on the caller's repo, which does not exist on the host
        if manifest.runs_in_caller_dir() {
            bail!("{} runs on the caller, not on the host", request.name);
        }
        manifest.ensure_available()?;
        command.current_dir(self.store.plugins_dir().join(&request.name));
        run_plugin_command(command)
    }

    /* A plugin with `stdin` runs here and nowhere else, so its secret goes from the store to the
    child's stdin and no reply ever holds it. Every refusal comes before the prompt */
    fn handle_fed_plugin(
        &mut self,
        request: &Request,
        caller: &str,
        scope: &str,
    ) -> Result<String> {
        if !request.run {
            bail!(
                "{} runs on the broker so its secret never leaves it, send a run request",
                request.name
            );
        }

        let bound: HashMap<String, String> = request.params.iter().cloned().collect();
        let (manifest, command) =
            plugin::fed_command(&self.store, &request.name, &request.action, &bound)?;
        let secret = manifest
            .stdin
            .as_deref()
            .ok_or_else(|| anyhow!("{} reads no secret in its bundled copy", request.name))?;
        let value = self
            .plugin_approval(request, caller, scope, &manifest, &bound)?
            .ok_or_else(|| anyhow!("no secret for {}, approve it again", request.name))?;
        let args = manifest
            .tool(&request.action)
            .map(|t| t.shown(&bound))
            .unwrap_or_default();
        self.audit_by(&request.agent, secret, "released", caller, &args)?;
        // The output crosses the socket or the tailnet, so it is scrubbed on the way out
        plugin::run_fed(command, &value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_plugin_command_returns_output_then_stderr_and_exit() {
        let mut ok = std::process::Command::new("printf");
        ok.args(["%s", "hello"]);
        assert_eq!(run_plugin_command(ok).unwrap(), "hello");

        let mut bad = std::process::Command::new("sh");
        bad.args(["-c", "printf out; printf oops >&2; exit 3"]);
        let text = run_plugin_command(bad).unwrap();
        assert!(text.contains("out"), "{text}");
        assert!(text.contains("stderr:") && text.contains("oops"), "{text}");
        assert!(text.contains("exit: 3"), "{text}");
    }
}
