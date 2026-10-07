/* An MCP server over stdio, exposing actions rather than values.

A `get_secret` tool would be the obvious shape and the wrong one: an MCP result lands in the
model's context, where it is logged, cached and sent onward. These tools run the command for the
agent and hand back only its output, so the value never enters the transcript. */

use crate::store::Store;
use crate::{agent_read_secret, run_child};
#[cfg(feature = "host")]
use anyhow::Context;
use anyhow::{Result, anyhow};
use serde_json::{Value, json};
use std::io::{BufRead, Write};

const PROTOCOL: &str = "2025-06-18";

pub fn serve(store: Store) -> Result<()> {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    let mut agent = "mcp".to_string();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let Ok(message) = serde_json::from_str::<Value>(&line) else {
            reply(
                &mut out,
                &Value::Null,
                Err((-32700, "parse error".to_string())),
            )?;
            continue;
        };
        let id = message.get("id").cloned();
        let method = message.get("method").and_then(Value::as_str).unwrap_or("");
        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));

        let result = match method {
            "initialize" => {
                // The client names itself in the handshake, which beats guessing up the tree
                if let Some(name) = params
                    .pointer("/clientInfo/name")
                    .and_then(Value::as_str)
                    .filter(|n| !n.is_empty())
                {
                    agent = name.to_string();
                }
                Ok(initialize(&params))
            }
            "tools/list" => Ok(tools(&store)),
            "tools/call" => Ok(call(&store, &agent, &params)),
            "ping" => Ok(json!({})),
            other => Err((-32601, format!("no method named {other}"))),
        };

        // A message with no id is a notification, which takes no reply
        let Some(id) = id else {
            continue;
        };
        reply(&mut out, &id, result)?;
    }
    Ok(())
}

/// A request left unanswered hangs the client, so an unknown method still gets an error back
fn reply(out: &mut impl Write, id: &Value, result: Result<Value, (i64, String)>) -> Result<()> {
    let message = match result {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err((code, text)) => {
            json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": text}})
        }
    };
    writeln!(out, "{message}")?;
    out.flush()?;
    Ok(())
}

fn initialize(params: &Value) -> Value {
    let version = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or(PROTOCOL);
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": "passbox", "version": env!("CARGO_PKG_VERSION") },
    })
}

fn tools(store: &Store) -> Value {
    let _ = store;
    #[cfg_attr(not(feature = "host"), allow(unused_mut))]
    let mut list = vec![
        json!({
            "name": "list_secrets",
            "description": "List the names of available secrets. Raises a Touch ID prompt unless \
                            one was already approved inside the window. Returns names only.",
            "inputSchema": { "type": "object", "properties": {} }
        }),
        json!({
            "name": "run_with_secret",
            "description": "Run a command with a secret injected, and return only the command's \
                            output. The secret value is never returned. Use this instead of \
                            asking for a password: put the command that needs it here.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "secret": { "type": "string", "description": "Name of the secret, as shown by list_secrets" },
                    "command": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Command and arguments, for example [\"gh\", \"api\", \"/user\"]"
                    },
                    "env_var": {
                        "type": "string",
                        "description": "Environment variable to hold the secret in the child. \
                                        Omitted means the secret is piped to the child on stdin."
                    }
                },
                "required": ["secret", "command"]
            }
        }),
    ];
    #[cfg(feature = "host")]
    for manifest in crate::plugin::installed(store).unwrap_or_default() {
        for tool in &manifest.tools {
            list.push(plugin_tool_schema(&manifest.name, tool));
        }
    }
    json!({ "tools": list })
}

#[cfg(feature = "host")]
fn plugin_tool_schema(plugin: &str, tool: &crate::plugin::Tool) -> Value {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();
    for param in &tool.params {
        let bare = param.trim_end_matches('?');
        properties.insert(bare.to_string(), json!({ "type": "string" }));
        if !param.ends_with('?') {
            required.push(bare.to_string());
        }
    }
    json!({
        "name": format!("{plugin}.{}", tool.name),
        "description": tool.description,
        "inputSchema": { "type": "object", "properties": properties, "required": required }
    })
}

fn call(store: &Store, agent: &str, params: &Value) -> Value {
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let args = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    let outcome = match name {
        "list_secrets" => list_secrets(store, agent),
        "run_with_secret" => run_with_secret(store, agent, &args),
        other => plugin_call(store, agent, other, &args),
    };

    // A tool failure is reported in the result, so the model can read it and adjust
    match outcome {
        Ok(text) => json!({ "content": [{ "type": "text", "text": text }] }),
        Err(e) => json!({
            "content": [{ "type": "text", "text": format!("{e:#}") }],
            "isError": true
        }),
    }
}

fn list_secrets(store: &Store, agent: &str) -> Result<String> {
    let names = crate::agent_list_names(store, agent)?;
    if names.is_empty() {
        return Ok("no secrets yet".to_string());
    }
    Ok(names.join("\n"))
}

/* A plugin tool call is approved and audited by the broker, then run here so it keeps this
process's GUI session. Its output is the result, so there is nothing to scrub: a plugin injects
no secret. */
#[cfg(feature = "host")]
fn plugin_call(store: &Store, agent: &str, name: &str, args: &Value) -> Result<String> {
    let (plugin, action) = name
        .split_once('.')
        .ok_or_else(|| anyhow!("no tool named {name}"))?;
    let manifest = crate::plugin::load(store, plugin)?;
    let tool = manifest
        .tool(action)
        .ok_or_else(|| anyhow!("no tool named {name}"))?;
    manifest.ensure_available()?;
    let mut bound = std::collections::HashMap::new();
    if let Some(object) = args.as_object() {
        for (key, value) in object {
            let text = value
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| value.to_string());
            bound.insert(key.clone(), text);
        }
    }
    let mut command = tool.command(&bound)?;
    if !manifest.runs_in_caller_dir() {
        command.current_dir(store.plugins_dir().join(plugin));
    }
    crate::broker::plugin_approve(store, plugin, action, agent)?;
    let output = command
        .output()
        .with_context(|| format!("could not run {name}"))?;
    Ok(render_output(&output))
}

#[cfg(not(feature = "host"))]
fn plugin_call(_store: &Store, _agent: &str, name: &str, _args: &Value) -> Result<String> {
    Err(anyhow!("no tool named {name}"))
}

/// stdout, then stderr and the exit code when the command failed, which is what a result shows
fn render_output(output: &std::process::Output) -> String {
    let mut text = String::new();
    text.push_str(&String::from_utf8_lossy(&output.stdout));
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.trim().is_empty() {
        text.push_str("\nstderr:\n");
        text.push_str(&stderr);
    }
    if !output.status.success() {
        text.push_str(&format!("\nexit: {}", output.status.code().unwrap_or(1)));
    }
    text
}

fn run_with_secret(store: &Store, agent: &str, args: &Value) -> Result<String> {
    let secret = args
        .get("secret")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("secret is required"))?;
    let command: Vec<String> = args
        .get("command")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("command is required"))?
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    if command.is_empty() {
        return Ok("command was empty".to_string());
    }
    let env_var = args.get("env_var").and_then(Value::as_str);

    let value = agent_read_secret(store, secret, agent)?;
    let output = run_child(&command, env_var, &value)?;
    Ok(redact(&render_output(&output), &value))
}

/* A command that echoes its own secret would otherwise put it straight into the transcript.

A multi-line entry is redacted whole and also piece by piece, its password line and each field
value, because a command that prints only the first line would otherwise slip past. Longest
first, so the whole value is caught before its parts. Pieces under four characters are left, so
a field such as `id: 7` cannot blank every 7 in the output. */
fn redact(text: &str, secret: &str) -> String {
    const MIN_PIECE: usize = 4;
    let mut pieces: Vec<&str> = vec![secret];
    for (i, line) in secret.lines().enumerate() {
        let piece = match line.split_once(':') {
            Some((_, value)) if i > 0 => value.trim(),
            _ => line.trim(),
        };
        if piece.len() >= MIN_PIECE {
            pieces.push(piece);
        }
    }
    pieces.retain(|p| !p.is_empty());
    pieces.sort_by_key(|p| std::cmp::Reverse(p.len()));
    pieces.into_iter().fold(text.to_string(), |out, p| {
        out.replace(p, "[redacted by passbox]")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_secret_is_scrubbed_from_whatever_the_command_printed() {
        let out = redact("token is ghp_abc123 ok", "ghp_abc123");
        assert_eq!(out, "token is [redacted by passbox] ok");
        assert!(!out.contains("ghp_abc123"));
    }

    #[test]
    fn redacting_every_occurrence() {
        let out = redact("a s b s", "s");
        assert_eq!(out.matches("[redacted by passbox]").count(), 2);
    }

    #[test]
    fn printing_one_line_of_a_multi_line_entry_is_still_scrubbed() {
        let secret = "s3cret-pw\nusername: bot\napi_key: key-123456";
        let out = redact("pw=s3cret-pw key=key-123456 user=bot", secret);
        assert!(
            !out.contains("s3cret-pw") && !out.contains("key-123456"),
            "{out}"
        );
        // A short field is not a secret worth blanking every occurrence of
        assert!(out.contains("user=bot"), "{out}");
    }

    #[test]
    fn an_unknown_method_gets_an_error_rather_than_silence() {
        let mut out = Vec::new();
        reply(
            &mut out,
            &json!(3),
            Err((-32601, "no method named resources/list".into())),
        )
        .unwrap();
        let sent: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(sent["id"], 3);
        assert_eq!(sent["error"]["code"], -32601);
    }

    #[test]
    fn an_empty_secret_does_not_blank_the_output() {
        assert_eq!(redact("hello", ""), "hello");
    }

    #[test]
    fn the_tool_list_offers_no_way_to_read_a_value() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store {
            dir: tmp.path().to_path_buf(),
        };
        let listed = tools(&store);
        let names: Vec<&str> = listed["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["list_secrets", "run_with_secret"]);
    }

    #[test]
    fn an_installed_plugin_adds_its_tools_to_the_list() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store {
            dir: tmp.path().to_path_buf(),
        };
        let dir = store.plugins_dir().join("demo");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("plugin.toml"),
            "name = \"demo\"\ndescription = \"x\"\n\n\
             [[tool]]\nname = \"say\"\nmode = \"open\"\nparams = [\"msg\", \"extra?\"]\n\
             run = [\"printf\", \"{msg}\"]\n",
        )
        .unwrap();

        let listed = tools(&store);
        let say = listed["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == "demo.say")
            .expect("demo.say listed");
        assert_eq!(say["inputSchema"]["required"], json!(["msg"]));
        assert!(say["inputSchema"]["properties"]["extra"].is_object());
    }

    #[test]
    fn initialize_echoes_the_version_the_client_asked_for() {
        let reply = initialize(&json!({"protocolVersion": "2024-11-05"}));
        assert_eq!(reply["protocolVersion"], "2024-11-05");
        assert_eq!(reply["serverInfo"]["name"], "passbox");
    }
}
