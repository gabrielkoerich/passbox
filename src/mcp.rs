/* An MCP server over stdio, exposing actions rather than values.

A `get_secret` tool would be the obvious shape and the wrong one: an MCP result lands in the
model's context, where it is logged, cached and sent onward. These tools run the command for the
agent and hand back only its output, so the value never enters the transcript. */

use crate::store::Store;
use crate::{agent_read_secret, run_child};
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
            continue;
        };
        let id = message.get("id").cloned();
        let method = message.get("method").and_then(Value::as_str).unwrap_or("");
        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));

        let reply = match method {
            "initialize" => {
                // The client names itself in the handshake, which beats guessing up the tree
                if let Some(name) = params
                    .pointer("/clientInfo/name")
                    .and_then(Value::as_str)
                    .filter(|n| !n.is_empty())
                {
                    agent = name.to_string();
                }
                Some(initialize(&params))
            }
            "tools/list" => Some(tools()),
            "tools/call" => Some(call(&store, &agent, &params)),
            "ping" => Some(json!({})),
            _ => None,
        };

        // A message with no id is a notification, which takes no reply
        let (Some(id), Some(result)) = (id, reply) else {
            continue;
        };
        writeln!(
            out,
            "{}",
            json!({"jsonrpc": "2.0", "id": id, "result": result})
        )?;
        out.flush()?;
    }
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

fn tools() -> Value {
    json!({ "tools": [
        {
            "name": "list_secrets",
            "description": "List the names of available secrets. Raises a Touch ID prompt unless \
                            one was already approved inside the window. Returns names only.",
            "inputSchema": { "type": "object", "properties": {} }
        },
        {
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
        }
    ]})
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
        other => Err(anyhow!("no tool named {other}")),
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
    Ok(redact(&text, &value))
}

/// A command that echoes its own secret would otherwise put it straight into the transcript
fn redact(text: &str, secret: &str) -> String {
    if secret.is_empty() {
        return text.to_string();
    }
    text.replace(secret, "[redacted by passbox]")
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
    fn an_empty_secret_does_not_blank_the_output() {
        assert_eq!(redact("hello", ""), "hello");
    }

    #[test]
    fn the_tool_list_offers_no_way_to_read_a_value() {
        let listed = tools();
        let names: Vec<&str> = listed["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["list_secrets", "run_with_secret"]);
    }

    #[test]
    fn initialize_echoes_the_version_the_client_asked_for() {
        let reply = initialize(&json!({"protocolVersion": "2024-11-05"}));
        assert_eq!(reply["protocolVersion"], "2024-11-05");
        assert_eq!(reply["serverInfo"]["name"], "passbox");
    }
}
