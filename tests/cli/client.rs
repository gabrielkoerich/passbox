//! A client machine that asks a host, the tokens it holds, and MCP.

use super::*;

/// The Mac's broker as a client with `PASSBOX_HOST` reaches it, on loopback. Each connection is one
/// request, answered by `answer` and handed back so a test can check what the client asked for
fn fake_host(
    answer: impl Fn(&serde_json::Value) -> Result<String, String> + Send + 'static,
) -> (String, std::sync::mpsc::Receiver<serde_json::Value>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (seen, requests) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut line = String::new();
            std::io::BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let request: serde_json::Value = serde_json::from_str(&line).unwrap();
            let response = match answer(&request) {
                Ok(value) => serde_json::json!({ "ok": true, "value": value, "error": null }),
                Err(error) => serde_json::json!({ "ok": false, "value": null, "error": error }),
            };
            seen.send(request).unwrap();
            writeln!(stream, "{response}").unwrap();
        }
    });
    (addr, requests)
}

/// A client run with a configured host, and with or without a token already held
fn on_host(cli: &Cli, host: &str, token: Option<&str>, args: &[&str]) -> (bool, String, String) {
    let mut cmd = cli.cmd(PASSPHRASE);
    cmd.env("PASSBOX_HOST", host).env_remove("PASSBOX_TOKEN");
    if let Some(token) = token {
        cmd.env("PASSBOX_TOKEN", token);
    }
    let out = cmd.args(args).output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn ops(requests: &std::sync::mpsc::Receiver<serde_json::Value>) -> Vec<serde_json::Value> {
    requests.try_iter().collect()
}

#[test]
fn grant_on_a_client_goes_to_the_host_and_keeps_the_token_off_stderr() {
    let cli = Cli::empty();
    let (host, requests) = fake_host(|_| Ok("tok-7f3a\na/b\nc/d".into()));
    let (ok, stdout, stderr) = on_host(&cli, &host, None, &["grant", "a/b", "c/d"]);

    assert!(ok, "{stderr}");
    assert_eq!(stdout, "tok-7f3a\n");
    // stderr lands in scrollback, CI logs and agent transcripts, so the token must not be there
    assert!(
        !stderr.contains("tok-7f3a"),
        "the token leaked to stderr: {stderr}"
    );
    assert!(stderr.contains("a/b") && stderr.contains("c/d"), "{stderr}");

    let seen = ops(&requests);
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0]["op"], "grant");
    assert_eq!(seen[0]["names"], serde_json::json!(["a/b", "c/d"]));
}

/// A client run with a configured host and the given stdin, for `--token-stdin`
fn on_host_stdin(cli: &Cli, host: &str, stdin: &str, args: &[&str]) -> (bool, String, String) {
    let mut cmd = cli.cmd(PASSPHRASE);
    cmd.env("PASSBOX_HOST", host).env_remove("PASSBOX_TOKEN");
    let mut child = cmd
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn a_token_on_stdin_asks_for_a_child_and_leaves_the_rest_to_the_exec_child() {
    let cli = Cli::empty();
    let (host, requests) = fake_host(|r| match r["op"].as_str() {
        Some("grant") if r["token"] == "parent-tok" => Ok("child-tok\na/b".into()),
        Some("get") if r["token"] == "child-tok" => Ok("v".into()),
        _ => Err("a request without the token from stdin".into()),
    });

    let (ok, stdout, stderr) = on_host_stdin(
        &cli,
        &host,
        "parent-tok\n",
        &["grant", "--token-stdin", "a/b"],
    );
    assert!(ok, "{stderr}");
    assert_eq!(stdout, "child-tok\n");
    assert!(
        !stderr.contains("parent-tok") && !stderr.contains("child-tok"),
        "a token leaked to stderr: {stderr}"
    );
    let seen = ops(&requests);
    // No --for asks for the parent's expiry
    assert_eq!(seen[0]["ttl"], 0);

    let args = [
        "exec",
        "--token-stdin",
        "--env",
        "A=a/b",
        "--",
        "sh",
        "-c",
        "printf %s, \"$A\"; cat",
    ];
    let (ok, stdout, stderr) = on_host_stdin(&cli, &host, "child-tok\nrest", &args);
    assert!(ok, "{stderr}");
    assert_eq!(stdout, "v,rest");
    assert!(
        !stderr.contains("child-tok"),
        "the token leaked to stderr: {stderr}"
    );
    let kinds: Vec<String> = ops(&requests)
        .iter()
        .map(|r| r["op"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(kinds, ["get"]);
}

#[test]
fn a_token_on_stdin_needs_a_first_line_and_no_newline_after_it() {
    let cli = Cli::empty();
    let (host, requests) = fake_host(|r| match r["token"].as_str() {
        Some("parent-tok") => Ok("child-tok\na/b".into()),
        _ => Err("a request without the token from stdin".into()),
    });
    let grant = ["grant", "--token-stdin", "a/b"];
    let exec = ["exec", "--token-stdin", "--env", "A=a/b", "--", "true"];

    // EOF, an empty first line or a blank one is refused before the host is asked
    for stdin in ["", "\n", "\nparent-tok\n", "  \n"] {
        for args in [&grant[..], &exec[..]] {
            let (ok, _, stderr) = on_host_stdin(&cli, &host, stdin, args);
            assert!(!ok, "{stdin:?} {args:?}");
            assert!(stderr.contains("--token-stdin read no token"), "{stderr}");
        }
    }
    assert_eq!(ops(&requests), Vec::<serde_json::Value>::new());

    let (ok, stdout, stderr) = on_host_stdin(&cli, &host, "parent-tok", &grant);
    assert!(ok, "{stderr}");
    assert_eq!(stdout, "child-tok\n");
    assert_eq!(ops(&requests)[0]["token"], "parent-tok");
}

#[test]
fn exec_with_many_secrets_asks_the_host_once() {
    let cli = Cli::empty();
    let (host, requests) = fake_host(|r| match r["op"].as_str() {
        Some("grant") => Ok("tok-1\na/b\nc/d".into()),
        Some("get") if r["token"] == "tok-1" => Ok(format!("v-{}", r["name"].as_str().unwrap())),
        _ => Err("a read without the batch token".into()),
    });
    let script = "printf %s, \"$A\"; cat";
    let args = [
        "exec", "--env", "A=a/b", "--stdin", "c/d", "--", "sh", "-c", script,
    ];
    let (ok, stdout, stderr) = on_host(&cli, &host, None, &args);

    assert!(ok, "{stderr}");
    assert_eq!(stdout, "v-a/b,v-c/d");
    let seen = ops(&requests);
    let kinds: Vec<&str> = seen.iter().map(|r| r["op"].as_str().unwrap()).collect();
    assert_eq!(kinds, ["grant", "get", "get"]);
    // A short token, so it is useless once the batch is read
    assert_eq!(seen[0]["ttl"], 30);
}

#[test]
fn exec_reads_one_by_one_when_the_grant_is_refused() {
    let cli = Cli::empty();
    let (host, requests) = fake_host(|r| match r["op"].as_str() {
        Some("grant") => Err("denied".into()),
        Some("get") if r["token"] == "" => Ok(format!("v-{}", r["name"].as_str().unwrap())),
        _ => Err("unexpected request".into()),
    });
    let args = [
        "exec",
        "--env",
        "A=a/b",
        "--env",
        "B=c/d",
        "--",
        "sh",
        "-c",
        "printf %s,%s \"$A\" \"$B\"",
    ];
    let (ok, stdout, stderr) = on_host(&cli, &host, None, &args);

    assert!(ok, "{stderr}");
    assert_eq!(stdout, "v-a/b,v-c/d");
    let kinds: Vec<String> = ops(&requests)
        .iter()
        .map(|r| r["op"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(kinds, ["grant", "get", "get"]);
}

#[test]
fn exec_with_one_secret_or_a_held_token_mints_no_grant() {
    let cli = Cli::empty();
    let (host, requests) = fake_host(|r| Ok(format!("v-{}", r["name"].as_str().unwrap())));

    let one = [
        "exec",
        "--env",
        "A=a/b",
        "--",
        "sh",
        "-c",
        "printf %s \"$A\"",
    ];
    let (ok, stdout, stderr) = on_host(&cli, &host, None, &one);
    assert!(ok, "{stderr}");
    assert_eq!(stdout, "v-a/b");
    let seen = ops(&requests);
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0]["op"], "get");

    let two = ["exec", "--env", "A=a/b", "--env", "B=c/d", "--", "true"];
    let (ok, _, stderr) = on_host(&cli, &host, Some("held"), &two);
    assert!(ok, "{stderr}");
    let seen = ops(&requests);
    assert_eq!(seen.len(), 2);
    assert!(
        seen.iter()
            .all(|r| r["op"] == "get" && r["token"] == "held"),
        "{seen:?}"
    );
}

/// Prints the two credential variables as the child sees them, so an empty pair means it got neither
const SHOW_CREDENTIALS: &str = "printf '[%s][%s]' \"$PASSBOX_TOKEN\" \"$PASSBOX_PASSPHRASE\"";

fn with_token(cli: &Cli, args: &[&str]) -> std::process::Output {
    cli.cmd(PASSPHRASE)
        .env("PASSBOX_TOKEN", "tok-leak")
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn exec_children_never_see_the_token_or_the_passphrase() {
    let cli = Cli::new();
    cli.run(&["add", "a/b"], Some("v")).unwrap();

    let out = with_token(
        &cli,
        &["exec", "--env", "A=a/b", "--", "sh", "-c", SHOW_CREDENTIALS],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "[][]");

    // Asking for a secret under that name on purpose still works
    let out = with_token(
        &cli,
        &[
            "exec",
            "--env",
            "PASSBOX_TOKEN=a/b",
            "--",
            "sh",
            "-c",
            SHOW_CREDENTIALS,
        ],
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "[v][]");
}

#[test]
fn passbox_wipes_the_credentials_from_its_own_environment() {
    let cli = Cli::new();
    cli.run(&["add", "a/b"], Some("v")).unwrap();

    // The child reads its parent's environment the way any process running as the user can
    let out = with_token(
        &cli,
        &[
            "exec",
            "--env",
            "A=a/b",
            "--",
            "sh",
            "-c",
            "ps eww -o command= -p $PPID",
        ],
    );
    let seen = String::from_utf8_lossy(&out.stdout);
    assert!(
        seen.contains("PASSBOX_DIR="),
        "ps did not show the environment: {seen}"
    );
    assert!(
        !seen.contains("tok-leak"),
        "the token is still in the environment: {seen}"
    );
    assert!(
        !seen.contains(PASSPHRASE),
        "the passphrase is still in the environment: {seen}"
    );
}

#[test]
fn plugin_commands_never_see_the_token_or_the_passphrase() {
    let cli = Cli::new();
    let src = tempfile::tempdir().unwrap();
    let manifest = format!(
        "name = \"envcheck\"\ndescription = \"test\"\n\n[[tool]]\nname = \"show\"\nrun = [\"sh\", \"-c\", {}]\n",
        toml_string(SHOW_CREDENTIALS)
    );
    std::fs::write(src.path().join("plugin.toml"), manifest).unwrap();
    cli.note(&["plugin", "add", src.path().to_str().unwrap()], None);

    let out = with_token(&cli, &["plugin", "envcheck", "show"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "[][]");
}

#[test]
fn mcp_run_with_secret_never_hands_the_token_or_the_passphrase_to_the_agent() {
    let cli = Cli::new();
    cli.run(&["add", "a/b"], Some("v-secret")).unwrap();

    let script = format!("{SHOW_CREDENTIALS}; printf '[%s]' \"$S\"");
    let call = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "run_with_secret", "arguments": {
            "secret": "a/b", "env_var": "S", "command": ["sh", "-c", script]
        }}
    });
    let mut child = cli
        .cmd(PASSPHRASE)
        .env("PASSBOX_TOKEN", "tok-leak")
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{call}").unwrap();
    let out = child.wait_with_output().unwrap();
    let reply = String::from_utf8_lossy(&out.stdout);

    assert!(reply.contains("[][][[redacted by passbox]]"), "{reply}");
    assert!(
        !reply.contains("tok-leak"),
        "the token reached the agent: {reply}"
    );
    assert!(
        !reply.contains(PASSPHRASE),
        "the passphrase reached the agent: {reply}"
    );
}

/// One session as a client runs it: every request gets an answer, a notification gets none
#[test]
fn an_mcp_session_answers_every_request_and_lists_names_only() {
    let cli = Cli::new();
    cli.run(&["add", "a/b"], Some("v-secret")).unwrap();

    let session = [
        "not json".to_string(),
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "clientInfo": {"name": "test-agent"}
        }})
        .to_string(),
        serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string(),
        serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}).to_string(),
        serde_json::json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "list_secrets"}})
        .to_string(),
        serde_json::json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "nope"}})
        .to_string(),
        serde_json::json!({"jsonrpc": "2.0", "id": 5, "method": "bogus/method"}).to_string(),
        serde_json::json!({"jsonrpc": "2.0", "id": 6, "method": "ping"}).to_string(),
    ];
    let mut child = cli
        .cmd(PASSPHRASE)
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(child.stdin.take().unwrap(), "{}", session.join("\n")).unwrap();
    let out = child.wait_with_output().unwrap();
    let replies: Vec<serde_json::Value> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let by_id = |id: i64| {
        replies
            .iter()
            .find(|r| r["id"] == id)
            .unwrap_or_else(|| panic!("no reply to {id}: {replies:?}"))
    };

    assert_eq!(
        replies.len(),
        7,
        "the notification got a reply: {replies:?}"
    );
    assert_eq!(replies[0]["id"], serde_json::Value::Null);
    assert_eq!(replies[0]["error"]["code"], -32700);
    assert_eq!(by_id(1)["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(by_id(1)["result"]["serverInfo"]["name"], "passbox");

    let tools: Vec<&str> = by_id(2)["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(tools.contains(&"list_secrets"), "{tools:?}");
    assert!(tools.contains(&"run_with_secret"), "{tools:?}");
    assert!(
        !tools.iter().any(|t| t.contains("get")),
        "a tool can hand back a value: {tools:?}"
    );

    let listed = &by_id(3)["result"];
    assert_eq!(listed["content"][0]["text"], "a/b");
    assert!(
        !listed.to_string().contains("v-secret"),
        "a listing held a value: {listed}"
    );
    assert_eq!(by_id(4)["result"]["isError"], true);
    assert_eq!(by_id(5)["error"]["code"], -32601);
    assert_eq!(by_id(6)["result"], serde_json::json!({}));
}
