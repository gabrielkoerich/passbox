"""Talk to passbox through MCP, the way an agent's client does.

An agent in Claude Code, Codex or Cursor never runs this file: the client speaks the protocol for
it. This is that conversation written out, for a harness of your own or to see exactly what the
model gets back. No SDK: MCP over stdio is newline-delimited JSON-RPC.
"""

from __future__ import annotations

import json
import os
import subprocess

PROTOCOL = "2025-06-18"


class PassboxMCP:
    """One `passbox mcp` server, started on first use and kept for the life of this object.

    `agent` goes in the handshake as `clientInfo.name`, and the Touch ID prompt shows it beside
    the secret. Keep one instance per process: each new server is a new conversation, and a
    window approved by one does not carry to an agent with a different name.

    `env` is the server's environment. Put `PASSBOX_TOKEN` there, not in your shell, when a grant
    should cover the reads.
    """

    def __init__(self, agent: str = "passbox-mcp-example", env: dict[str, str] | None = None) -> None:
        self.agent = agent
        self.env = env
        self._server: subprocess.Popen[str] | None = None
        self._next_id = 0

    def list_secrets(self) -> list[str]:
        """Names only. There is no tool that returns a value."""
        text = self._call("list_secrets", {})
        return [] if text == "no secrets yet" else text.splitlines()

    def run_with_secret(self, secret: str, command: list[str], env_var: str | None = None) -> str:
        """The command's output, with the value scrubbed out. Without `env_var` it goes on stdin."""
        arguments: dict[str, object] = {"secret": secret, "command": command}
        if env_var:
            arguments["env_var"] = env_var
        return self._call("run_with_secret", arguments)

    def close(self) -> None:
        if self._server:
            self._server.stdin.close()
            self._server.wait(timeout=5)
            self._server = None

    def __enter__(self) -> PassboxMCP:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _call(self, tool: str, arguments: dict[str, object]) -> str:
        result = self._request("tools/call", {"name": tool, "arguments": arguments})
        text = result["content"][0]["text"]
        # A refusal is a result rather than a protocol error, so the model can read why
        if result.get("isError"):
            raise RuntimeError(text)
        return text

    def _request(self, method: str, params: dict[str, object]) -> dict:
        if self._server is None:
            self._start()
        self._next_id += 1
        self._send({"jsonrpc": "2.0", "id": self._next_id, "method": method, "params": params})
        reply = json.loads(self._server.stdout.readline())
        if "error" in reply:
            raise RuntimeError(reply["error"]["message"])
        return reply["result"]

    def _start(self) -> None:
        self._server = subprocess.Popen(
            ["passbox", "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            env={**os.environ, **(self.env or {})}, text=True,
        )
        self._next_id += 1
        self._send({"jsonrpc": "2.0", "id": self._next_id, "method": "initialize", "params": {
            "protocolVersion": PROTOCOL, "capabilities": {},
            "clientInfo": {"name": self.agent, "version": "1"},
        }})
        json.loads(self._server.stdout.readline())
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _send(self, message: dict) -> None:
        self._server.stdin.write(json.dumps(message) + "\n")
        self._server.stdin.flush()


def _self_check() -> None:
    """Round trip against a throwaway store, so it needs no hardware and raises no prompt."""
    import shutil
    import tempfile

    store = tempfile.mkdtemp(prefix="passbox-mcp-")
    # A passphrase turns the Enclave path off, which is what makes this run without a finger
    env = {"PASSBOX_DIR": store, "PASSBOX_PASSPHRASE": "correct horse battery staple"}
    full = {**os.environ, **env}
    try:
        subprocess.run(["passbox", "init"], env=full, check=True, capture_output=True)
        subprocess.run(["passbox", "add", "demo/api"], input=b"s3cret\nusername: bot",
                       env=full, check=True, capture_output=True)

        with PassboxMCP(env=env) as mcp:
            assert mcp.list_secrets() == ["demo/api"]

            out = mcp.run_with_secret("demo/api", ["sh", "-c", 'test -n "$API_KEY" && echo ok'], "API_KEY")
            assert out.strip() == "ok", out

            # Whatever the command prints, the value is scrubbed before it reaches the model
            for script in ['printf "%s" "$API_KEY"', 'printf "%s" "$API_KEY" | head -n 1']:
                out = mcp.run_with_secret("demo/api", ["sh", "-c", script], "API_KEY")
                assert "s3cret" not in out and "[redacted by passbox]" in out, out

            # Without env_var the value arrives on stdin
            out = mcp.run_with_secret("demo/api", ["sh", "-c", 'read -r v && test -n "$v" && echo ok'])
            assert out.strip() == "ok", out

            try:
                mcp.run_with_secret("demo/missing", ["true"])
                raise AssertionError("a missing secret should be refused")
            except RuntimeError as e:
                assert "no secret named demo/missing" in str(e), e
    finally:
        shutil.rmtree(store, ignore_errors=True)
    print("all checks passed")


if __name__ == "__main__":
    _self_check()
