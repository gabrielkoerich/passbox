"""Read secrets from passbox, and hand one to a child process without holding it.

Nothing here is passbox-specific beyond the command names. It shells out to the CLI,
so there is no library to install and no key material in this process.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

# A read can raise a Touch ID prompt, so this has to cover a human reaching for the
# sensor rather than just a subprocess. The broker gives up well before it.
READ_TIMEOUT = 120

# passbox caps a grant at 24 hours and refuses more, so ask for the ceiling. A shorter one
# only means another prompt sooner, and nobody is at the sensor at 3am.
GRANT_SECS = 86_400


class Passbox:
    """Paths are entry names, such as "github/token".

    `namespace` is prepended to every lookup, so callers ask for "token" and get
    "github/token" without the layout leaking into call sites.

    `agent` is the name the Touch ID prompt shows beside the secret. Set it to
    something a human will recognise when the prompt appears.
    """

    def __init__(
        self,
        namespace: str | None = None,
        agent: str | None = None,
        grant: list[str] | None = None,
        grant_secs: int = GRANT_SECS,
    ) -> None:
        self.namespace = namespace
        self.agent = agent
        self.grant = grant
        self.grant_secs = grant_secs
        self._token: str | None = None

    def _token_for(self) -> str | None:
        """One approval for everything this process reads, rather than one per secret.

        An inherited PASSBOX_TOKEN wins, which is how a daemon hands one to the jobs it
        spawns. A grant that fails falls back to prompting rather than stopping the job.

        Mint once and keep it. Build a fresh client per call and you mint a fresh grant per
        call, which is a fingerprint per read.
        """
        inherited = os.environ.get("PASSBOX_TOKEN")
        if inherited:
            return inherited
        if self._token or not self.grant:
            return self._token
        names = [self._name(n) for n in self.grant]
        try:
            done = subprocess.run(
                ["passbox", "grant", *names, "--for", str(self.grant_secs)],
                capture_output=True,
                text=True,
                check=True,
                timeout=READ_TIMEOUT,
            )
        except (subprocess.SubprocessError, OSError):
            return None
        self._token = done.stdout.strip() or None
        return self._token

    def _name(self, path: str) -> str:
        return f"{self.namespace}/{path}" if self.namespace else path

    def get(self, path: str) -> str:
        """The whole value. For a multi-line entry this includes the fields."""
        return self._run(["passbox", "get", self._name(path)])

    def get_fields(self, path: str) -> dict[str, str]:
        """First line as "password", then any "key: value" lines below it.

        This is the layout `pass` uses, which passbox keeps on import.
        """
        lines = self.get(path).strip().splitlines()
        if not lines:
            return {}
        fields = {"password": lines[0]}
        for line in lines[1:]:
            key, sep, value = line.partition(":")
            if sep and key.strip() and value.strip():
                fields[key.strip().lower()] = value.strip()
        return fields

    def run_with(self, env_var: str, path: str, command: list[str]) -> subprocess.CompletedProcess[str]:
        """Run a command with the secret in its environment, never in this process.

        Prefer this over get(). The value goes from the broker into the child, so a
        crash dump or a traceback here cannot contain it.
        """
        return subprocess.run(
            ["passbox", "exec", "--env", f"{env_var}={self._name(path)}", "--", *command],
            capture_output=True,
            text=True,
            timeout=READ_TIMEOUT,
            env=self._env(),
        )

    def is_available(self) -> bool:
        """Whether passbox can be used, without reading anything.

        Deliberately not `passbox ls`, which decrypts every entry to learn the names
        and so raises a Touch ID prompt each time anything asks.
        """
        store = Path(os.environ.get("PASSBOX_DIR") or Path.home() / ".passbox")
        if not (store / "wraps").is_dir():
            return False
        try:
            subprocess.run(["passbox", "--version"], capture_output=True, check=True, timeout=8)
            return True
        except (subprocess.SubprocessError, OSError):
            return False

    def _env(self) -> dict[str, str]:
        env = os.environ.copy()
        if self.agent:
            env["PASSBOX_AGENT"] = self.agent
        token = self._token_for()
        if token:
            env["PASSBOX_TOKEN"] = token
        return env

    def _run(self, cmd: list[str]) -> str:
        done = subprocess.run(
            cmd, capture_output=True, text=True, check=True, timeout=READ_TIMEOUT, env=self._env()
        )
        return done.stdout


def _self_check() -> None:
    """Round-trip against a throwaway store, so it needs no hardware and no prompt."""
    import tempfile

    with tempfile.TemporaryDirectory() as store:
        env = {
            **os.environ,
            "PASSBOX_DIR": store,
            "PASSBOX_PASSPHRASE": "correct horse battery staple",
        }
        subprocess.run(["passbox", "init"], env=env, capture_output=True, check=True)
        subprocess.run(
            ["passbox", "add", "demo/api"],
            env=env,
            input="s3cret\nusername: bot\nhost: example.com",
            text=True,
            capture_output=True,
            check=True,
        )

        os.environ["PASSBOX_DIR"] = store
        os.environ["PASSBOX_PASSPHRASE"] = "correct horse battery staple"
        box = Passbox(namespace="demo", agent="self-check", grant=["api"])

        assert box.is_available()
        assert box.get("api").splitlines()[0] == "s3cret"
        assert box.get_fields("api") == {
            "password": "s3cret",
            "username": "bot",
            "host": "example.com",
        }
        done = box.run_with("API_KEY", "api", ["sh", "-c", "test -n \"$API_KEY\" && echo ok"])
        assert done.stdout.strip() == "ok", done.stderr
        print("all checks passed")


if __name__ == "__main__":
    _self_check()
