# Python

`passbox.py` is a small client over the CLI. There is no library to install, and no key material in the Python process.

```python
from passbox import Passbox

box = Passbox(namespace="github", agent="deploy-script")

# Hand the secret to a child, never to this process
box.run_with("GITHUB_TOKEN", "token", ["gh", "api", "/user"])
```

A script that needs the value itself runs under `passbox exec --env GITHUB_TOKEN=github/token -- python3 script.py` and reads `os.environ`.

Run `python3 passbox.py` to check it against a throwaway store. It needs no hardware and raises no prompt, because it sets `PASSBOX_PASSPHRASE`.

## Two things worth copying

**Inject, do not read.** `run_with` sends the value from the broker into the child process, so a traceback or a crash dump in your own process cannot carry it.

**Do not use `passbox ls` as an availability check.** `ls` decrypts every entry to learn the names, so it raises a Touch ID prompt every time it runs. `is_available()` checks for the binary and the store directory instead.

## The agent name

`agent` sets `PASSBOX_AGENT`, which is what the prompt shows beside the secret name. The caller declares it, so it proves nothing. The broker records the real process ancestry in the audit log. Set it to make the prompt readable. It is not a security measure.
