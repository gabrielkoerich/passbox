# Python

`passbox.py` is a small client over the CLI. There is no library to install, and no
key material in the Python process.

```python
from passbox import Passbox

box = Passbox(namespace="github", agent="deploy-script")

# Hand the secret to a child, never to this process. Prefer this.
box.run_with("GITHUB_TOKEN", "token", ["gh", "api", "/user"])

# Or read it, when a library needs the value in-process
token = box.get("token")
fields = box.get_fields("api")     # {"password": ..., "username": ..., ...}
```

Run `python3 passbox.py` to check it against a throwaway store. It needs no hardware
and raises no prompt, because it sets `PASSBOX_PASSPHRASE`.

## Two things worth copying

**Prefer `run_with` over `get`.** The value goes from the broker into the child
process, so a traceback or a crash dump in your own process cannot carry it.

**Do not use `passbox ls` as an availability check.** `ls` decrypts every entry to
learn the names, so it raises a Touch ID prompt every time it runs. `is_available()`
checks for the binary and the store directory instead.

## The agent name

`agent` sets `PASSBOX_AGENT`, which is what the prompt shows beside the secret name.
The caller declares it, so it is not proof of anything, and the broker records the
real process ancestry in the audit log. Set it so the prompt is readable, not as a
security measure.
