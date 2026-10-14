# Alfred

Type `pb`, pick a secret, and press `⏎` to copy its password or `⌘⏎` to copy its username. `passbox copy` writes the value as a concealed, transient clipboard item and clears it after 20 seconds, so it never reaches Alfred or clipboard history. Needs the Alfred Powerpack.

## Install

Every release attaches the workflow, and this link always serves the newest one:

```bash
curl -fsSLO https://github.com/gabrielkoerich/passbox/releases/latest/download/passbox.alfredworkflow
open passbox.alfredworkflow
```

Or download it from the [latest release](https://github.com/gabrielkoerich/passbox/releases/latest) and double-click it. Alfred imports it, and installing a newer one replaces the old. From a checkout, `./build.sh dev passbox.alfredworkflow` builds the same file. To open it with a hotkey, such as `⌘⇧C`, add a Hotkey trigger in the workflow and connect it to the `pb` Script Filter.

## Prompts

| Action | Prompt |
|---|---|
| `pb`, which lists the names | "list your secret names for alfred" |
| `⏎` or `⌘⏎` | "release the password for NAME to alfred" |

So one use is two fingerprints. Setting the workflow variable `cache_seconds` above 0, such as 300, makes Alfred reuse the list and refresh it in the background, so a use within that window is one fingerprint. The cost is that Alfred keeps the names in its cache folder, on disk and unencrypted. passbox otherwise never writes a name in the clear, so the default is 0.

## Files

| File | Does |
|---|---|
| `filter.sh` | Runs `passbox ls` once and prints Alfred's JSON. A refused listing shows as an item with the error |
| `build.sh` | Packs the three files into `passbox.alfredworkflow`, stamped with a version. CI and the release use it |
| `copy.sh` | Runs `passbox copy NAME`, with `--field username` on `⌘⏎` |
| `info.plist` | The workflow: the `pb` Script Filter, the copy script and a notification with the result |

Both scripts call `/opt/homebrew/bin/passbox`, since Alfred runs them with a minimal `PATH`. Set the `PASSBOX` workflow variable to use another path.
