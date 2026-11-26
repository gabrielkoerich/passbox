# Alfred

Type `pbx` and press `⏎`, touch the sensor, then pick a secret in the box that reopens. `⌘⏎` copies its password, the first line of an entry with fields. `⏎` lists its fields, masked, in another box, and `⏎` on one copies that field alone. A note has no fields, so its box holds one `note` row that copies the whole text, and `⌘⏎` on a note says it has no password instead of copying its first line. `passbox copy` writes the value as a concealed, transient clipboard item and clears it after 20 seconds, so it never reaches Alfred or clipboard history. It needs the Alfred Powerpack.

## Install

Every release attaches the workflow, and this link always serves the newest one:

```bash
curl -fsSLO https://github.com/gabrielkoerich/passbox/releases/latest/download/passbox.alfredworkflow
open passbox.alfredworkflow
```

Or download it from the [latest release](https://github.com/gabrielkoerich/passbox/releases/latest) and double-click it. Alfred imports it, and installing a newer one replaces the old. From a checkout, `./build.sh dev passbox.alfredworkflow` builds the same file. To open it with a hotkey, such as `⌘⇧C`, add a Hotkey trigger in the workflow and connect it to the `list.sh` Run Script, which skips typing the keyword.

`pbx` rather than `pb`, because Alfred's app search matches `pb` to Photo Booth and ranks whichever you picked last first.

## Prompts

| Action | Prompt |
|---|---|
| `pbx` and `⏎`, which lists the names | "list your secret names for alfred" |
| `⌘⏎` on a name, or `⏎` on a field | "release the password for NAME to alfred" |
| `⏎` on a name, which lists its fields | "list the fields of NAME for alfred" |

So one use is two fingerprints. The Touch ID prompt takes focus, and Alfred hides when it loses focus, so `pbx` lists the names while Alfred is closed and then reopens it with them. You type the name into the box that reopens, not after `pbx`. The names reach the reopened box as a workflow variable, so they never touch disk.

Picking a field is three fingerprints: the names, the fields and the copy. `passbox fields` returns field names and never a value, so the reopened box, Alfred's debugger log and the Script Filter's output hold names only. The value goes from the broker to the clipboard as a concealed, transient item, as a copy of the password does.

Rejected: listing inside the Script Filter. The prompt closes Alfred before the names arrive, and typing `pbx` again asks again.

## Files

| File | Does |
|---|---|
| `list.sh` | Runs `passbox ls` behind the `pbx` keyword and passes the names, or the error, on as variables |
| `filter.sh` | Turns the names into Alfred's JSON for the reopened box. A refused listing shows as an item with the error |
| `build.sh` | Packs the scripts, `info.plist` and `icon.png` into `passbox.alfredworkflow`, stamped with a version. CI and the release use it |
| `fields.sh` | Runs `passbox fields NAME` while Alfred is closed and passes the field names, or the error, on as variables |
| `pick.sh` | Turns the field names into one masked item each for the box that reopens, or one `note` item when there are none |
| `copy.sh` | Runs `passbox copy NAME --field FIELD`, the picked field or `password`, or `passbox copy NAME` for a note |
| `icon.svg` | The workflow icon. `rsvg-convert -w 512 icon.svg -o icon.png` renders the `icon.png` that Alfred and the Alfred Gallery show |
| `info.plist` | The workflow: the `pbx` keyword, the listing, two External Triggers that reopen Alfred on the names and on one name's fields, the copy script and a notification with the result |

Both scripts call `/opt/homebrew/bin/passbox`, since Alfred runs them with a minimal `PATH`. Set the `PASSBOX` workflow variable to use another path.
