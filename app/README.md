# Mac app

A menu-bar app for copying a credential quickly. Press `⌘⇧Space`, type part of a name, and press `⏎` to copy the password or `⌘⏎` to copy the username. `↑` and `↓` move the selection, `⌘R` lists the names again, and `esc` closes the panel. This is phase 1 of [#21](https://github.com/gabrielkoerich/passbox/issues/21). Notes and the Open view come later.

## Build and run

```bash
app/build.sh dev ~/Applications/passbox.app
open ~/Applications/passbox.app
```

It needs the Command Line Tools and macOS 14, not Xcode. `build.sh` runs `swift build`, wraps the binary in a bundle with `Info.plist`, and signs it ad hoc. A bundle built on the Mac carries no quarantine flag, so Gatekeeper lets it open. `Launch at login` in the menu registers it with `SMAppService`.

## Prompts

| Action | Prompt |
|---|---|
| The first open, or `⌘R` | "list your secret names for passbox-app" |
| `⏎` or `⌘⏎` | "release the password for NAME to passbox-app" |

The broker raises them, so the app needs no `LocalAuthentication` of its own. The names stay in memory until the app quits, so later opens ask nothing. They never touch disk.

## How it talks to passbox

Through the CLI: `passbox ls` for the names and `passbox copy NAME [--field username]` for the clipboard. A value goes broker to CLI to the Swift helper to the pasteboard and never enters the app, so the clipboard rules stay in one place: the concealed and transient types, the 20 second clear, and clearing only if the clipboard is unchanged.

Rejected: the broker socket. It would hand the value to the app, which would then need its own copy of the clipboard rules. The CLI costs a process spawn per action, which is fast enough for a keypress.

The app calls `/opt/homebrew/bin/passbox`, or `/usr/local/bin/passbox`, since an app opened from Finder gets a minimal `PATH`. Set `PASSBOX` to use another path when launching it from a shell.

## Files

| File | Does |
|---|---|
| `Sources/PassboxApp/main.swift` | The status item, the hotkey, the search panel and the calls to passbox |
| `Sources/Search/Search.swift` | The search filter, apart from AppKit so it can be checked headless |
| `Sources/SearchCheck/main.swift` | Checks the filter, `swift run SearchCheck`. CI runs it |
| `Info.plist` | The bundle. `LSUIElement` keeps it out of the Dock |
| `build.sh` | Builds and signs `passbox.app`, stamped with a version. CI runs it |
| `Package.swift` | The SwiftPM package |
