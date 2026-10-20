/**
 * A menu-bar app with a search panel over the secret names, opened by ⌘⇧Space. It talks to
 * passbox only through the CLI, `passbox ls` for the names and `passbox copy` for the clipboard.
 * A value goes broker to CLI to the Swift helper to the pasteboard and never enters this process,
 * so the clipboard rules stay in `passbox copy` alone. The names stay in memory for the session,
 * so one listing prompt covers every search until ⌘R or quit
 **/

import AppKit
import Carbon.HIToolbox
import Search
import ServiceManagement
import SwiftUI

// An app launched from Finder gets a minimal PATH, so look where Homebrew installs it
let passbox =
    ProcessInfo.processInfo.environment["PASSBOX"]
    ?? ["/opt/homebrew/bin/passbox", "/usr/local/bin/passbox"].first {
        FileManager.default.isExecutableFile(atPath: $0)
    } ?? "passbox"

/// Runs passbox off the main thread. The Touch ID prompt comes from the broker, not from here
func run(_ args: [String]) async -> (ok: Bool, out: String, err: String) {
    await Task.detached {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: passbox)
        process.arguments = args
        var env = ProcessInfo.processInfo.environment
        env["PASSBOX_AGENT"] = "passbox-app"
        process.environment = env
        let out = Pipe()
        let err = Pipe()
        process.standardOutput = out
        process.standardError = err
        do {
            try process.run()
        } catch {
            return (false, "", "could not run \(passbox): \(error.localizedDescription)")
        }

        let stdout = out.fileHandleForReading.readDataToEndOfFile()
        let stderr = err.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (
            process.terminationStatus == 0, String(decoding: stdout, as: UTF8.self),
            String(decoding: stderr, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        )
    }.value
}

@MainActor
final class Model: ObservableObject {
    @Published var names: [String] = []
    @Published var query = "" {
        didSet { selected = 0 }
    }
    @Published var selected = 0
    @Published var status = ""
    @Published var busy = false
    var done: () -> Void = {}

    var matches: [String] { search(names, for: query) }

    func reload() {
        guard !busy else {
            return
        }

        busy = true
        status = "Listing, touch the sensor"
        Task {
            let result = await run(["ls"])
            busy = false
            if result.ok {
                names = result.out.split(separator: "\n").map(String.init)
                status = ""
            } else {
                status = result.err
            }
        }
    }

    func move(_ by: Int) {
        let count = matches.count
        guard count > 0 else {
            return
        }

        selected = (selected + by + count) % count
    }

    func copy(field: String?) {
        let list = matches
        guard !busy, list.indices.contains(selected) else {
            return
        }

        let name = list[selected]
        busy = true
        status = "Copying \(name), touch the sensor"
        Task {
            let result = await run(["copy", name] + (field.map { ["--field", $0] } ?? []))
            busy = false
            if result.ok {
                status = ""
                done()
            } else {
                status = result.err
            }
        }
    }
}

struct SearchView: View {
    @ObservedObject var model: Model
    @FocusState private var focused: Bool

    var body: some View {
        VStack(spacing: 0) {
            TextField("Search secrets", text: $model.query)
                .textFieldStyle(.plain)
                .font(.title2)
                .padding(14)
                .focused($focused)
            Divider()
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(Array(model.matches.enumerated()), id: \.element) { index, name in
                            Text(name)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(.horizontal, 14)
                                .padding(.vertical, 6)
                                .background(index == model.selected ? Color.accentColor.opacity(0.3) : .clear)
                                .contentShape(Rectangle())
                                .id(index)
                                .onTapGesture(count: 2) { model.copy(field: nil) }
                                .onTapGesture { model.selected = index }
                        }
                    }
                }
                .onChange(of: model.selected) { proxy.scrollTo(model.selected) }
            }
            Divider()
            Text(model.status.isEmpty ? "⏎ password   ⌘⏎ username   ⌘R reload   esc close" : model.status)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(10)
        }
        .frame(width: 560, height: 380)
        .onAppear { focused = true }
    }
}

final class Panel: NSPanel {
    override var canBecomeKey: Bool { true }
}

@MainActor
final class Controller: NSObject, NSApplicationDelegate {
    let model = Model()
    let panel = Panel(
        contentRect: .zero, styleMask: [.titled, .fullSizeContentView], backing: .buffered,
        defer: false)
    var item: NSStatusItem?

    func applicationDidFinishLaunching(_ note: Notification) {
        panel.titleVisibility = .hidden
        panel.titlebarAppearsTransparent = true
        panel.isMovableByWindowBackground = true
        panel.level = .floating
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        // The Touch ID prompt takes focus, and a panel that hid then would close under the user
        panel.hidesOnDeactivate = false
        model.done = { [weak self] in self?.hide() }

        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        item.button?.image = NSImage(systemSymbolName: "key.fill", accessibilityDescription: "passbox")
        let menu = NSMenu()
        menu.addItem(withTitle: "Search  ⌘⇧Space", action: #selector(show), keyEquivalent: "")
        menu.addItem(withTitle: "Reload names", action: #selector(reload), keyEquivalent: "")
        let login = menu.addItem(withTitle: "Launch at login", action: #selector(toggleLogin), keyEquivalent: "")
        login.state = SMAppService.mainApp.status == .enabled ? .on : .off
        menu.addItem(.separator())
        menu.addItem(withTitle: "Quit", action: #selector(NSApplication.terminate), keyEquivalent: "q")
        item.menu = menu
        self.item = item

        NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] event in
            guard let self, self.panel.isKeyWindow else {
                return event
            }

            return self.key(event) ? nil : event
        }
        NotificationCenter.default.addObserver(
            forName: NSApplication.didResignActiveNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                if self?.model.busy == false {
                    self?.hide()
                }
            }
        }
        registerHotKey()
    }

    /// True when the panel handled the key, so the search field never sees it
    func key(_ event: NSEvent) -> Bool {
        let command = event.modifierFlags.contains(.command)
        switch Int(event.keyCode) {
        case kVK_Return, kVK_ANSI_KeypadEnter:
            model.copy(field: command ? "username" : nil)
        case kVK_Escape:
            hide()
        case kVK_DownArrow:
            model.move(1)
        case kVK_UpArrow:
            model.move(-1)
        case kVK_ANSI_R where command:
            model.reload()
        default:
            return false
        }

        return true
    }

    @objc func show() {
        model.query = ""
        model.status = ""
        // A fresh view each time, so onAppear puts the cursor back in the search field
        panel.contentView = NSHostingView(rootView: SearchView(model: model))
        panel.center()
        NSApp.activate()
        panel.makeKeyAndOrderFront(nil)
        if model.names.isEmpty {
            model.reload()
        }
    }

    /// Hiding the app hands focus back to the app it came from, so ⌘V pastes there
    func hide() {
        panel.orderOut(nil)
        NSApp.hide(nil)
    }

    func toggle() {
        if panel.isVisible {
            hide()
        } else {
            show()
        }
    }

    @objc func reload() {
        show()
        model.reload()
    }

    @objc func toggleLogin(_ sender: NSMenuItem) {
        do {
            if SMAppService.mainApp.status == .enabled {
                try SMAppService.mainApp.unregister()
            } else {
                try SMAppService.mainApp.register()
            }
        } catch {
            NSAlert(error: error).runModal()
        }

        sender.state = SMAppService.mainApp.status == .enabled ? .on : .off
    }

    // RegisterEventHotKey needs no Accessibility permission, unlike a global event monitor
    func registerHotKey() {
        var spec = EventTypeSpec(eventClass: OSType(kEventClassKeyboard), eventKind: UInt32(kEventHotKeyPressed))
        InstallEventHandler(
            GetApplicationEventTarget(),
            { _, _, _ in
                DispatchQueue.main.async { MainActor.assumeIsolated { controller.toggle() } }
                return noErr
            }, 1, &spec, nil, nil)
        var ref: EventHotKeyRef?
        let id = EventHotKeyID(signature: OSType(0x7062_6170), id: 1)
        RegisterEventHotKey(
            UInt32(kVK_Space), UInt32(cmdKey | shiftKey), id, GetApplicationEventTarget(), 0, &ref)
    }
}

let app = NSApplication.shared
let controller = MainActor.assumeIsolated { Controller() }
app.delegate = controller
app.setActivationPolicy(.accessory)
app.run()
