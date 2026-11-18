/**
 * Everything the two screens show. While the app is on screen it keeps one call open to the Mac,
 * which the Mac answers the moment a prompt needs the phone, so a request appears without the app
 * asking every second. Nothing runs in the background: iOS does not let an app listen there, and
 * the notification that would wake it is not built yet
 **/

import Foundation
import PassboxCore
import SwiftUI

@MainActor
final class Model: ObservableObject {
    /// Nil until a Mac is paired, which decides which of the two faces the screen shows
    @Published private(set) var pairing: Pairing?
    /// The request the Mac is waiting on
    @Published private(set) var request: Pending?
    /// Pairing, approving or refusing, so a button cannot be pressed twice
    @Published private(set) var busy = false
    /// The last thing that went wrong, in the Mac's words where it had any
    @Published private(set) var trouble: String?
    /// When the Mac last answered, and nil while it has not
    @Published private(set) var lastContact: Date?
    /// Set for a moment after an approval, so the screen can say so
    @Published private(set) var approved = false

    private var watcher: Task<Void, Never>?
    /// The request this phone last answered, which a poll already on its way may still carry
    private var answered: String?

    init() {
        pairing = Pairing.load()
    }

    var reachable: Bool { lastContact != nil && trouble == nil }

    private func client(_ pairing: Pairing) -> Client {
        Client(transport: Tailnet(host: pairing.host), token: pairing.token)
    }

    // MARK: Watching the Mac

    func start() {
        guard watcher == nil, let pairing else {
            return
        }
        let mac = client(pairing)
        watcher = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else {
                    return
                }
                await self.look(mac)
            }
        }
    }

    func stop() {
        watcher?.cancel()
        watcher = nil
    }

    /// One look at the Mac, held open until the waiting request differs from the one on screen,
    /// so a new request and the Mac answering one itself both show at once
    private func look(_ client: Client) async {
        do {
            let found = try await client.pending(wait: 25, seen: request?.id)
            lastContact = Date()
            trouble = nil
            if found?.id != request?.id, found == nil || found?.id != answered {
                request = found
            }
        } catch is CancellationError {
            return
        } catch {
            guard !Task.isCancelled else {
                return
            }
            trouble = error.localizedDescription
            try? await Task.sleep(for: .seconds(3))
        }
    }

    // MARK: Pairing

    /// The key is made first, since its public half is what the Mac wraps the store key to. The
    /// Mac then waits for a fingerprint, so this can take as long as its owner does
    func pair(host: String, code: String) async {
        let host = host.trimmingCharacters(in: .whitespacesAndNewlines)
        let code = code.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !host.isEmpty, !code.isEmpty, !busy else {
            return
        }
        busy = true
        trouble = nil
        defer { busy = false }
        do {
            let key = try PhoneKey.make()
            let enrolled = try await Client(transport: Tailnet(host: host))
                .enroll(code: code, publicKey: key.publicKey)
            let paired = Pairing(
                host: host, mac: enrolled.mac, phone: enrolled.phone, token: enrolled.token,
                keyBlob: key.blob, added: Date())
            try paired.save()
            pairing = paired
            // The Mac asks for one approval straight away, to prove the pairing
            start()
        } catch {
            trouble = error.localizedDescription
        }
    }

    /// The Mac keeps its wrap until `passbox phone rm`, and without this phone's key it is inert
    func forget() {
        stop()
        Pairing.forget()
        pairing = nil
        request = nil
        trouble = nil
        lastContact = nil
    }

    // MARK: Answering

    func approve() async {
        guard let pairing, let request, !busy else {
            return
        }
        busy = true
        defer { busy = false }
        do {
            let key = try await PhoneKey.open(
                blob: pairing.keyBlob, reason: "Approve the request from \(pairing.mac)")
            try await client(pairing).approve(request, with: key)
            answered = request.id
            self.request = nil
            trouble = nil
            approved = true
            try? await Task.sleep(for: .seconds(2))
            approved = false
        } catch {
            trouble = error.localizedDescription
        }
    }

    func deny() async {
        guard let pairing, let request, !busy else {
            return
        }
        busy = true
        defer { busy = false }
        do {
            try await client(pairing).deny(request)
            answered = request.id
            self.request = nil
            trouble = nil
        } catch {
            trouble = error.localizedDescription
        }
    }
}
