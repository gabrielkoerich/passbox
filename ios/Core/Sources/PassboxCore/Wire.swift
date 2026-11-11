/*
 The broker's protocol as the phone speaks it: one JSON line out, one JSON line back, a new
 connection each time. `docs/content/design.md` has the table this follows.
 */

import Foundation

/// A refusal in the broker's own words, or a reply that was not one
public struct Refused: Error, LocalizedError, Equatable {
    public let message: String

    public init(_ message: String) {
        self.message = message
    }

    public var errorDescription: String? { message }
}

/// The request on the Mac's screen, with what the phone needs to answer it
public struct Pending: Decodable, Equatable, Sendable {
    public let id: String
    /// The prompt's own sentence, such as "release the password for github/token to claude"
    public let reason: String
    /// When the Mac started asking, in seconds since 1970
    public let since: UInt64
    /// The request's one-time X25519 public key, in base64
    public let key: String
    public let ephemeral: String
    public let ciphertext: String
}

/// What enrolling gives back: the bearer for every later call, and the two names to show
public struct Enrolled: Decodable, Equatable, Sendable {
    public let token: String
    public let mac: String
    public let phone: String
}

enum Wire {
    private struct Request: Encodable {
        let op = "phone"
        // The broker requires the field. A phone is not an agent, so it stays empty
        let agent = ""
        let action: String
        let name: String
        let token: String
        let params: [[String]]
    }

    private struct Reply: Decodable {
        let ok: Bool
        let value: String?
        let error: String?
    }

    static func line(
        _ action: String, name: String = "", token: String = "", params: [(String, String)] = []
    ) throws -> Data {
        let request = Request(
            action: action, name: name, token: token, params: params.map { [$0.0, $0.1] })
        return try JSONEncoder().encode(request) + Data("\n".utf8)
    }

    static func value(of reply: Data) throws -> String {
        guard let reply = try? JSONDecoder().decode(Reply.self, from: reply) else {
            throw Refused("the Mac sent something that is not a reply")
        }
        guard reply.ok, let value = reply.value else {
            throw Refused(reply.error ?? "the Mac refused")
        }
        return value
    }
}

/// How a line reaches the broker. The app's is a TCP connection over the tailnet
public protocol Transport: Sendable {
    func exchange(_ line: Data, timeout: TimeInterval) async throws -> Data
}

public struct Client: Sendable {
    let transport: Transport
    let token: String

    public init(transport: Transport, token: String = "") {
        self.transport = transport
        self.token = token
    }

    /// The Mac waits for a fingerprint before it answers this, so the call is given the whole of
    /// the enrollment window
    public func enroll(code: String, publicKey: Data) async throws -> Enrolled {
        let line = try Wire.line(
            "enroll", params: [("code", code), ("public_key", publicKey.base64EncodedString())])
        let value = try Wire.value(of: await transport.exchange(line, timeout: 150))
        guard let enrolled = try? JSONDecoder().decode(Enrolled.self, from: Data(value.utf8))
        else {
            throw Refused("the Mac's enrollment reply is not one this app understands")
        }
        return enrolled
    }

    /// The waiting request, or nil. With `wait` the Mac holds the call open that many seconds for
    /// one to appear, so an open app hears at once and asks rarely
    public func pending(wait: Int = 0) async throws -> Pending? {
        let params = wait > 0 ? [("wait", String(wait))] : []
        let line = try Wire.line("pending", token: token, params: params)
        let value = try Wire.value(
            of: await transport.exchange(line, timeout: TimeInterval(wait + 10)))
        guard !value.isEmpty else {
            return nil
        }
        guard let pending = try? JSONDecoder().decode(Pending.self, from: Data(value.utf8)) else {
            throw Refused("the Mac's request is not one this app understands")
        }
        return pending
    }

    /// Open the wrap with the phone's key, which is the Face ID moment, and send the store key
    /// back sealed for this request alone
    public func approve(_ pending: Pending, with key: Agreement) async throws {
        guard let ephemeral = Data(base64Encoded: pending.ephemeral),
            let ciphertext = Data(base64Encoded: pending.ciphertext),
            let requestKey = Data(base64Encoded: pending.key)
        else {
            throw Refused("the Mac's request is not valid base64")
        }
        let storeKey = try Wrap.open(ephemeral: ephemeral, ciphertext: ciphertext, with: key)
        let answer = try Answer.seal(storeKey, to: requestKey, id: pending.id)
        let line = try Wire.line(
            "answer", name: pending.id, token: token,
            params: [
                ("ephemeral", answer.ephemeral.base64EncodedString()),
                ("sealed", answer.sealed.base64EncodedString()),
            ])
        _ = try Wire.value(of: await transport.exchange(line, timeout: 15))
    }

    public func deny(_ pending: Pending) async throws {
        let line = try Wire.line(
            "answer", name: pending.id, token: token, params: [("deny", "1")])
        _ = try Wire.value(of: await transport.exchange(line, timeout: 15))
    }
}
