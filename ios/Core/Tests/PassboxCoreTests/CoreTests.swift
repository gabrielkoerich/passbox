#if canImport(CryptoKit)
    import CryptoKit
#else
    import Crypto
#endif
import Foundation
import XCTest

@testable import PassboxCore

/// A broker that answers each line with the next reply it was given, and keeps what it was sent
final class FakeBroker: Transport, @unchecked Sendable {
    private let lock = NSLock()
    private var replies: [String]
    private(set) var sent: [[String: Any]] = []

    init(_ replies: [String]) {
        self.replies = replies
    }

    func exchange(_ line: Data, timeout: TimeInterval) async throws -> Data {
        try answer(line)
    }

    private func answer(_ line: Data) throws -> Data {
        lock.lock()
        defer { lock.unlock() }
        let request = try JSONSerialization.jsonObject(with: line) as? [String: Any]
        sent.append(request ?? [:])
        return Data(replies.removeFirst().utf8)
    }

    static func ok(_ value: String) -> String {
        let data = try! JSONSerialization.data(withJSONObject: ["ok": true, "value": value])
        return String(decoding: data, as: UTF8.self)
    }

    static func refused(_ error: String) -> String {
        let data = try! JSONSerialization.data(withJSONObject: ["ok": false, "error": error])
        return String(decoding: data, as: UTF8.self)
    }
}

func hex(_ text: String) -> Data {
    var data = Data()
    var index = text.startIndex
    while index < text.endIndex {
        let next = text.index(index, offsetBy: 2)
        data.append(UInt8(text[index..<next], radix: 16)!)
        index = next
    }
    return data
}

final class CoreTests: XCTestCase {
    /* The same bytes are pinned in `src/broker/phone.rs`, where the broker opens them. Each side
     checks the vector on its own CI, so neither needs the other's toolchain to prove they agree. */
    func testAnAnswerIsSealedTheWayTheBrokerOpensIt() throws {
        let request = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: Data(repeating: 0x11, count: 32))
        let ephemeral = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: Data(repeating: 0x22, count: 32))
        let answer = try Answer.seal(
            Data("AGE-SECRET-KEY-1EXAMPLE".utf8), to: request.publicKey.rawRepresentation,
            id: "request-1", with: ephemeral)

        XCTAssertEqual(answer.ephemeral, hex(VECTOR_EPHEMERAL))
        XCTAssertEqual(answer.sealed, hex(VECTOR_SEALED))
    }

    /// A wrap sealed by another implementation, Python's `cryptography`, to a fixed key
    func testAWrapFromAnotherImplementationOpens() throws {
        let key = try P256.KeyAgreement.PrivateKey(rawRepresentation: hex(WRAP_PRIVATE))
        let plain = try Wrap.open(
            ephemeral: hex(WRAP_EPHEMERAL), ciphertext: hex(WRAP_CIPHERTEXT), with: key)
        XCTAssertEqual(String(decoding: plain, as: UTF8.self), "AGE-SECRET-KEY-1EXAMPLE")
    }

    func testAWrapOpensOnlyWithItsOwnKey() throws {
        let key = P256.KeyAgreement.PrivateKey()
        let wrap = try Wrap.seal(Data("the store key".utf8), to: key.publicKey)
        XCTAssertEqual(
            try Wrap.open(ephemeral: wrap.ephemeral, ciphertext: wrap.ciphertext, with: key),
            Data("the store key".utf8))
        XCTAssertThrowsError(
            try Wrap.open(
                ephemeral: wrap.ephemeral, ciphertext: wrap.ciphertext,
                with: P256.KeyAgreement.PrivateKey()))
    }

    func testEnrollingSendsTheCodeAndTheKeyAndReadsTheNames() async throws {
        let broker = FakeBroker([
            FakeBroker.ok(#"{"token":"bearer","mac":"studio","phone":"iphone (me@x, 100.64.0.9)"}"#)
        ])
        let enrolled = try await Client(transport: broker)
            .enroll(code: "123456", publicKey: Data([4, 7, 7]))

        XCTAssertEqual(enrolled.token, "bearer")
        XCTAssertEqual(enrolled.mac, "studio")
        let sent = broker.sent[0]
        XCTAssertEqual(sent["op"] as? String, "phone")
        XCTAssertEqual(sent["agent"] as? String, "")
        XCTAssertEqual(sent["action"] as? String, "enroll")
        XCTAssertEqual(
            sent["params"] as? [[String]], [["code", "123456"], ["public_key", "BAcH"]])
    }

    func testNothingWaitingIsNilAndARefusalIsTheBrokersWords() async throws {
        let broker = FakeBroker([
            FakeBroker.ok(""), FakeBroker.refused("no phone is enrolled on this Mac"), "nonsense",
        ])
        let client = Client(transport: broker, token: "bearer")

        let nothing = try await client.pending(wait: 25)
        XCTAssertNil(nothing)
        XCTAssertEqual(broker.sent[0]["token"] as? String, "bearer")
        XCTAssertEqual(broker.sent[0]["params"] as? [[String]], [["wait", "25"]])

        do {
            _ = try await client.pending()
            XCTFail("a refusal read as an answer")
        } catch {
            XCTAssertEqual(error as? Refused, Refused("no phone is enrolled on this Mac"))
        }
        do {
            _ = try await client.pending()
            XCTFail("nonsense read as an answer")
        } catch {
            XCTAssertNotNil(error as? Refused)
        }
    }

    /// The whole approval against a broker written here: its wrap, its request key, its opening
    func testApprovingOpensTheWrapAndAnswersForThatRequest() async throws {
        let phone = P256.KeyAgreement.PrivateKey()
        let storeKey = Data("AGE-SECRET-KEY-1EXAMPLE".utf8)
        let wrap = try Wrap.seal(storeKey, to: phone.publicKey)
        let request = Curve25519.KeyAgreement.PrivateKey()
        let shown: [String: Any] = [
            "id": "request-9", "reason": "release the password for a/b to claude", "since": 1,
            "key": request.publicKey.rawRepresentation.base64EncodedString(),
            "ephemeral": wrap.ephemeral.base64EncodedString(),
            "ciphertext": wrap.ciphertext.base64EncodedString(),
        ]
        let json = String(
            decoding: try JSONSerialization.data(withJSONObject: shown), as: UTF8.self)
        let broker = FakeBroker([FakeBroker.ok(json), FakeBroker.ok("ok"), FakeBroker.ok("ok")])
        let client = Client(transport: broker, token: "bearer")

        let found = try await client.pending()
        let pending = try XCTUnwrap(found)
        XCTAssertEqual(pending.reason, "release the password for a/b to claude")
        try await client.approve(pending, with: phone)

        let answer = broker.sent[1]
        XCTAssertEqual(answer["action"] as? String, "answer")
        XCTAssertEqual(answer["name"] as? String, "request-9")
        let params = Dictionary(
            uniqueKeysWithValues: (answer["params"] as! [[String]]).map { ($0[0], $0[1]) })
        let ephemeral = try XCTUnwrap(Data(base64Encoded: params["ephemeral"]!))
        let sealed = try XCTUnwrap(Data(base64Encoded: params["sealed"]!))

        // The broker's half of the box, as `open_box` in src/broker/phone.rs does it
        let theirs = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephemeral)
        let symmetric = try request.sharedSecretFromKeyAgreement(with: theirs)
            .hkdfDerivedSymmetricKey(
                using: SHA256.self, salt: ephemeral + request.publicKey.rawRepresentation,
                sharedInfo: Data("passbox-phone-v1 request-9".utf8), outputByteCount: 32)
        let box = try ChaChaPoly.SealedBox(
            nonce: ChaChaPoly.Nonce(data: Data(count: 12)),
            ciphertext: sealed.dropLast(16), tag: sealed.suffix(16))
        XCTAssertEqual(
            try ChaChaPoly.open(box, using: symmetric, authenticating: Data("request-9".utf8)),
            storeKey)

        try await client.deny(pending)
        XCTAssertEqual(broker.sent[2]["params"] as? [[String]], [["deny", "1"]])
    }
}

// Made by Python's `cryptography` from fixed keys, so three implementations agree on these bytes
let VECTOR_EPHEMERAL = "0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20"
let VECTOR_SEALED = "81bfa93789e621bd66606d5110cb79bffa48ebcbdeec9e69278b8b7cffdcf951ff41f600f798d7"
let WRAP_PRIVATE = "3333333333333333333333333333333333333333333333333333333333333333"
let WRAP_EPHEMERAL =
    "045b36890dacbd7c9a96bb74a1ee28b3d2d75b72e09a20ef25cf8e6fd8a9f0350d0e14bed8d4682a34d83538bdff5b96e89a6666ec0db5745d02fa1210072df75a"
let WRAP_CIPHERTEXT =
    "555555555555555555555555c0771727d0e1443e262a982b41782a98785a51b853b09d4ab564f79e57408aa8703fb5e99b8004"
