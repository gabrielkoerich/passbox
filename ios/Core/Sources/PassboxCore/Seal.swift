/*
 The two boxes the phone handles. It opens the wrap the Mac made at enrollment, which holds the
 store key, and seals that key into the answer for one request. Both formats are the broker's:
 `swift/passbox-se.swift` seals the first and `src/broker/phone.rs` opens the second.
 */

#if canImport(CryptoKit)
    import CryptoKit
#else
    import Crypto
#endif
import Foundation

/// The private half of the phone's key, wherever it lives. In the app that is the Secure Enclave,
/// which only ever does the agreement, so nothing else is asked of a key
public protocol Agreement {
    func sharedSecretFromKeyAgreement(
        with publicKeyShare: P256.KeyAgreement.PublicKey
    ) throws -> SharedSecret
}

extension P256.KeyAgreement.PrivateKey: Agreement {}

public enum Wrap {
    static let info = Data("passbox-se-v1".utf8)

    /// The store key out of the phone's wrap: P-256 agreement with the sender's one-time key,
    /// HKDF-SHA256 salted with that key, then AES-GCM
    public static func open(ephemeral: Data, ciphertext: Data, with key: Agreement) throws -> Data {
        let sender = try P256.KeyAgreement.PublicKey(x963Representation: ephemeral)
        let shared = try key.sharedSecretFromKeyAgreement(with: sender)
        let symmetric = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: ephemeral, sharedInfo: info, outputByteCount: 32)
        return try AES.GCM.open(AES.GCM.SealedBox(combined: ciphertext), using: symmetric)
    }

    /// The Mac's half, here so a test can make a wrap without a Mac
    static func seal(
        _ plaintext: Data, to recipient: P256.KeyAgreement.PublicKey
    ) throws -> (ephemeral: Data, ciphertext: Data) {
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let salt = ephemeral.publicKey.x963Representation
        let symmetric = try ephemeral.sharedSecretFromKeyAgreement(with: recipient)
            .hkdfDerivedSymmetricKey(
                using: SHA256.self, salt: salt, sharedInfo: info, outputByteCount: 32)
        guard let combined = try AES.GCM.seal(plaintext, using: symmetric).combined else {
            throw Refused("could not seal")
        }
        return (salt, combined)
    }
}

public enum Answer {
    /* The box only one request's key opens: X25519 with a key made for this message, HKDF-SHA256
     salted with both public keys and bound to the request id, then ChaCha20-Poly1305 with the id
     as associated data. The nonce is zero because the key is used once. `ephemeral` is a
     parameter so a test can pin the output. */
    public static func seal(
        _ plaintext: Data, to key: Data, id: String,
        with ephemeral: Curve25519.KeyAgreement.PrivateKey = .init()
    ) throws -> (ephemeral: Data, sealed: Data) {
        let theirs = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: key)
        let ours = ephemeral.publicKey.rawRepresentation
        let symmetric = try ephemeral.sharedSecretFromKeyAgreement(with: theirs)
            .hkdfDerivedSymmetricKey(
                using: SHA256.self, salt: ours + key,
                sharedInfo: Data("passbox-phone-v1 \(id)".utf8), outputByteCount: 32)
        let box = try ChaChaPoly.seal(
            plaintext, using: symmetric, nonce: ChaChaPoly.Nonce(data: Data(count: 12)),
            authenticating: Data(id.utf8))
        return (ours, box.ciphertext + box.tag)
    }
}
