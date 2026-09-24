/*
 Wraps the store key to a Secure Enclave key, and unwraps it behind a Touch ID prompt we word.

 Swift rather than Rust because CryptoKit's SecureEnclave is the only API that hands back a usable
 key blob without a keychain item. Keychain items with biometric access control need the
 keychain-access-groups entitlement, which needs an Apple Developer identity. A key blob needs
 neither, which is why age-plugin-se runs from a Homebrew bottle with an ad-hoc signature.
 */

import CryptoKit
import Foundation
import LocalAuthentication

let info = Data("passbox-se-v1".utf8)

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
}

func readStdin() -> [String: String] {
    let data = FileHandle.standardInput.readDataToEndOfFile()
    guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: String] else {
        fail("stdin is not a flat json object")
    }
    return json
}

func field(_ json: [String: String], _ key: String) -> Data {
    guard let value = json[key], let data = Data(base64Encoded: value) else {
        fail("missing or malformed field \(key)")
    }
    return data
}

func emit(_ object: [String: String]) {
    guard let data = try? JSONSerialization.data(withJSONObject: object) else {
        fail("could not serialise the result")
    }
    FileHandle.standardOutput.write(data)
}

/// Shared secret to symmetric key, with the ephemeral public key as the salt
func derive(_ shared: SharedSecret, salt: Data) -> SymmetricKey {
    shared.hkdfDerivedSymmetricKey(
        using: SHA256.self, salt: salt, sharedInfo: info, outputByteCount: 32)
}

func keygen() {
    guard
        let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryAny], nil)
    else {
        fail("could not build the access control")
    }
    do {
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        emit([
            "public_key": key.publicKey.x963Representation.base64EncodedString(),
            "key_blob": key.dataRepresentation.base64EncodedString(),
        ])
    } catch {
        fail("no Secure Enclave key: \(error)")
    }
}

/// Wrapping needs only the public key, so storing a secret never raises a prompt
func wrap() {
    let json = readStdin()
    let plaintext = field(json, "plaintext")
    guard
        let recipient = try? P256.KeyAgreement.PublicKey(
            x963Representation: field(json, "public_key"))
    else {
        fail("bad public key")
    }

    let ephemeral = P256.KeyAgreement.PrivateKey()
    guard let shared = try? ephemeral.sharedSecretFromKeyAgreement(with: recipient) else {
        fail("key agreement failed")
    }
    let salt = ephemeral.publicKey.x963Representation
    guard let sealed = try? AES.GCM.seal(plaintext, using: derive(shared, salt: salt)),
        let combined = sealed.combined
    else {
        fail("could not seal")
    }
    emit([
        "ephemeral": salt.base64EncodedString(),
        "ciphertext": combined.base64EncodedString(),
    ])
}

/// Authenticate first with our own wording, then use that context for the key operation
func unwrap(reason: String) {
    let json = readStdin()
    let blob = field(json, "key_blob")
    let ephemeral = field(json, "ephemeral")
    let ciphertext = field(json, "ciphertext")

    let context = LAContext()
    context.localizedCancelTitle = "Deny"

    /* Ask whether the sensor is reachable before raising anything. Hardware present, a print
    enrolled and an unlocked session are all still not enough: a MacBook running with the lid shut
    has its sensor inside the closed keyboard, and `evaluatePolicy` then fails with a cancellation
    that reads like the user refused. */
    var reachable: NSError?
    if !context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &reachable) {
        let why = reachable?.localizedDescription ?? "unknown reason"
        fail("Touch ID is unavailable on this Mac right now (\(why)). A closed lid or a sleeping "
            + "Touch ID keyboard will do this. Use the recovery passphrase, or open the lid.")
    }

    var authError: Error?
    let waiter = DispatchSemaphore(value: 0)
    context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) {
        _, error in
        authError = error
        waiter.signal()
    }
    waiter.wait()
    if let authError {
        fail("denied: \(authError.localizedDescription)")
    }

    guard
        let key = try? SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: blob, authenticationContext: context)
    else {
        fail("this key does not belong to this Secure Enclave")
    }
    guard
        let sender = try? P256.KeyAgreement.PublicKey(x963Representation: ephemeral),
        let shared = try? key.sharedSecretFromKeyAgreement(with: sender),
        let box = try? AES.GCM.SealedBox(combined: ciphertext),
        let plaintext = try? AES.GCM.open(box, using: derive(shared, salt: ephemeral))
    else {
        fail("could not open the wrap")
    }
    FileHandle.standardOutput.write(plaintext)
}

let args = Array(CommandLine.arguments.dropFirst())
switch args.first {
case "keygen":
    keygen()
case "wrap":
    wrap()
case "unwrap":
    guard args.count == 3, args[1] == "--reason" else {
        fail("usage: passbox-se unwrap --reason <text>")
    }
    unwrap(reason: args[2])
default:
    fail("usage: passbox-se keygen | wrap | unwrap --reason <text>")
}
