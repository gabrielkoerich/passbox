/*
 The phone's key. The private half is made inside the Secure Enclave and never leaves it. What
 this app keeps is the blob the Enclave hands back, which only this phone's Enclave can use, and
 only after Face ID. That is what makes the phone a second sensor and not a second password.
 */

import CryptoKit
import Foundation
import LocalAuthentication
import PassboxCore

/// A Secure Enclave key that Face ID has just opened, for one agreement
struct EnclaveKey: Agreement {
    let key: SecureEnclave.P256.KeyAgreement.PrivateKey

    func sharedSecretFromKeyAgreement(
        with publicKeyShare: P256.KeyAgreement.PublicKey
    ) throws -> SharedSecret {
        try key.sharedSecretFromKeyAgreement(with: publicKeyShare)
    }
}

enum PhoneKey {
    /// A new key, as its public half for the Mac and the blob to keep. No Face ID yet: making a
    /// key opens nothing
    static func make() throws -> (publicKey: Data, blob: Data) {
        #if targetEnvironment(simulator)
            // The simulator has no Enclave. A software key lets the screens be tried there
            let key = P256.KeyAgreement.PrivateKey()
            return (key.publicKey.x963Representation, key.rawRepresentation)
        #else
            guard
                let access = SecAccessControlCreateWithFlags(
                    nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                    [.privateKeyUsage, .biometryAny], nil)
            else {
                throw Refused("could not build the access control for the key")
            }
            let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
            return (key.publicKey.x963Representation, key.dataRepresentation)
        #endif
    }

    /// Face ID, then the key. Authenticating first and handing that context to the key is what
    /// the Mac's helper does too, so there is one prompt and it is this one
    static func open(blob: Data, reason: String) async throws -> Agreement {
        #if targetEnvironment(simulator)
            return try P256.KeyAgreement.PrivateKey(rawRepresentation: blob)
        #else
            let context = LAContext()
            do {
                _ = try await context.evaluatePolicy(
                    .deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
            } catch {
                throw Refused("Face ID did not confirm it: \(error.localizedDescription)")
            }
            return EnclaveKey(
                key: try SecureEnclave.P256.KeyAgreement.PrivateKey(
                    dataRepresentation: blob, authenticationContext: context))
        #endif
    }
}
