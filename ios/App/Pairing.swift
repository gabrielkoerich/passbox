/*
 What the phone remembers about its Mac, kept as one keychain item that never leaves this device
 and is not in a backup. The bearer and the key blob are both useless anywhere else: the blob
 needs this phone's Enclave, and the Mac only takes the bearer from this phone's tailnet node.
 */

import Foundation
import Security

struct Pairing: Codable, Equatable {
    /// What was typed at enrollment: the Mac's tailnet address or MagicDNS name
    var host: String
    /// The Mac's own name for itself
    var mac: String
    /// This phone as the tailnet names it, which is how the Mac's prompt and audit log name it
    var phone: String
    var token: String
    var keyBlob: Data
    var added: Date

    private static let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "com.gabrielkoerich.passbox.phone",
        kSecAttrAccount as String: "pairing",
    ]

    static func load() -> Pairing? {
        var query = Self.query
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var found: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &found) == errSecSuccess,
            let data = found as? Data
        else {
            return nil
        }
        return try? JSONDecoder().decode(Pairing.self, from: data)
    }

    func save() throws {
        Pairing.forget()
        var item = Self.query
        item[kSecValueData as String] = try JSONEncoder().encode(self)
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError(status: status)
        }
    }

    static func forget() {
        SecItemDelete(query as CFDictionary)
    }
}

struct KeychainError: LocalizedError {
    let status: OSStatus

    var errorDescription: String? {
        let text = SecCopyErrorMessageString(status, nil) as String? ?? "error \(status)"
        return "the keychain refused: \(text)"
    }
}
