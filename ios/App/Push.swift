/**
 * Notifications. Only the app's owner can ask Apple to wake the app, so a relay holds that key:
 * the Cloudflare Worker in `relay/`. The phone registers its device token there and gets an id and
 * a secret, which it hands to its Mac. When a request waits, the Mac sends the relay those two and
 * the phone shows "Your Mac is waiting for an approval". What is asked stays between Mac and phone
 **/

import SwiftUI
import UserNotifications

enum Relay {
    static let address = "https://passbox-push.RELAY.workers.dev"

    // Xcode runs debug builds against Apple's sandbox, and TestFlight and the App Store use production
    #if DEBUG
        static let environment = "sandbox"
    #else
        static let environment = "production"
    #endif

    struct Registration: Codable, Equatable {
        let id: String
        let secret: String
    }

    /// A new registration, or the same one carried over to a new device token
    static func register(token: String, known: Registration?) async throws -> Registration {
        guard let url = URL(string: "\(address)/register") else {
            throw Unreachable(why: "the relay address is not a URL")
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "content-type")
        var body = ["token": token, "environment": environment]
        if let known {
            body["id"] = known.id
            body["secret"] = known.secret
        }

        request.httpBody = try JSONEncoder().encode(body)
        let (data, response) = try await URLSession.shared.data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200,
            let registration = try? JSONDecoder().decode(Registration.self, from: data)
        else {
            throw Unreachable(why: "the notification relay refused this phone")
        }

        return registration
    }
}

/// Where iOS hands over the device token, which only an app delegate receives
final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    var onToken: ((String) -> Void)?

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        return true
    }

    func application(
        _ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data
    ) {
        onToken?(deviceToken.map { String(format: "%02x", $0) }.joined())
    }

    // With the app open the request is already on screen, so a banner would say it twice
    func userNotificationCenter(
        _ center: UNUserNotificationCenter, willPresent notification: UNNotification
    ) async -> UNNotificationPresentationOptions {
        []
    }
}
