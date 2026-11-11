/*
 The phone's half of passbox: a second approver for the Mac's Touch ID prompt. A Status tab, which
 shows the request the Mac is waiting on and answers it with Face ID, and a Settings tab of facts
 about the pairing. The protocol and both boxes are in PassboxCore. This target adds the Secure
 Enclave key, the keychain, the tailnet connection and the screen.
 */

import SwiftUI

@main
struct PassboxApp: App {
    @StateObject private var model = Model()
    @Environment(\.scenePhase) private var phase

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
                .onAppear { model.start() }
        }
        // The Mac is asked only while the app is on screen. iOS gives it no way to listen otherwise
        .onChange(of: phase) { _, now in
            if now == .active {
                model.start()
            } else {
                model.stop()
            }
        }
    }
}
