/*
 The Settings tab: facts about the pairing, and nothing to set. The one action is forgetting the
 Mac, which is how a phone is paired again or handed on.
 */

import SwiftUI

struct InfoView: View {
    @EnvironmentObject private var model: Model
    @State private var confirmingForget = false

    var body: some View {
        NavigationStack {
            List {
                if let pairing = model.pairing {
                    Section("Mac") {
                        LabeledContent("Name", value: pairing.mac)
                        LabeledContent("Address", value: pairing.host)
                        LabeledContent("Port", value: "8787, over Tailscale")
                    }

                    Section("This phone") {
                        LabeledContent("Known to the Mac as", value: pairing.phone)
                        LabeledContent(
                            "Paired", value: pairing.added.formatted(date: .abbreviated, time: .shortened))
                        LabeledContent("Key", value: "Secure Enclave, behind Face ID")
                    }

                    Section("Connection") {
                        LabeledContent("Mac", value: model.reachable ? "Reachable" : "Not reachable")
                        if let lastContact = model.lastContact {
                            LabeledContent(
                                "Last answer", value: lastContact.formatted(date: .omitted, time: .standard))
                        }
                        if let trouble = model.trouble {
                            Text(trouble)
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                    }
                } else {
                    Section("Mac") {
                        Text("Not paired. Pair from the Status tab.")
                            .foregroundStyle(.secondary)
                    }
                }

                Section {
                    LabeledContent("Version", value: Self.version)
                } header: {
                    Text("About")
                } footer: {
                    Text(
                        """
                        This phone holds no secrets. It can open the store key for its Mac, only \
                        after Face ID, and only to answer a request the Mac is showing.
                        """)
                }

                if model.pairing != nil {
                    Section {
                        Button("Forget this Mac", role: .destructive) {
                            confirmingForget = true
                        }
                    } footer: {
                        Text(
                            "Then run `passbox phone rm` on the Mac, so it stops asking this phone.")
                    }
                }
            }
            .navigationTitle("Settings")
            .confirmationDialog(
                "Forget this Mac?", isPresented: $confirmingForget, titleVisibility: .visible
            ) {
                Button("Forget", role: .destructive) {
                    model.forget()
                }
            } message: {
                Text("This phone will no longer be able to approve for it.")
            }
        }
    }

    private static var version: String {
        let info = Bundle.main.infoDictionary
        let short = info?["CFBundleShortVersionString"] as? String ?? "?"
        let build = info?["CFBundleVersion"] as? String ?? "?"
        return "\(short) (\(build))"
    }
}
