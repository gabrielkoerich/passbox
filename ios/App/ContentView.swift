/*
 The one screen. Before pairing it asks for the Mac and the code. After, it is either quiet or
 showing the sentence the Mac's own prompt shows, with a button that asks for Face ID.
 */

import PassboxCore
import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var model: Model
    @State private var showingInfo = false

    var body: some View {
        NavigationStack {
            Group {
                if model.pairing == nil {
                    PairView()
                } else {
                    HomeView()
                }
            }
            .navigationTitle("passbox")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                if model.pairing != nil {
                    ToolbarItem(placement: .topBarTrailing) {
                        Button {
                            showingInfo = true
                        } label: {
                            Image(systemName: "info.circle")
                        }
                        .accessibilityLabel("About this pairing")
                    }
                }
            }
            .sheet(isPresented: $showingInfo) {
                InfoView()
            }
        }
    }
}

/// A large symbol over a title and a line of detail, which is all the quiet states are
private struct Status: View {
    let symbol: String
    let tint: Color
    let title: String
    let detail: String

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: symbol)
                .font(.system(size: 76, weight: .regular))
                .foregroundStyle(tint)
                .padding(.bottom, 6)
            Text(title)
                .font(.title2.weight(.semibold))
            Text(detail)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding(.horizontal, 32)
    }
}

struct HomeView: View {
    @EnvironmentObject private var model: Model

    var body: some View {
        let mac = model.pairing?.mac ?? "the Mac"
        VStack {
            Spacer()
            if let request = model.request {
                RequestView(request: request, mac: mac)
            } else if model.approved {
                Status(
                    symbol: "checkmark.circle.fill", tint: .green, title: "Approved",
                    detail: "\(mac) has what it asked for.")
            } else if let trouble = model.trouble {
                Status(
                    symbol: "wifi.exclamationmark", tint: .orange, title: "Cannot reach \(mac)",
                    detail: trouble)
            } else if model.reachable {
                Status(
                    symbol: "lock.shield", tint: .accentColor, title: "Nothing waiting",
                    detail: "Watching \(mac). A request it cannot get answered appears here.")
            } else {
                ProgressView("Looking for \(mac)")
            }
            Spacer()
            Spacer()
        }
        .frame(maxWidth: .infinity)
        .animation(.default, value: model.request)
        .animation(.default, value: model.approved)
    }
}

/// The Mac's prompt, word for word, so the two screens can be compared
struct RequestView: View {
    @EnvironmentObject private var model: Model
    let request: Pending
    let mac: String

    var body: some View {
        VStack(spacing: 28) {
            VStack(spacing: 10) {
                Text("passbox on \(mac) is trying to")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Text("\(request.reason).")
                    .font(.title2.weight(.semibold))
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                Text(
                    "Asked \(Date(timeIntervalSince1970: TimeInterval(request.since)), style: .relative) ago"
                )
                .font(.footnote)
                .foregroundStyle(.secondary)
            }

            if let trouble = model.trouble {
                Text(trouble)
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
            }

            VStack(spacing: 14) {
                Button {
                    Task { await model.approve() }
                } label: {
                    Label("Approve", systemImage: "faceid")
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 6)
                }
                .buttonStyle(.borderedProminent)

                Button("Deny", role: .destructive) {
                    Task { await model.deny() }
                }
            }
            .disabled(model.busy)
        }
        .padding(.horizontal, 28)
    }
}

struct PairView: View {
    @EnvironmentObject private var model: Model
    @State private var host = ""
    @State private var code = ""

    var body: some View {
        Form {
            Section {
                TextField("Mac", text: $host, prompt: Text("100.64.0.1 or its tailnet name"))
                    .keyboardType(.URL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                TextField("Code", text: $code, prompt: Text("Six digits"))
                    .keyboardType(.numberPad)
                    .font(.body.monospacedDigit())
            } header: {
                Text("Pair with your Mac")
            } footer: {
                Text(
                    """
                    Run `passbox phone add` on the Mac and enter the two lines it shows. \
                    Tailscale has to be on, here and there.
                    """)
            }

            Section {
                Button {
                    Task { await model.pair(host: host, code: code) }
                } label: {
                    if model.busy {
                        HStack(spacing: 10) {
                            ProgressView()
                            Text("Touch the sensor on the Mac")
                        }
                    } else {
                        Text("Pair")
                    }
                }
                .disabled(model.busy || host.isEmpty || code.count < 6)
            } footer: {
                if let trouble = model.trouble {
                    Text(trouble).foregroundStyle(.red)
                }
            }
        }
    }
}
