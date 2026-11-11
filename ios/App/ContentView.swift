/*
 Two tabs, and the first is the app. Status is black with the name in the middle and one thing
 under it: a line saying the Mac is being watched, or the sentence the Mac's own prompt shows
 with a button that asks for Face ID. Settings states the pairing and sets nothing.
 */

import PassboxCore
import SwiftUI

struct ContentView: View {
    var body: some View {
        TabView {
            StatusView()
                .tabItem { Label("Status", systemImage: "checkmark.shield.fill") }
            InfoView()
                .tabItem { Label("Settings", systemImage: "gearshape.fill") }
        }
        // One look in any light, since the screen is mostly empty and meant to be glanced at
        .preferredColorScheme(.dark)
    }
}

/// The mark and the name, side by side
private struct Brand: View {
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "lock.shield.fill")
                .font(.system(size: 46))
                .foregroundStyle(
                    LinearGradient(
                        colors: [
                            Color(red: 0.36, green: 0.64, blue: 1.0),
                            Color(red: 0.16, green: 0.40, blue: 1.0),
                        ], startPoint: .top, endPoint: .bottom))
            Text("passbox")
                .font(.system(size: 40, weight: .bold))
                .foregroundStyle(.white)
        }
    }
}

/// A dot and a few words in a capsule, which is all a quiet state needs
private struct Pill: View {
    let dot: Color
    let text: String

    var body: some View {
        HStack(spacing: 10) {
            Circle()
                .fill(dot)
                .frame(width: 10, height: 10)
            Text(text)
                .font(.headline)
                .foregroundStyle(.white)
        }
        .padding(.horizontal, 22)
        .padding(.vertical, 14)
        .background(Capsule().fill(Color.white.opacity(0.10)))
    }
}

struct StatusView: View {
    @EnvironmentObject private var model: Model

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            VStack(spacing: 40) {
                Spacer()
                Brand()
                if model.pairing == nil {
                    PairView()
                } else {
                    PairedView()
                }
                Spacer()
                Spacer()
            }
            .padding(.horizontal, 28)
            .frame(maxWidth: .infinity)
        }
    }
}

private struct PairedView: View {
    @EnvironmentObject private var model: Model

    var body: some View {
        let mac = model.pairing?.mac ?? "the Mac"
        VStack(spacing: 14) {
            if let request = model.request {
                RequestView(request: request, mac: mac)
            } else if model.approved {
                Pill(dot: .green, text: "Approved")
                caption("\(mac) has what it asked for.")
            } else if let trouble = model.trouble {
                Pill(dot: .orange, text: "Cannot reach \(mac)")
                caption(trouble)
            } else if model.reachable {
                Pill(dot: .green, text: "Watching \(mac)")
                caption("Nothing waiting.")
            } else {
                ProgressView()
                    .tint(.white)
                caption("Looking for \(mac)")
            }
        }
        .animation(.default, value: model.request)
        .animation(.default, value: model.approved)
    }

    private func caption(_ text: String) -> some View {
        Text(text)
            .font(.subheadline)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
    }
}

/// The Mac's prompt, word for word, so the two screens can be compared
private struct RequestView: View {
    @EnvironmentObject private var model: Model
    let request: Pending
    let mac: String

    var body: some View {
        VStack(spacing: 26) {
            VStack(spacing: 10) {
                Text("\(mac) is trying to")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Text("\(request.reason).")
                    .font(.title3.weight(.semibold))
                    .foregroundStyle(.white)
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

            VStack(spacing: 16) {
                Button {
                    Task { await model.approve() }
                } label: {
                    Label("Approve", systemImage: "faceid")
                        .font(.title3.weight(.semibold))
                        .foregroundStyle(.white)
                        .frame(maxWidth: 300)
                        .frame(height: 64)
                        .background(Capsule().fill(Color.accentColor))
                }

                Button("Deny", role: .destructive) {
                    Task { await model.deny() }
                }
                .font(.headline)
            }
            .disabled(model.busy)
            .opacity(model.busy ? 0.5 : 1)
        }
    }
}

private struct PairView: View {
    @EnvironmentObject private var model: Model
    @State private var host = ""
    @State private var code = ""

    var body: some View {
        VStack(spacing: 14) {
            field("Mac address", text: $host)
                .keyboardType(.URL)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            field("Code", text: $code)
                .keyboardType(.numberPad)

            Button {
                Task { await model.pair(host: host, code: code) }
            } label: {
                Group {
                    if model.busy {
                        HStack(spacing: 10) {
                            ProgressView()
                                .tint(.white)
                            Text("Touch the sensor on the Mac")
                        }
                    } else {
                        Text("Pair")
                    }
                }
                .font(.headline)
                .foregroundStyle(.white)
                .frame(maxWidth: 300)
                .frame(height: 54)
                .background(Capsule().fill(Color.accentColor))
            }
            .disabled(model.busy || host.isEmpty || code.count < 6)
            .opacity(host.isEmpty || code.count < 6 ? 0.5 : 1)
            .padding(.top, 6)

            if let trouble = model.trouble {
                Text(trouble)
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
            } else {
                Text(
                    """
                    Run `passbox phone add` on the Mac and enter the two lines it shows. \
                    Tailscale has to be on, here and there.
                    """
                )
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            }
        }
    }

    private func field(_ title: String, text: Binding<String>) -> some View {
        TextField(title, text: text)
            .font(.body.monospacedDigit())
            .foregroundStyle(.white)
            .padding(.horizontal, 18)
            .frame(maxWidth: 300)
            .frame(height: 50)
            .background(Capsule().fill(Color.white.opacity(0.10)))
    }
}
