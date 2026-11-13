/*
 One line to the Mac's broker and one line back, over a TCP connection that Tailscale carries.
 The broker listens on the tailnet port through `tailscale serve`, which is also what tells it
 that the caller is this phone.
 */

import Foundation
import Network
import PassboxCore

struct Tailnet: Transport {
    /// The broker's port, fixed on the Mac as well
    static let port: NWEndpoint.Port = 8787

    let host: String

    func exchange(_ line: Data, timeout: TimeInterval) async throws -> Data {
        let call = Call(host: host, line: line)
        // A cancelled task takes its connection down with it, so leaving the screen leaves
        // nothing open on the Mac
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                call.start(continuation, timeout: timeout)
            }
        } onCancel: {
            call.finish(.failure(CancellationError()))
        }
    }
}

struct Unreachable: LocalizedError {
    let why: String

    var errorDescription: String? { why }
}

/// One exchange. Network.framework reports on its own queue, a timeout fires on that queue and a
/// cancel arrives from anywhere, so the lock is what makes the continuation resume exactly once
private final class Call: @unchecked Sendable {
    private let connection: NWConnection
    private let line: Data
    private let queue = DispatchQueue(label: "passbox.tailnet")
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data, Error>?
    private var outcome: Result<Data, Error>?
    private var reply = Data()

    init(host: String, line: Data) {
        connection = NWConnection(host: NWEndpoint.Host(host), port: Tailnet.port, using: .tcp)
        self.line = line
    }

    func start(_ continuation: CheckedContinuation<Data, Error>, timeout: TimeInterval) {
        lock.lock()
        // Cancelled before it began
        if let outcome {
            lock.unlock()
            continuation.resume(with: outcome)
            return
        }
        self.continuation = continuation
        lock.unlock()

        connection.stateUpdateHandler = { [weak self] state in
            guard let self else {
                return
            }
            switch state {
            case .ready:
                self.send()
            case .waiting(let error), .failed(let error):
                // Waiting means no route, which on a phone is Tailscale being off
                self.finish(.failure(Unreachable(why: Self.explain(error))))
            default:
                break
            }
        }
        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + timeout) { [weak self] in
            self?.finish(.failure(Unreachable(why: "the Mac did not answer in time")))
        }
    }

    func finish(_ result: Result<Data, Error>) {
        lock.lock()
        guard outcome == nil else {
            lock.unlock()
            return
        }
        outcome = result
        let waiting = continuation
        continuation = nil
        lock.unlock()

        connection.cancel()
        waiting?.resume(with: result)
    }

    private func send() {
        connection.send(
            content: line,
            completion: .contentProcessed { [weak self] error in
                if let error {
                    self?.finish(.failure(Unreachable(why: Self.explain(error))))
                } else {
                    self?.receive()
                }
            })
    }

    /// The reply is one line, so read until its newline or until the Mac closes
    private func receive() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) {
            [weak self] data, _, closed, error in
            guard let self else {
                return
            }
            if let data {
                self.reply.append(data)
            }
            if self.reply.last == UInt8(ascii: "\n") || closed {
                self.finish(.success(self.reply))
            } else if let error {
                self.finish(.failure(Unreachable(why: Self.explain(error))))
            } else {
                self.receive()
            }
        }
    }

    private static func explain(_ error: NWError) -> String {
        "cannot reach the Mac (\(error.localizedDescription)). Is Tailscale on, and the Mac awake?"
    }
}
