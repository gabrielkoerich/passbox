#if DEBUG
    import Foundation

    /// `-demo connected|request|settings|pairing` puts a debug build on that screen with no Mac
    enum Demo {
        static let state: String? = {
            let arguments = ProcessInfo.processInfo.arguments
            guard let at = arguments.firstIndex(of: "-demo"), at + 1 < arguments.count else {
                return nil
            }
            return arguments[at + 1]
        }()
    }
#endif
