import Foundation

public enum ProbeOperation: String, CaseIterable, Sendable {
    case create, reopen, sign, noInteraction, delete
}

public enum ProbeOutcome: String, Sendable {
    case created, reopened, signatureVerified, interactionRequired, deleted
    case missingKey, cancelled, unavailable, failed, unsafe
}

/// This records API observations only; it never claims a human touched a sensor.
public struct AttemptGate {
    public private(set) var active: UUID?
    public private(set) var invalidated = false
    public private(set) var verifiedSignatures = 0
    public private(set) var blockedWithoutInteraction = 0
    public private(set) var unsafeObserved = false
    private var operation: ProbeOperation?

    public init() {}

    public mutating func begin(_ operation: ProbeOperation) -> UUID? {
        guard active == nil else { return nil }
        guard !unsafeObserved || (operation != .sign && operation != .noInteraction) else { return nil }
        let token = UUID()
        active = token
        invalidated = false
        self.operation = operation
        return token
    }

    /// Keep admission closed until the native worker has returned, even on cancel.
    public mutating func cancel() { if active != nil { invalidated = true } }

    public mutating func finish(_ token: UUID, outcome: ProbeOutcome) -> ProbeOutcome? {
        guard active == token else { return nil }
        defer { active = nil; operation = nil; invalidated = false }
        // Cancellation cannot undo a completed Keychain mutation or hide a
        // security failure. Preserve these observations even after invalidation.
        if outcome == .unsafe { unsafeObserved = true; return .unsafe }
        if (operation == .create && outcome == .created)
            || (operation == .delete && outcome == .deleted) {
            verifiedSignatures = 0
            blockedWithoutInteraction = 0
            return outcome
        }
        guard !invalidated else { return .cancelled }
        if operation == .sign && outcome == .signatureVerified { verifiedSignatures += 1 }
        if operation == .noInteraction && outcome == .interactionRequired {
            blockedWithoutInteraction += 1
        }
        return outcome
    }
}

/// Only a specific noninteractive-authentication error establishes this negative.
/// Missing keys, unavailable hardware and generic authentication errors do not.
public func isInteractionRequired(domain: String, code: Int) -> Bool {
    (domain == "NSOSStatusErrorDomain" && code == -25308)
        || (domain == "com.apple.LocalAuthentication" && code == -1004)
}
