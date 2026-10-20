import Foundation

enum TestOperation: String { case create, reopen, delete, sign, noInteraction }
enum TestOutcome: String { case created, reopened, deleted, verified, interactionRequired, cancelled, unavailable, missingKey, failed, unsafe }

struct SignerReply {
    var outcome: TestOutcome
    var publicKey = Data()
    var signature = Data()
}

/// Native code accepts a typed synthetic request, never arbitrary message bytes.
struct SyntheticWork {
    let token: UInt32
    let epoch: UInt32
    let operation: TestOperation
    let fixture: UInt32
    let expiresUnixMs: UInt64
    let nonce: Data
    let keyID: Data

    init(token: UInt32, epoch: UInt32, operation: TestOperation, fixture: UInt32,
         expiresUnixMs: UInt64, nonce: Data, keyID: Data) throws {
        guard token > 0, [1, 2].contains(fixture), nonce.count == 32, keyID.count == 32 else {
            throw ContractError.invalid
        }
        self.token = token; self.epoch = epoch; self.operation = operation; self.fixture = fixture
        self.expiresUnixMs = expiresUnixMs; self.nonce = nonce; self.keyID = keyID
    }

    func transcript() -> Data {
        let title = fixture == 1 ? "Synthetic request one" : "Synthetic request two"
        let detail = fixture == 1
            ? "Demonstrate a local signature only. No vault, provider or execution."
            : "Demonstrate another fresh signature only. No vault, provider or execution."
        let fields = [Data("dev.vaultwarden.companion.synthetic.v1".utf8), Data("sign".utf8),
                      bytes(fixture), Data(title.utf8), Data(detail.utf8), bytes(epoch),
                      bytes(token), bytes(expiresUnixMs), nonce, keyID]
        var result = Data()
        for field in fields { result.append(bytes(UInt32(field.count))); result.append(field) }
        return result
    }
}

enum ContractError: Error { case invalid }

private func bytes<T: FixedWidthInteger>(_ value: T) -> Data {
    var value = value.bigEndian
    return withUnsafeBytes(of: &value) { Data($0) }
}

func isInteractionRequired(domain: String, code: Int) -> Bool {
    (domain == "NSOSStatusErrorDomain" && code == -25308)
        || (domain == "com.apple.LocalAuthentication" && code == -1004)
}

/// Main-thread platform worker ownership, shared with harmless native tests.
/// It cannot sign or approve; Rust still validates the returned proof.
struct NativeAttemptSlot {
    private struct Active {
        let token: UInt32
        let epoch: UInt32
        let cancel: () -> Void
        var invalidated = false
    }
    private var active: Active?
    private var lastToken: UInt32 = 0
    var isBusy: Bool { active != nil }

    mutating func begin(_ work: SyntheticWork, cancel: @escaping () -> Void) -> Bool {
        guard active == nil, work.token > lastToken else { return false }
        lastToken = work.token
        active = Active(token: work.token, epoch: work.epoch, cancel: cancel)
        return true
    }

    mutating func invalidate(token: UInt32? = nil) {
        guard let current = active, token == nil || token == current.token else { return }
        active?.invalidated = true
        current.cancel()
    }

    mutating func finish(token: UInt32, epoch: UInt32, reply: SignerReply) -> SignerReply? {
        guard let current = active, current.token == token, current.epoch == epoch else { return nil }
        defer { active = nil }
        if current.invalidated && reply.outcome == .verified {
            return SignerReply(outcome: .cancelled)
        }
        // Key mutations cannot be undone, and unsafe evidence must survive cancel.
        return reply
    }
}
