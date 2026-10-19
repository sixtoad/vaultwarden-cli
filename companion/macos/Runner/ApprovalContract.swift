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
