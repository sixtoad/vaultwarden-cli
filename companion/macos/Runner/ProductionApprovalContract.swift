import CryptoKit
import Foundation

/// Production Touch ID approval v2 (issue 49). The Secure Enclave key signs
/// only transcripts that Rust built for the provider's v2 verifier, and only
/// when the framed fields bind it to its own provider and approval client.
/// This is a second line of defence: Rust and the provider remain the
/// authorities. The synthetic demonstration contract
/// (`dev.vaultwarden.companion.synthetic.v1`, `NativeTestKey`) never reaches
/// this code and this key never signs its transcripts.
enum ProductionDomain {
    static let approval = Data("dev.vaultwarden.provider.approval.v2".utf8)
    static let enroll = Data("dev.vaultwarden.provider.approval-enroll.v2".utf8)
    static let synthetic = Data("dev.vaultwarden.companion.synthetic.v1".utf8)
}

enum ProductionPurpose: String { case approve, enroll }

/// One Secure Enclave key per (provider identity, approval client): the two
/// SHA-256 pins the companion uses for the provider TLS leaf and its own
/// client mTLS leaf. A provider certificate rotation or a new client identity
/// therefore selects another key, which has to be enrolled again.
struct ProductionBinding: Equatable {
    static let tagPrefix = "dev.vaultwarden.companion.approval-v2.key."
    let providerIdentity: Data
    let approvalClient: Data

    init(providerIdentity: Data, approvalClient: Data) throws {
        guard providerIdentity.count == 32, approvalClient.count == 32 else { throw ContractError.invalid }
        self.providerIdentity = providerIdentity
        self.approvalClient = approvalClient
    }

    init(providerHex: String, clientHex: String) throws {
        guard let provider = Data(lowerHex: providerHex), let client = Data(lowerHex: clientHex) else {
            throw ContractError.invalid
        }
        try self.init(providerIdentity: provider, approvalClient: client)
    }

    /// Keychain application tag. Disjoint from the synthetic test key tag.
    var tag: Data {
        let digest = SHA256.hash(data: providerIdentity + approvalClient)
        return Data((Self.tagPrefix + digest.map { String(format: "%02x", $0) }.joined()).utf8)
    }
}

enum ProductionTranscript {
    /// Splits 4-byte big-endian length framing. Nil on any trailing or short bytes.
    static func fields(_ data: Data) -> [Data]? {
        var fields: [Data] = []
        var index = data.startIndex
        while index < data.endIndex {
            guard data.endIndex - index >= 4 else { return nil }
            let length = data[index..<index + 4].reduce(0) { ($0 << 8) | Int($1) }
            index += 4
            guard length <= data.endIndex - index else { return nil }
            fields.append(Data(data[index..<index + length]))
            index += length
            guard fields.count <= 32 else { return nil }
        }
        return fields
    }

    /// Whether the production key bound to `binding`, whose public key is
    /// `publicKey` (65-byte SEC1), may sign `transcript` for `purpose`.
    static func admits(_ transcript: Data, purpose: ProductionPurpose,
                       binding: ProductionBinding, publicKey: Data) -> Bool {
        guard publicKey.count == 65, publicKey.first == 0x04, let f = fields(transcript) else { return false }
        switch purpose {
        case .approve:
            let keyID = Data(SHA256.hash(data: publicKey))
            let sizes = [32, 32, 32, 8, 8, 32, 8, 32] // record, policy, arguments, expiry, generation, ticket, deadline, review
            return f.count == 14
                && f[0] == ProductionDomain.approval && f[1] == Data("approve".utf8)
                && f[2] == binding.providerIdentity && f[3] == binding.approvalClient
                && f[4] == keyID && f[5].count == 43
                && zip(f[6...], sizes).allSatisfy { $0.count == $1 }
        case .enroll:
            return f.count == 6
                && f[0] == ProductionDomain.enroll
                && f[1] == binding.providerIdentity && f[2] == binding.approvalClient
                && f[3] == publicKey && f[4].count == 32 && f[5].count == 43
        }
    }
}

extension Data {
    init?(lowerHex: String) {
        guard lowerHex.count % 2 == 0,
              lowerHex.allSatisfy({ ("0"..."9").contains($0) || ("a"..."f").contains($0) }) else { return nil }
        var bytes = [UInt8]()
        var index = lowerHex.startIndex
        while index < lowerHex.endIndex {
            let next = lowerHex.index(index, offsetBy: 2)
            guard let byte = UInt8(lowerHex[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }
}
