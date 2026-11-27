import CryptoKit
import Foundation
import LocalAuthentication
import Security
import XCTest
@testable import NativeContract

/// Production approval v2 contract: the native signer guard against the
/// shared admission vectors, the synthetic-domain separation, the key binding
/// tag and the key access control. The signature check is Rust's
/// (shared-approval-checks-spec S-3).
final class ProductionContractTests: XCTestCase {
    private var golden: [String: Any] = [:]
    private var publicKey = Data()
    private var binding: ProductionBinding!

    override func setUpWithError() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let data = try Data(contentsOf: root.appendingPathComponent("tests/fixtures/approval-v2-golden.json"))
        golden = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        publicKey = try XCTUnwrap(base64url(golden["public_key"] as? String))
        let approval = try XCTUnwrap(golden["approval"] as? [String: Any])
        binding = try ProductionBinding(providerHex: try XCTUnwrap(approval["provider_identity"] as? String),
                                        clientHex: try XCTUnwrap(approval["approval_client"] as? String))
    }

    private func transcript(_ section: String) throws -> Data {
        let value = try XCTUnwrap(golden[section] as? [String: Any])
        return try XCTUnwrap(Data(lowerHex: try XCTUnwrap(value["transcript_hex"] as? String)))
    }

    private func base64url(_ text: String?) -> Data? {
        guard var text else { return nil }
        text = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while text.count % 4 != 0 { text += "=" }
        return Data(base64Encoded: text)
    }

    /// The shared admission vectors (`companion/fixtures/approval-v2-admission.json`,
    /// generated and checked by the Rust reference, shared-approval-checks-spec
    /// S-2): this native guard must give every case the Rust verdict.
    func testEverySharedAdmissionVectorGetsTheRustVerdict() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let data = try Data(contentsOf: root.appendingPathComponent("companion/fixtures/approval-v2-admission.json"))
        let document = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let cases = try XCTUnwrap(document["cases"] as? [[String: Any]])
        XCTAssertGreaterThan(cases.count, 40)
        var admitted = 0
        for vector in cases {
            let name = try XCTUnwrap(vector["name"] as? String)
            let purpose = try XCTUnwrap((vector["purpose"] as? String).flatMap(ProductionPurpose.init(rawValue:)))
            let binding = try ProductionBinding(providerHex: try XCTUnwrap(vector["provider_identity"] as? String),
                                                clientHex: try XCTUnwrap(vector["approval_client"] as? String))
            let key = try XCTUnwrap(Data(lowerHex: try XCTUnwrap(vector["public_key_hex"] as? String)))
            let transcript = try XCTUnwrap(Data(lowerHex: try XCTUnwrap(vector["transcript_hex"] as? String)))
            let expected = try XCTUnwrap(vector["admitted"] as? Bool)
            XCTAssertEqual(ProductionTranscript.admits(transcript, purpose: purpose, binding: binding, publicKey: key),
                           expected, name)
            if expected { admitted += 1 }
        }
        XCTAssertEqual(admitted, 4, "only the golden transcripts and their sized-field variants")
    }

    func testProductionKeyRefusesSyntheticTranscriptsAndTheReverse() throws {
        let synthetic = try SyntheticWork(token: 9, epoch: 7, operation: .sign, fixture: 1,
            expiresUnixMs: 1_700_000_000_000, nonce: Data(repeating: 0x11, count: 32),
            keyID: Data(SHA256.hash(data: publicKey))).transcript()
        for purpose in [ProductionPurpose.approve, .enroll] {
            XCTAssertFalse(ProductionTranscript.admits(synthetic, purpose: purpose, binding: binding, publicKey: publicKey))
        }
        // A v2 transcript relabelled with the synthetic domain is refused too.
        var fields = try XCTUnwrap(ProductionTranscript.fields(try transcript("approval")))
        XCTAssertEqual(fields[0], ProductionDomain.approval)
        fields[0] = ProductionDomain.synthetic
        XCTAssertFalse(ProductionTranscript.admits(frame(fields), purpose: .approve, binding: binding, publicKey: publicKey))
        // Synthetic work can only produce synthetic-domain bytes.
        XCTAssertEqual(ProductionTranscript.fields(synthetic)?.first, ProductionDomain.synthetic)
        // Keychain namespaces are disjoint: neither tag can name the other key.
        XCTAssertNotEqual(binding.tag, NativeTestKey.tag)
        XCTAssertTrue(String(decoding: binding.tag, as: UTF8.self).hasPrefix(ProductionBinding.tagPrefix))
        XCTAssertFalse(String(decoding: NativeTestKey.tag, as: UTF8.self).hasPrefix(ProductionBinding.tagPrefix))
    }

    func testAnotherBindingSelectsAnotherKeyTag() throws {
        let other = try ProductionBinding(providerIdentity: Data(repeating: 0x99, count: 32),
                                          approvalClient: binding.approvalClient)
        let client = try ProductionBinding(providerIdentity: binding.providerIdentity,
                                           approvalClient: Data(repeating: 0x99, count: 32))
        XCTAssertNotEqual(other.tag, binding.tag)
        XCTAssertNotEqual(client.tag, binding.tag)
    }

    func testBindingParsingAndAccessControl() {
        XCTAssertThrowsError(try ProductionBinding(providerHex: String(repeating: "A", count: 64),
                                                    clientHex: String(repeating: "a", count: 64)))
        XCTAssertThrowsError(try ProductionBinding(providerHex: String(repeating: "a", count: 62),
                                                    clientHex: String(repeating: "a", count: 64)))
        XCTAssertEqual(ProductionApprovalKey.accessFlags(), [.privateKeyUsage, .biometryCurrentSet])
        let context = ProductionApprovalKey.context()
        XCTAssertEqual(context.touchIDAuthenticationAllowableReuseDuration, 0)
        XCTAssertEqual(context.localizedFallbackTitle, "")
        XCTAssertTrue(context.interactionNotAllowed)
        XCTAssertEqual(ProductionApprovalKey.classify(domain: LAError.errorDomain, code: LAError.userCancel.rawValue).outcome, .cancelled)
        XCTAssertEqual(ProductionApprovalKey.classify(domain: LAError.errorDomain, code: LAError.userFallback.rawValue).outcome, .cancelled)
        XCTAssertEqual(ProductionApprovalKey.classify(domain: LAError.errorDomain, code: LAError.biometryLockout.rawValue).outcome, .unavailable)
        XCTAssertEqual(ProductionApprovalKey.classify(domain: NSOSStatusErrorDomain, code: Int(errSecAuthFailed)).outcome, .failed)
    }

    private func frame(_ fields: [Data]) -> Data {
        var data = Data()
        for field in fields {
            var length = UInt32(field.count).bigEndian
            data.append(Data(bytes: &length, count: 4))
            data.append(field)
        }
        return data
    }
}
