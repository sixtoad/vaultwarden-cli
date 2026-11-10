import CryptoKit
import Foundation
import LocalAuthentication
import Security
import XCTest
@testable import NativeContract

/// Production approval v2 contract against the provider's golden vector
/// (`tests/fixtures/approval-v2-golden.json`, verify only, no private key).
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

    func testGoldenApprovalAndEnrollmentTranscriptsAreAdmittedOnlyForTheirPurpose() throws {
        let approval = try transcript("approval"), enroll = try transcript("enroll")
        XCTAssertTrue(ProductionTranscript.admits(approval, purpose: .approve, binding: binding, publicKey: publicKey))
        XCTAssertTrue(ProductionTranscript.admits(enroll, purpose: .enroll, binding: binding, publicKey: publicKey))
        XCTAssertFalse(ProductionTranscript.admits(approval, purpose: .enroll, binding: binding, publicKey: publicKey))
        XCTAssertFalse(ProductionTranscript.admits(enroll, purpose: .approve, binding: binding, publicKey: publicKey))
        // The golden signatures verify over exactly these bytes.
        let key = try P256.Signing.PublicKey(x963Representation: publicKey)
        for section in ["approval", "enroll"] {
            let value = try XCTUnwrap(golden[section] as? [String: Any])
            let der = try XCTUnwrap(base64url(value["signature"] as? String))
            XCTAssertTrue(key.isValidSignature(try P256.Signing.ECDSASignature(derRepresentation: der),
                                               for: try transcript(section)))
        }
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

    func testEveryBindingFieldIsChecked() throws {
        let approval = try XCTUnwrap(ProductionTranscript.fields(try transcript("approval")))
        let enroll = try XCTUnwrap(ProductionTranscript.fields(try transcript("enroll")))
        for index in 0..<approval.count {
            var mutated = approval
            mutated[index] = index == 5 ? Data(repeating: 0x41, count: 42) : mutated[index] + Data([0])
            XCTAssertFalse(ProductionTranscript.admits(frame(mutated), purpose: .approve, binding: binding,
                                                       publicKey: publicKey), "approval field \(index)")
        }
        for index in 0..<enroll.count {
            var mutated = enroll
            mutated[index] = mutated[index] + Data([0])
            XCTAssertFalse(ProductionTranscript.admits(frame(mutated), purpose: .enroll, binding: binding,
                                                       publicKey: publicKey), "enroll field \(index)")
        }
        var action = approval
        action[1] = Data("deny".utf8)
        XCTAssertFalse(ProductionTranscript.admits(frame(action), purpose: .approve, binding: binding, publicKey: publicKey))
        // Another provider, another client or another key never signs.
        let other = try ProductionBinding(providerIdentity: Data(repeating: 0x99, count: 32),
                                          approvalClient: binding.approvalClient)
        let client = try ProductionBinding(providerIdentity: binding.providerIdentity,
                                           approvalClient: Data(repeating: 0x99, count: 32))
        for b in [other, client] {
            XCTAssertFalse(ProductionTranscript.admits(try transcript("approval"), purpose: .approve, binding: b, publicKey: publicKey))
            XCTAssertFalse(ProductionTranscript.admits(try transcript("enroll"), purpose: .enroll, binding: b, publicKey: publicKey))
            XCTAssertNotEqual(b.tag, binding.tag)
        }
        var otherKey = publicKey
        otherKey[64] ^= 1
        XCTAssertFalse(ProductionTranscript.admits(try transcript("approval"), purpose: .approve, binding: binding, publicKey: otherKey))
        XCTAssertFalse(ProductionTranscript.admits(try transcript("enroll"), purpose: .enroll, binding: binding, publicKey: otherKey))
        // Framing: trailing, truncated and extra fields are refused.
        let full = try transcript("approval")
        XCTAssertFalse(ProductionTranscript.admits(full + Data([0]), purpose: .approve, binding: binding, publicKey: publicKey))
        XCTAssertFalse(ProductionTranscript.admits(full.dropLast(), purpose: .approve, binding: binding, publicKey: publicKey))
        XCTAssertFalse(ProductionTranscript.admits(frame(approval + [Data()]), purpose: .approve, binding: binding, publicKey: publicKey))
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
