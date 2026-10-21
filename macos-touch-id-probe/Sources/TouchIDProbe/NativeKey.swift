import CryptoKit
import Foundation
import LocalAuthentication
import ProbeCore
import Security

struct NativeResult {
    let outcome: ProbeOutcome
    var fingerprint: String? = nil
}

enum NativeKey {
    // Exact dedicated test tag. Never query/delete other application identities.
    static let tag = Data("dev.vaultwarden.TouchIDProbe.disposable.v1".utf8)

    static func query(_ context: LAContext) -> [String: Any] {
        [kSecClass as String: kSecClassKey,
         kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
         kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
         kSecAttrApplicationTag as String: tag,
         kSecUseDataProtectionKeychain as String: true,
         kSecUseAuthenticationContext as String: context]
    }

    static func perform(_ operation: ProbeOperation, context: LAContext) -> NativeResult {
        defer { context.invalidate() }
        if operation == .create { return create(context) }
        if operation == .delete {
            let status = SecItemDelete(query(context) as CFDictionary)
            return NativeResult(outcome: status == errSecSuccess ? .deleted :
                                    status == errSecItemNotFound ? .missingKey : .failed)
        }
        var attributes = query(context)
        attributes[kSecReturnRef as String] = true
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(attributes as CFDictionary, &item)
        guard status == errSecSuccess, let item else {
            if status == errSecItemNotFound { return NativeResult(outcome: .missingKey) }
            return classify(operation, domain: NSOSStatusErrorDomain, code: Int(status))
        }
        guard CFGetTypeID(item) == SecKeyGetTypeID() else { return NativeResult(outcome: .failed) }
        let key = item as! SecKey
        guard let keyAttributes = SecKeyCopyAttributes(key) as? [String: Any],
              keyAttributes[kSecAttrTokenID as String] as? String == kSecAttrTokenIDSecureEnclave as String,
              let publicKey = SecKeyCopyPublicKey(key),
              let publicData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            return NativeResult(outcome: .unsafe)
        }
        let fingerprint = SHA256.hash(data: publicData).map { String(format: "%02x", $0) }.joined()
        if operation == .reopen { return NativeResult(outcome: .reopened, fingerprint: fingerprint) }
        // Synthetic, internally generated message only; no API for arbitrary signing.
        let message = Data(("vw-touch-id-feasibility-v1:" + UUID().uuidString).utf8)
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256,
                                                    message as CFData, &error) else {
            guard let failure = error?.takeRetainedValue() else { return NativeResult(outcome: .failed) }
            return classify(operation, domain: CFErrorGetDomain(failure) as String,
                            code: CFErrorGetCode(failure))
        }
        // Signing without an interactive authentication context is a failed security gate.
        guard operation == .sign else { return NativeResult(outcome: .unsafe) }
        let valid = SecKeyVerifySignature(publicKey, .ecdsaSignatureMessageX962SHA256,
                                           message as CFData, signature, nil)
        let tampered = SecKeyVerifySignature(publicKey, .ecdsaSignatureMessageX962SHA256,
                                              Data("different synthetic message".utf8) as CFData,
                                              signature, nil)
        return NativeResult(outcome: valid && !tampered ? .signatureVerified : .unsafe,
                            fingerprint: fingerprint)
    }

    private static func create(_ context: LAContext) -> NativeResult {
        var failure: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &failure),
              context.biometryType == .touchID else { return NativeResult(outcome: .unavailable) }
        // Never replace an existing test key, including one we cannot currently access.
        var existing = query(context)
        existing[kSecReturnAttributes as String] = true
        let found = SecItemCopyMatching(existing as CFDictionary, nil)
        guard found == errSecItemNotFound else { return NativeResult(outcome: .failed) }
        guard let access = SecAccessControlCreateWithFlags(nil,
                    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                    [.privateKeyUsage, .biometryCurrentSet], nil) else {
            return NativeResult(outcome: .failed)
        }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain as String: true,
            kSecUseAuthenticationContext as String: context,
            kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access]
        ]
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, nil) else {
            return NativeResult(outcome: .failed)
        }
        // A Secure Enclave private key must not expose its raw private bytes.
        guard SecKeyCopyExternalRepresentation(key, nil) == nil else {
            return NativeResult(outcome: .unsafe)
        }
        return NativeResult(outcome: .created)
    }

    private static func classify(_ operation: ProbeOperation, domain: String, code: Int) -> NativeResult {
        if operation == .noInteraction && isInteractionRequired(domain: domain, code: code) {
            return NativeResult(outcome: .interactionRequired)
        }
        if (domain == NSOSStatusErrorDomain && code == Int(errSecUserCanceled))
            || (domain == LAError.errorDomain && [LAError.userCancel.rawValue,
                LAError.appCancel.rawValue, LAError.systemCancel.rawValue].contains(code)) {
            return NativeResult(outcome: .cancelled)
        }
        return NativeResult(outcome: .failed)
    }
}
