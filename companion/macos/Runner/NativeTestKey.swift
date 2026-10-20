import CryptoKit
import Foundation
import LocalAuthentication
import Security

enum NativeTestKey {
    static let tag = Data("dev.vaultwarden.companionSlice.test-key.v1".utf8)

    static func availability() -> Bool {
        let context = LAContext()
        defer { context.invalidate() }
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
            && context.biometryType == .touchID
    }

    static func context(for operation: TestOperation) -> LAContext {
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        context.localizedFallbackTitle = ""
        context.localizedReason = "Sign this synthetic companion request with Touch ID"
        // Keychain lookup/signing never owns an implicit authentication prompt.
        // Only the explicit access-control evaluation below may show one.
        context.interactionNotAllowed = true
        return context
    }

    static func query(_ context: LAContext) -> [String: Any] {
        [kSecClass as String: kSecClassKey,
         kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
         kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
         kSecAttrApplicationTag as String: tag,
         kSecUseDataProtectionKeychain as String: true,
         kSecUseAuthenticationContext as String: context]
    }

    static func perform(_ work: SyntheticWork, context: LAContext,
                        worker: DispatchQueue, completion: @escaping (SignerReply) -> Void) {
        guard work.operation == .sign else {
            completion(performWithoutInteraction(work, context: context))
            return
        }
        // Fetch the stored key's ACL without prompting. Authorize that actual ACL,
        // not a separate device-owner boolean, on the context we can invalidate.
        var attributes = query(context)
        attributes[kSecReturnAttributes as String] = true
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(attributes as CFDictionary, &item)
        guard status == errSecSuccess else {
            context.invalidate()
            completion(status == errSecItemNotFound ? SignerReply(outcome: .missingKey)
                       : classify(.sign, domain: NSOSStatusErrorDomain, code: Int(status)))
            return
        }
        guard let dictionary = item as? [String: Any],
              let access = dictionary[kSecAttrAccessControl as String],
              CFGetTypeID(access as CFTypeRef) == SecAccessControlGetTypeID() else {
            context.invalidate()
            completion(SignerReply(outcome: .failed))
            return
        }
        authorize(work, access: access as! SecAccessControl, context: context, worker: worker) { failure in
            if let failure {
                context.invalidate()
                completion(failure)
            } else {
                // Re-query with this authenticated context after evaluation, so
                // the SecKey captures its credential. Signing must not prompt again.
                completion(performWithoutInteraction(work, context: context))
            }
        }
    }

    /// Callback runs on the worker only after evaluation actually returns.
    /// Invalidating the same context cancels the explicit OS prompt; the caller
    /// must still await this callback before releasing admission.
    static func authorize(_ work: SyntheticWork, access: SecAccessControl, context: LAContext,
                          worker: DispatchQueue, completion: @escaping (SignerReply?) -> Void) {
        guard UInt64(Date().timeIntervalSince1970 * 1000) < work.expiresUnixMs else {
            completion(SignerReply(outcome: .cancelled))
            return
        }
        context.interactionNotAllowed = false
        context.evaluateAccessControl(access, operation: .useKeySign,
                                      localizedReason: "Sign synthetic request \(work.fixture) with Touch ID") { success, error in
            worker.async {
                if success {
                    context.interactionNotAllowed = true
                    completion(nil)
                } else if let error = error as NSError? {
                    completion(classify(.sign, domain: error.domain, code: error.code))
                } else {
                    completion(SignerReply(outcome: .failed))
                }
            }
        }
    }

    private static func performWithoutInteraction(_ work: SyntheticWork, context: LAContext) -> SignerReply {
        defer { context.invalidate() }
        if work.operation == .create { return create(context) }
        if work.operation == .delete {
            let status = SecItemDelete(query(context) as CFDictionary)
            return SignerReply(outcome: deletionOutcome(status))
        }
        var attributes = query(context)
        attributes[kSecReturnRef as String] = true
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(attributes as CFDictionary, &item)
        guard status == errSecSuccess, let item else {
            if status == errSecItemNotFound { return SignerReply(outcome: .missingKey) }
            return classify(work.operation, domain: NSOSStatusErrorDomain, code: Int(status))
        }
        guard CFGetTypeID(item) == SecKeyGetTypeID() else { return SignerReply(outcome: .failed) }
        let key = item as! SecKey
        guard let keyAttributes = SecKeyCopyAttributes(key) as? [String: Any],
              keyAttributes[kSecAttrTokenID as String] as? String == kSecAttrTokenIDSecureEnclave as String,
              keyAttributes[kSecAttrAccessControl as String] != nil,
              let publicKey = SecKeyCopyPublicKey(key),
              let publicData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?,
              publicData.count == 65 else { return SignerReply(outcome: .unsafe) }
        if work.operation == .reopen { return SignerReply(outcome: .reopened, publicKey: publicData) }
        guard SHA256.hash(data: publicData).withUnsafeBytes({ Data($0) }) == work.keyID else {
            return SignerReply(outcome: .failed)
        }
        guard UInt64(Date().timeIntervalSince1970 * 1000) < work.expiresUnixMs else {
            return SignerReply(outcome: .cancelled)
        }
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256,
                                                    work.transcript() as CFData, &error) else {
            guard let failure = error?.takeRetainedValue() else { return SignerReply(outcome: .failed) }
            return classify(work.operation, domain: CFErrorGetDomain(failure) as String, code: CFErrorGetCode(failure))
        }
        // Rust verifies the proof. No local authenticated boolean grants authority.
        return SignerReply(outcome: work.operation == .noInteraction ? .unsafe : .verified,
                           signature: signature as Data)
    }

    static func deletionOutcome(_ status: OSStatus) -> TestOutcome {
        // Only an explicit deletion retires an already absent identity.
        status == errSecSuccess || status == errSecItemNotFound ? .deleted : .failed
    }

    private static func create(_ context: LAContext) -> SignerReply {
        guard availability() else { return SignerReply(outcome: .unavailable) }
        var existing = query(context)
        existing[kSecReturnAttributes as String] = true
        guard SecItemCopyMatching(existing as CFDictionary, nil) == errSecItemNotFound else {
            return SignerReply(outcome: .failed)
        }
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                          [.privateKeyUsage, .biometryCurrentSet], nil) else {
            return SignerReply(outcome: .failed)
        }
        let attributes: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256, kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain as String: true, kSecUseAuthenticationContext as String: context,
            kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag, kSecAttrAccessControl as String: access]]
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, nil) else { return SignerReply(outcome: .failed) }
        guard let publicKey = SecKeyCopyPublicKey(key),
              let publicData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
            // Creation happened: don't delete or overwrite to recover automatically.
            return SignerReply(outcome: .unsafe)
        }
        return SignerReply(outcome: .created, publicKey: publicData)
    }

    static func classify(_ operation: TestOperation, domain: String, code: Int) -> SignerReply {
        if operation == .noInteraction && isInteractionRequired(domain: domain, code: code) {
            return SignerReply(outcome: .interactionRequired)
        }
        if (domain == NSOSStatusErrorDomain && code == Int(errSecUserCanceled))
            || (domain == LAError.errorDomain && [LAError.userCancel.rawValue,
                LAError.appCancel.rawValue, LAError.systemCancel.rawValue,
                LAError.invalidContext.rawValue].contains(code)) {
            return SignerReply(outcome: .cancelled)
        }
        return SignerReply(outcome: .failed)
    }
}
