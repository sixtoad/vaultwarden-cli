import CryptoKit
import Foundation
import LocalAuthentication
import Security

enum ProductionOutcome: String {
    case present, absent, created, deleted, signed
    case cancelled, unavailable, missingKey, refused, failed, unsafe
}

struct ProductionReply {
    var outcome: ProductionOutcome
    var publicKey = Data()
    var signature = Data()
}

/// The production approval key: a non-exportable Secure Enclave P-256 key,
/// one per `ProductionBinding`, usable only after Touch ID on the CURRENT
/// enrolled finger set (`.biometryCurrentSet`: adding or removing a finger
/// invalidates it, and it must be enrolled again). Every signature evaluates
/// the key's access control on a fresh `LAContext` with no reuse window, so
/// each approval needs its own touch. There is no device-passcode fallback in
/// the prompt; the companion's explicit password approval is the fallback.
enum ProductionApprovalKey {
    static func availability() -> Bool { NativeTestKey.availability() }

    static func context() -> LAContext {
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0
        context.localizedFallbackTitle = ""
        context.interactionNotAllowed = true
        return context
    }

    static func query(_ binding: ProductionBinding, _ context: LAContext) -> [String: Any] {
        [kSecClass as String: kSecClassKey,
         kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
         kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
         kSecAttrApplicationTag as String: binding.tag,
         kSecUseDataProtectionKeychain as String: true,
         kSecUseAuthenticationContext as String: context]
    }

    static func accessFlags() -> SecAccessControlCreateFlags { [.privateKeyUsage, .biometryCurrentSet] }

    /// The stored key and its public point, without any prompt.
    static func read(_ binding: ProductionBinding) -> ProductionReply {
        let context = context()
        defer { context.invalidate() }
        switch lookup(binding, context) {
        case .failure(let reply): return reply
        case .found(_, let publicKey, _): return ProductionReply(outcome: .present, publicKey: publicKey)
        }
    }

    /// Creates the key. Refuses when one exists: replacing a key is an
    /// explicit delete first, never an implicit overwrite.
    static func create(_ binding: ProductionBinding) -> ProductionReply {
        guard availability() else { return ProductionReply(outcome: .unavailable) }
        let context = context()
        defer { context.invalidate() }
        var existing = query(binding, context)
        existing[kSecReturnAttributes as String] = true
        guard SecItemCopyMatching(existing as CFDictionary, nil) == errSecItemNotFound else {
            return ProductionReply(outcome: .refused)
        }
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                          accessFlags(), nil) else {
            return ProductionReply(outcome: .failed)
        }
        let attributes: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256, kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain as String: true, kSecUseAuthenticationContext as String: context,
            kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: binding.tag, kSecAttrAccessControl as String: access]]
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, nil) else {
            return ProductionReply(outcome: .failed)
        }
        guard let publicKey = SecKeyCopyPublicKey(key),
              let data = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?, data.count == 65 else {
            return ProductionReply(outcome: .unsafe)
        }
        return ProductionReply(outcome: .created, publicKey: data)
    }

    static func delete(_ binding: ProductionBinding) -> ProductionReply {
        let context = context()
        defer { context.invalidate() }
        let status = SecItemDelete(query(binding, context) as CFDictionary)
        return ProductionReply(outcome: status == errSecSuccess || status == errSecItemNotFound ? .deleted : .failed)
    }

    /// Touch ID, then one signature over `transcript`, which must be admitted
    /// by `ProductionTranscript.admits` for this key. The completion runs on
    /// `worker` after the OS prompt has returned.
    static func sign(_ binding: ProductionBinding, purpose: ProductionPurpose, transcript: Data,
                     reason: String, context: LAContext, worker: DispatchQueue,
                     completion: @escaping (ProductionReply) -> Void) {
        let access: SecAccessControl
        switch lookup(binding, context) {
        case .failure(let reply):
            context.invalidate(); completion(reply); return
        case .found(_, let publicKey, let control):
            guard ProductionTranscript.admits(transcript, purpose: purpose, binding: binding, publicKey: publicKey) else {
                context.invalidate(); completion(ProductionReply(outcome: .refused)); return
            }
            access = control
        }
        context.interactionNotAllowed = false
        context.evaluateAccessControl(access, operation: .useKeySign, localizedReason: reason) { success, error in
            worker.async {
                guard success else {
                    context.invalidate()
                    let failure = error as NSError?
                    completion(classify(domain: failure?.domain ?? "", code: failure?.code ?? 0))
                    return
                }
                context.interactionNotAllowed = true
                completion(signAuthenticated(binding, purpose: purpose, transcript: transcript, context: context))
            }
        }
    }

    private static func signAuthenticated(_ binding: ProductionBinding, purpose: ProductionPurpose,
                                          transcript: Data, context: LAContext) -> ProductionReply {
        defer { context.invalidate() }
        // Re-query with the authenticated context; signing must not prompt again.
        guard case .found(let key, let publicKey, _) = lookup(binding, context),
              ProductionTranscript.admits(transcript, purpose: purpose, binding: binding, publicKey: publicKey) else {
            return ProductionReply(outcome: .refused)
        }
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256,
                                                    transcript as CFData, &error) as Data? else {
            guard let failure = error?.takeRetainedValue() else { return ProductionReply(outcome: .failed) }
            return classify(domain: CFErrorGetDomain(failure) as String, code: CFErrorGetCode(failure))
        }
        guard (8...72).contains(signature.count) else { return ProductionReply(outcome: .failed) }
        return ProductionReply(outcome: .signed, publicKey: publicKey, signature: signature)
    }

    enum Lookup {
        case found(SecKey, Data, SecAccessControl)
        case failure(ProductionReply)
    }

    static func lookup(_ binding: ProductionBinding, _ context: LAContext) -> Lookup {
        var attributes = query(binding, context)
        attributes[kSecReturnRef as String] = true
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(attributes as CFDictionary, &item)
        guard status == errSecSuccess, let item else {
            return .failure(ProductionReply(outcome: status == errSecItemNotFound ? .absent : .failed))
        }
        guard CFGetTypeID(item) == SecKeyGetTypeID() else { return .failure(ProductionReply(outcome: .failed)) }
        let key = item as! SecKey
        // Only a Secure Enclave key with an access control is acceptable.
        guard let keyAttributes = SecKeyCopyAttributes(key) as? [String: Any],
              keyAttributes[kSecAttrTokenID as String] as? String == kSecAttrTokenIDSecureEnclave as String,
              let control = keyAttributes[kSecAttrAccessControl as String],
              CFGetTypeID(control as CFTypeRef) == SecAccessControlGetTypeID(),
              let publicKey = SecKeyCopyPublicKey(key),
              let data = SecKeyCopyExternalRepresentation(publicKey, nil) as Data?,
              data.count == 65 else { return .failure(ProductionReply(outcome: .unsafe)) }
        return .found(key, data, control as! SecAccessControl)
    }

    static func classify(domain: String, code: Int) -> ProductionReply {
        if (domain == NSOSStatusErrorDomain && code == Int(errSecUserCanceled))
            || (domain == LAError.errorDomain && [LAError.userCancel.rawValue, LAError.appCancel.rawValue,
                LAError.systemCancel.rawValue, LAError.invalidContext.rawValue,
                LAError.userFallback.rawValue].contains(code)) {
            return ProductionReply(outcome: .cancelled)
        }
        if domain == LAError.errorDomain && [LAError.biometryNotAvailable.rawValue,
            LAError.biometryNotEnrolled.rawValue, LAError.biometryLockout.rawValue,
            LAError.passcodeNotSet.rawValue].contains(code) {
            return ProductionReply(outcome: .unavailable)
        }
        return ProductionReply(outcome: .failed)
    }
}
