import CryptoKit
import Foundation
import Security

public struct ProviderConfiguration: Codable, Sendable {
    public let endpoint: URL
    public let trustedCA: Data
    public let leafSHA256: String
    public let identityReference: Data
    public init(endpoint: URL, trustedCA: Data, leafSHA256: String, identityReference: Data) throws {
        guard endpoint.scheme == "https", let host = endpoint.host, !host.isEmpty,
              endpoint.user == nil, endpoint.password == nil, endpoint.query == nil, endpoint.fragment == nil,
              ["", "/", "/v1/companion"].contains(endpoint.path),
              validHex(leafSHA256, count: 64), !identityReference.isEmpty,
              SecCertificateCreateWithData(nil, trustedCA as CFData) != nil else { throw CompanionError.configuration }
        var parts = URLComponents(url: endpoint, resolvingAgainstBaseURL: false)!
        parts.path = "/v1/companion"
        self.endpoint = parts.url!; self.trustedCA = trustedCA
        self.leafSHA256 = leafSHA256; self.identityReference = identityReference
    }
    public func validated() throws -> Self {
        try Self(endpoint: endpoint, trustedCA: trustedCA, leafSHA256: leafSHA256, identityReference: identityReference)
    }
}

public enum KeychainIdentity {
    /// PKCS#12 is imported into the operator's Keychain; only its opaque persistent reference is saved in preferences.
    public static func importPKCS12(_ data: Data, passphrase: String, keychain: SecKeychain? = nil) throws -> Data {
        var options: [String: Any] = [kSecImportExportPassphrase as String: passphrase]
        if let keychain { options[kSecImportExportKeychain as String] = keychain }
        var items: CFArray?
        guard SecPKCS12Import(data as CFData, options as CFDictionary, &items) == errSecSuccess,
              let first = (items as? [[String: Any]])?.first,
              let identityValue = first[kSecImportItemIdentity as String] else { throw CompanionError.configuration }
        let identity = identityValue as! SecIdentity
        var reference: CFTypeRef?
        let query: [String: Any] = [kSecClass as String: kSecClassIdentity,
                                   kSecMatchItemList as String: [identity],
                                   kSecReturnPersistentRef as String: true]
        guard SecItemCopyMatching(query as CFDictionary, &reference) == errSecSuccess,
              let reference = reference as? Data else { throw CompanionError.configuration }
        // Keychain certificate uniqueness can reject a renewed certificate that
        // collides with an older issuer/serial. Never return that older identity.
        var importedCertificate: SecCertificate?
        var persistedCertificate: SecCertificate?
        let persistedIdentity = try resolve(reference)
        guard SecIdentityCopyCertificate(identity, &importedCertificate) == errSecSuccess,
              SecIdentityCopyCertificate(persistedIdentity, &persistedCertificate) == errSecSuccess,
              let importedCertificate, let persistedCertificate,
              SecCertificateCopyData(importedCertificate) as Data == SecCertificateCopyData(persistedCertificate) as Data
        else { throw CompanionError.configuration }
        return reference
    }
    public static func resolve(_ reference: Data) throws -> SecIdentity {
        var result: CFTypeRef?
        guard SecItemCopyMatching([kSecValuePersistentRef as String: reference,
                                   kSecReturnRef as String: true,
                                   kSecClass as String: kSecClassIdentity] as CFDictionary, &result) == errSecSuccess,
              let result, CFGetTypeID(result) == SecIdentityGetTypeID() else { throw CompanionError.configuration }
        return (result as! SecIdentity)
    }
    public static func fingerprint(_ reference: Data) throws -> String {
        let identity = try resolve(reference)
        var certificate: SecCertificate?
        guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate else { throw CompanionError.configuration }
        return fingerprintDER(SecCertificateCopyData(certificate) as Data)
    }
    static func fingerprintDER(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
}

public actor PinnedTransport: CompanionTransport {
    private let configuration: ProviderConfiguration
    private var activeRequests = 0
    public init(configuration: ProviderConfiguration) throws { self.configuration = try configuration.validated() }
    public func send(_ body: Data) async throws -> Data {
        guard body.count <= 16_384, activeRequests < 8 else { throw CompanionError.oversized }
        activeRequests += 1
        defer { activeRequests -= 1 }
        let identity = try KeychainIdentity.resolve(configuration.identityReference)
        let delegate = RequestDelegate(configuration: configuration, identity: identity)
        let sessionConfiguration = URLSessionConfiguration.ephemeral
        sessionConfiguration.urlCache = nil
        sessionConfiguration.httpCookieStorage = nil
        sessionConfiguration.urlCredentialStorage = nil
        sessionConfiguration.httpShouldSetCookies = false
        sessionConfiguration.httpShouldUsePipelining = false
        sessionConfiguration.httpMaximumConnectionsPerHost = 1
        sessionConfiguration.timeoutIntervalForRequest = 5
        sessionConfiguration.timeoutIntervalForResource = 5
        sessionConfiguration.waitsForConnectivity = false
        sessionConfiguration.tlsMinimumSupportedProtocolVersion = .TLSv12
        let queue = OperationQueue()
        queue.maxConcurrentOperationCount = 1
        let session = URLSession(configuration: sessionConfiguration, delegate: delegate, delegateQueue: queue)
        defer { session.invalidateAndCancel() }
        var request = URLRequest(url: configuration.endpoint, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 5)
        request.httpMethod = "POST"
        request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
        request.setValue("close", forHTTPHeaderField: "Connection")
        request.setValue(String(body.count), forHTTPHeaderField: "Content-Length")
        return try await withCheckedThrowingContinuation { continuation in
            delegate.continuation = continuation
            session.dataTask(with: request).resume()
        }
    }
}

private final class RequestDelegate: NSObject, URLSessionDataDelegate, URLSessionTaskDelegate, @unchecked Sendable {
    let configuration: ProviderConfiguration
    let identity: SecIdentity
    var continuation: CheckedContinuation<Data, Error>?
    private var bytes = Data()
    private var failure: CompanionError?
    private var httpStatus: Int?
    init(configuration: ProviderConfiguration, identity: SecIdentity) {
        self.configuration = configuration; self.identity = identity
    }
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        authenticate(challenge, completionHandler: completionHandler)
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        authenticate(challenge, completionHandler: completionHandler)
    }
    private func authenticate(_ challenge: URLAuthenticationChallenge,
                              completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.previousFailureCount == 0,
              challenge.protectionSpace.host == configuration.endpoint.host else {
            completionHandler(.cancelAuthenticationChallenge, nil); return
        }
        switch challenge.protectionSpace.authenticationMethod {
        case NSURLAuthenticationMethodServerTrust:
            guard let trust = challenge.protectionSpace.serverTrust,
                  let ca = SecCertificateCreateWithData(nil, configuration.trustedCA as CFData),
                  SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, configuration.endpoint.host! as CFString)) == errSecSuccess,
                  SecTrustSetAnchorCertificates(trust, [ca] as CFArray) == errSecSuccess,
                  SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
                  SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess,
                  SecTrustEvaluateWithError(trust, nil),
                  let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], let leaf = chain.first,
                  KeychainIdentity.fingerprintDER(SecCertificateCopyData(leaf) as Data) == configuration.leafSHA256 else {
                completionHandler(.cancelAuthenticationChallenge, nil); return
            }
            completionHandler(.useCredential, URLCredential(trust: trust))
        case NSURLAuthenticationMethodClientCertificate:
            completionHandler(.useCredential, URLCredential(identity: identity, certificates: nil, persistence: .none))
        default: completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        failure = .invalidResponse
        completionHandler(nil)
    }
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    needNewBodyStream completionHandler: @escaping (InputStream?) -> Void) {
        // A request body is single-use. Never supply one for an automatic replay.
        completionHandler(nil)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard let response = response as? HTTPURLResponse,
              response.url == configuration.endpoint,
              [200, 400, 403, 409, 422, 429, 503].contains(response.statusCode),
              response.mimeType == "application/json",
              response.value(forHTTPHeaderField: "Content-Encoding") == nil,
              response.expectedContentLength >= 0,
              response.expectedContentLength <= 1_048_576 else {
            failure = .invalidResponse; completionHandler(.cancel); return
        }
        httpStatus = response.statusCode
        completionHandler(.allow)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        guard bytes.count <= 1_048_576 - data.count else { failure = .oversized; dataTask.cancel(); return }
        bytes.append(data)
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        let callback = continuation
        continuation = nil
        if let failure { callback?.resume(throwing: failure) }
        else if error != nil { callback?.resume(throwing: CompanionError.transport) }
        else {
            do {
                // HTTP and JSON form one protocol response. Never treat an error
                // under 200 as a definite rejection, or a success under 503 as success.
                guard let httpStatus,
                      let object = try JSONSerialization.jsonObject(with: bytes) as? [String: Any] else {
                    throw CompanionError.invalidResponse
                }
                if httpStatus == 200 {
                    guard object["error"] == nil else { throw CompanionError.invalidResponse }
                } else {
                    let envelope = try JSONDecoder().decode(ErrorResponse.self, from: bytes)
                    guard ErrorResponse.httpStatus[envelope.error] == httpStatus else { throw CompanionError.invalidResponse }
                }
                callback?.resume(returning: bytes)
            } catch { callback?.resume(throwing: CompanionError.invalidResponse) }
        }
        bytes.removeAll(keepingCapacity: false)
    }
}
