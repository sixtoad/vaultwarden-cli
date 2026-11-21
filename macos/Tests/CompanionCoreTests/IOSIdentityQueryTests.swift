import CryptoKit
import Foundation
import Security
import XCTest
@testable import CompanionCore

/// The iOS identity import (#60) is exercised on a physical iPhone; its
/// Keychain queries are pure and checked here on the host.
final class IOSIdentityQueryTests: XCTestCase {
    func testLookupIsRestrictedToIdentities() {
        let value = "identity" as CFString
        let query = IOSIdentityQueries.lookup(value)
        XCTAssertEqual(query[kSecClass as String] as? String, kSecClassIdentity as String,
                       "Without kSecClass the duplicate lookup can resolve a stale identity")
        XCTAssertTrue((query[kSecValueRef as String] as AnyObject) === value)
        XCTAssertEqual(query[kSecReturnPersistentRef as String] as? Bool, true)
        XCTAssertEqual(query.count, 3)
    }
}

final class IOSReplacedIdentityQueryTests: XCTestCase {
    func testPublicKeyHashIsTheKeychainApplicationLabel() throws {
        var error: Unmanaged<CFError>?
        let key = try XCTUnwrap(SecKeyCreateRandomKey([kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                                                       kSecAttrKeySizeInBits as String: 256] as CFDictionary, &error))
        let publicKey = try XCTUnwrap(SecKeyCopyPublicKey(key))
        let label = try XCTUnwrap((SecKeyCopyAttributes(key) as? [String: Any])?[kSecAttrApplicationLabel as String] as? Data)
        XCTAssertEqual(IOSIdentityQueries.publicKeyHash(publicKey), label)
        XCTAssertEqual(label.count, 20)
    }

    func testReplacedQueriesTargetOnlyThisKeysCertificateAndKey() throws {
        let hash = Data(repeating: 0xAB, count: 20)
        let queries = IOSIdentityQueries.replaced(publicKeyHash: hash)
        XCTAssertEqual(queries.count, 2)
        XCTAssertEqual(queries[0][kSecClass as String] as? String, kSecClassCertificate as String)
        XCTAssertEqual(queries[0][kSecAttrPublicKeyHash as String] as? Data, hash)
        XCTAssertEqual(queries[1][kSecClass as String] as? String, kSecClassKey as String)
        XCTAssertEqual(queries[1][kSecAttrApplicationLabel as String] as? Data, hash)
        // Never an unscoped delete: each query names its class and this key.
        XCTAssertTrue(queries.allSatisfy { $0.count == 2 })
    }
}
