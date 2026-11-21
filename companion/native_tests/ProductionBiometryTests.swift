import LocalAuthentication
import XCTest
@testable import NativeContract

/// The shared key admits only the sensors of its platform (#60 phase 2):
/// macOS keeps Touch ID only; iOS adds Face ID (checked in ios/RunnerTests).
final class ProductionBiometryTests: XCTestCase {
    func testMacOSAdmitsTouchIDOnly() {
        XCTAssertEqual(ProductionBiometry.admitted(.touchID), .touchID)
        XCTAssertNil(ProductionBiometry.admitted(.faceID))
        XCTAssertNil(ProductionBiometry.admitted(.none))
        XCTAssertEqual(ProductionApprovalKey.accessFlags(), [.privateKeyUsage, .biometryCurrentSet])
    }
}
