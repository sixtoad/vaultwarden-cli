import Cocoa
import FlutterMacOS
import XCTest

class RunnerTests: XCTestCase {

  func testDedicatedBundleIdentity() {
    XCTAssertEqual(Bundle.main.bundleIdentifier, "dev.vaultwarden.companionSlice")
  }

}
