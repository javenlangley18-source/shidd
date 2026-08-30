import XCTest
@testable import PrivacyShieldCore

final class PrivacyShieldCoreTests: XCTestCase {
    func testBlocksExactAndSubdomains() {
        let blocker = TrackerBlocker(blockedDomains: ["ads.example.com"])

        XCTAssertTrue(blocker.shouldBlock(host: "ads.example.com"))
        XCTAssertTrue(blocker.shouldBlock(host: "pixel.ads.example.com."))
        XCTAssertFalse(blocker.shouldBlock(host: "example.com"))
        XCTAssertFalse(blocker.shouldBlock(host: "notads.example.com"))
    }

    func testInvalidHostsFailOpen() {
        let blocker = TrackerBlocker(blockedDomains: ["ads.example.com"])

        XCTAssertFalse(blocker.shouldBlock(host: "ads..example.com"))
        XCTAssertFalse(blocker.shouldBlock(host: "https://ads.example.com"))
        XCTAssertFalse(blocker.shouldBlock(host: ""))
    }

    func testPermissionSummaryReportsAuthorizedCapabilities() {
        let summary = AppPermissionSummary(
            bundleIdentifier: "com.example.video",
            displayName: "Example Video",
            permissions: [
                PermissionRecord(capability: .camera, state: .authorized),
                PermissionRecord(capability: .microphone, state: .denied),
                PermissionRecord(capability: .tracking, state: .authorized)
            ]
        )

        XCTAssertEqual(summary.authorizedCapabilities, [.camera, .tracking])
    }
}