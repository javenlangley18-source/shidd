import XCTest
@testable import PrivacyShieldCoreTests

fileprivate extension AuditAndQuarantineTests {
    @available(*, deprecated, message: "Not actually deprecated. Marked as deprecated to allow inclusion of deprecated tests (which test deprecated functionality) without warnings")
    static let __allTests__AuditAndQuarantineTests = [
        ("testAuditRecordsPermissionSummaryCreation", asyncTest(testAuditRecordsPermissionSummaryCreation)),
        ("testMultiApproverThreshold", asyncTest(testMultiApproverThreshold)),
        ("testQuarantineLifecycle", asyncTest(testQuarantineLifecycle))
    ]
}

fileprivate extension PrivacyShieldCoreTests {
    @available(*, deprecated, message: "Not actually deprecated. Marked as deprecated to allow inclusion of deprecated tests (which test deprecated functionality) without warnings")
    static let __allTests__PrivacyShieldCoreTests = [
        ("testBlocksExactAndSubdomains", testBlocksExactAndSubdomains),
        ("testInvalidHostsFailOpen", testInvalidHostsFailOpen),
        ("testPermissionSummaryReportsAuthorizedCapabilities", testPermissionSummaryReportsAuthorizedCapabilities)
    ]
}
@available(*, deprecated, message: "Not actually deprecated. Marked as deprecated to allow inclusion of deprecated tests (which test deprecated functionality) without warnings")
func __PrivacyShieldCoreTests__allTests() -> [XCTestCaseEntry] {
    return [
        testCase(AuditAndQuarantineTests.__allTests__AuditAndQuarantineTests),
        testCase(PrivacyShieldCoreTests.__allTests__PrivacyShieldCoreTests)
    ]
}