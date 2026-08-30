import XCTest
@testable import PrivacyShieldCore

final class AuditAndQuarantineTests: XCTestCase {
    override func setUp() async throws {
        await AuditLog.shared.clear()
    }

    func testAuditRecordsPermissionSummaryCreation() async throws {
        let _ = AppPermissionSummary(
            bundleIdentifier: "com.example.test",
            displayName: "Example",
            permissions: [
                PermissionRecord(capability: .camera, state: .authorized)
            ]
        )

        // Allow the async audit task to run
        try await Task.sleep(nanoseconds: 100_000_000)

        let events = await AuditLog.shared.allEvents()
        XCTAssertTrue(events.contains { $0.action == "permission_summary_created" && $0.target == "com.example.test" })
    }

    func testQuarantineLifecycle() async throws {
        let qm = QuarantineManager.shared
        let requester = "adminA"
        let approver = "adminB"

        // Ensure single-approver threshold (default)
        await qm.setApprovalThreshold(1, actorId: "system")

        let reqId = await qm.requestQuarantine(resourceId: "resource-123", requesterId: requester, justification: "Test purge")
        let req = await qm.getRequest(reqId)
        XCTAssertEqual(req?.state, .requested)

        let approved = await qm.approve(requestId: reqId, approverId: approver)
        XCTAssertEqual(approved?.state, .approved)
        XCTAssertTrue(approved?.approvals.contains(approver) ?? false)

        let applied = await qm.applyQuarantine(requestId: reqId, actorId: approver)
        XCTAssertEqual(applied?.state, .quarantined)

        let marked = await qm.markReadyForDeletion(requestId: reqId, actorId: approver)
        XCTAssertEqual(marked?.state, .readyForDeletion)

        // Restore should not work once readyForDeletion
        let restored = await qm.restore(requestId: reqId, actorId: approver)
        XCTAssertNil(restored) // restore only works when state == .quarantined

        // Check audit events exist for the lifecycle
        let events = await AuditLog.shared.allEvents()
        let actions = events.map { $0.action }
        XCTAssertTrue(actions.contains("quarantine_requested"))
        XCTAssertTrue(actions.contains("quarantine_approved"))
        XCTAssertTrue(actions.contains("quarantine_applied"))
        XCTAssertTrue(actions.contains("quarantine_ready_for_deletion"))
    }

    func testMultiApproverThreshold() async throws {
        let qm = QuarantineManager.shared
        let requester = "adminA"
        let approver1 = "adminB"
        let approver2 = "adminC"

        // Set threshold to 2
        await qm.setApprovalThreshold(2, actorId: "system")

        let reqId = await qm.requestQuarantine(resourceId: "resource-456", requesterId: requester, justification: "Multi-approver test")

        // First approval should not reach threshold
        let afterFirst = await qm.approve(requestId: reqId, approverId: approver1)
        XCTAssertEqual(afterFirst?.state, .requested)
        XCTAssertTrue(afterFirst?.approvals.contains(approver1) ?? false)

        // Second approval should mark approved
        let afterSecond = await qm.approve(requestId: reqId, approverId: approver2)
        XCTAssertEqual(afterSecond?.state, .approved)
        XCTAssertTrue(afterSecond?.approvals.contains(approver2) ?? false)
    }
}
