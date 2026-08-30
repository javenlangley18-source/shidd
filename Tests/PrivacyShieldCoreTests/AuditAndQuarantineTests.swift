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

        let reqId = await qm.requestQuarantine(resourceId: "resource-123", requesterId: requester, justification: "Test purge")
        var req = await qm.getRequest(reqId)
        XCTAssertEqual(req?.state, .requested)

        let approved = await qm.approve(requestId: reqId, approverId: approver)
        XCTAssertEqual(approved?.state, .approved)
        XCTAssertTrue(approved?.approvals.contains(approver) ?? false)

        let applied = await qm.applyQuarantine(requestId: reqId, actorId: approver)
        XCTAssertEqual(applied?.state, .quarantined)

        let marked = await qm.markReadyForDeletion(requestId: reqId, actorId: approver)
        XCTAssertEqual(marked?.state, .readyForDeletion)

        // Restore should not change state from readyForDeletion in this simple implementation
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
}
