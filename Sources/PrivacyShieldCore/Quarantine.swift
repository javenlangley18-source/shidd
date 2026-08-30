import Foundation

public enum QuarantineState: String, Sendable {
    case requested
    case approved
    case quarantined
    case restored
    case readyForDeletion
}

public struct QuarantineRequest: Identifiable, Sendable, Equatable {
    public let id: UUID
    public let resourceId: String
    public let requesterId: String
    public let justification: String
    public let requestedAt: Date
    public var approvals: [String]
    public var state: QuarantineState

    public init(resourceId: String, requesterId: String, justification: String, requestedAt: Date = Date(), approvals: [String] = [], state: QuarantineState = .requested) {
        self.id = UUID()
        self.resourceId = resourceId
        self.requesterId = requesterId
        self.justification = justification
        self.requestedAt = requestedAt
        self.approvals = approvals
        self.state = state
    }
}

public actor QuarantineManager: Sendable {
    public static let shared = QuarantineManager()

    private var requestsById: [UUID: QuarantineRequest] = [:]

    /// Approval threshold (number of distinct approvers required before a request becomes approved).
    /// Default is 1 (single-approver). Can be adjusted via setApprovalThreshold by an admin.
    private var approvalThreshold: Int = 1

    public init() {}

    /// Admin-callable: set the number of approvers required for approval. Value must be >= 1.
    public func setApprovalThreshold(_ n: Int, actorId: String) async {
        guard n >= 1 else { return }
        approvalThreshold = n
        await AuditLog.shared.record(actor: actorId, action: "set_approval_threshold", target: nil, details: "threshold=\(n)")
    }

    /// Request quarantine for a resource. Returns the request id.
    public func requestQuarantine(resourceId: String, requesterId: String, justification: String) async -> UUID {
        var req = QuarantineRequest(resourceId: resourceId, requesterId: requesterId, justification: justification)
        req.state = .requested
        requestsById[req.id] = req
        Storage.shared.upsertQuarantineRequest(req)
        await AuditLog.shared.record(actor: requesterId, action: "quarantine_requested", target: resourceId, details: justification)
        return req.id
    }

    /// Approve a pending quarantine request. Returns the updated request if successful.
    /// Approval only transitions to `.approved` when the number of distinct approvers >= approvalThreshold.
    public func approve(requestId: UUID, approverId: String) async -> QuarantineRequest? {
        guard var req = requestsById[requestId] else { return nil }
        guard req.state == .requested || req.state == .approved else { return req }
        if !req.approvals.contains(approverId) {
            req.approvals.append(approverId)
        }
        // Only mark as approved when approvals reach threshold
        if req.approvals.count >= approvalThreshold {
            req.state = .approved
        } else {
            req.state = .requested
        }
        requestsById[requestId] = req
        Storage.shared.upsertQuarantineRequest(req)
        await AuditLog.shared.record(actor: approverId, action: "quarantine_approval_added", target: req.resourceId, details: "approvals=\(req.approvals)")
        if req.state == .approved {
            await AuditLog.shared.record(actor: approverId, action: "quarantine_approved", target: req.resourceId, details: "approvals=\(req.approvals)")
        }
        return req
    }

    /// Mark a request as quarantined (data flagged/hidden but not deleted). Returns the updated request.
    public func applyQuarantine(requestId: UUID, actorId: String) async -> QuarantineRequest? {
        guard var req = requestsById[requestId] else { return nil }
        guard req.state == .approved else { return req }
        req.state = .quarantined
        requestsById[requestId] = req
        Storage.shared.upsertQuarantineRequest(req)
        await AuditLog.shared.record(actor: actorId, action: "quarantine_applied", target: req.resourceId, details: nil)
        return req
    }

    /// Restore quarantined data (revoke quarantine). Returns the updated request.
    public func restore(requestId: UUID, actorId: String) async -> QuarantineRequest? {
        guard var req = requestsById[requestId], req.state == .quarantined else { return nil }
        req.state = .restored
        requestsById[requestId] = req
        Storage.shared.upsertQuarantineRequest(req)
        await AuditLog.shared.record(actor: actorId, action: "quarantine_restored", target: req.resourceId, details: nil)
        return req
    }

    /// Mark a request ready for final deletion (still does not perform deletion).
    /// Final deletion is intentionally not implemented here — this manager only marks the lifecycle
    /// and records audit events. Actual irreversible deletion must be performed by an admin tool
    /// that reads this marker and performs deletion with additional confirmation.
    public func markReadyForDeletion(requestId: UUID, actorId: String) async -> QuarantineRequest? {
        guard var req = requestsById[requestId] else { return nil }
        guard req.state == .quarantined || req.state == .approved else { return req }
        req.state = .readyForDeletion
        requestsById[requestId] = req
        Storage.shared.upsertQuarantineRequest(req)
        await AuditLog.shared.record(actor: actorId, action: "quarantine_ready_for_deletion", target: req.resourceId, details: nil)
        return req
    }

    public func getRequest(_ id: UUID) -> QuarantineRequest? {
        // Try in-memory first, then storage
        if let inMem = requestsById[id] { return inMem }
        return Storage.shared.fetchQuarantineRequest(id: id)
    }

    public func listRequests() -> [QuarantineRequest] {
        // Combine in-memory and persisted, but prefer persisted list which is authoritative
        return Storage.shared.listQuarantineRequests()
    }
}
