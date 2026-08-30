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

    public init() {}

    /// Request quarantine for a resource. Returns the request id.
    public func requestQuarantine(resourceId: String, requesterId: String, justification: String) async -> UUID {
        var req = QuarantineRequest(resourceId: resourceId, requesterId: requesterId, justification: justification)
        req.state = .requested
        requestsById[req.id] = req
        await AuditLog.shared.record(actor: requesterId, action: "quarantine_requested", target: resourceId, details: justification)
        return req.id
    }

    /// Approve a pending quarantine request. Returns the updated request if successful.
    /// For safety this implementation requires at least one approver; to enable a 2-person rule
    /// change the approval threshold in future.
    public func approve(requestId: UUID, approverId: String) async -> QuarantineRequest? {
        guard var req = requestsById[requestId] else { return nil }
        guard req.state == .requested || req.state == .approved else { return req }
        if !req.approvals.contains(approverId) {
            req.approvals.append(approverId)
        }
        req.state = .approved
        requestsById[requestId] = req
        await AuditLog.shared.record(actor: approverId, action: "quarantine_approved", target: req.resourceId, details: "approvals=\(req.approvals)")
        return req
    }

    /// Mark a request as quarantined (data flagged/hidden but not deleted). Returns the updated request.
    public func applyQuarantine(requestId: UUID, actorId: String) async -> QuarantineRequest? {
        guard var req = requestsById[requestId] else { return nil }
        guard req.state == .approved else { return req }
        req.state = .quarantined
        requestsById[requestId] = req
        await AuditLog.shared.record(actor: actorId, action: "quarantine_applied", target: req.resourceId, details: nil)
        return req
    }

    /// Restore quarantined data (revoke quarantine). Returns the updated request.
    public func restore(requestId: UUID, actorId: String) async -> QuarantineRequest? {
        guard var req = requestsById[requestId], req.state == .quarantined else { return nil }
        req.state = .restored
        requestsById[requestId] = req
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
        await AuditLog.shared.record(actor: actorId, action: "quarantine_ready_for_deletion", target: req.resourceId, details: nil)
        return req
    }

    public func getRequest(_ id: UUID) -> QuarantineRequest? {
        requestsById[id]
    }

    public func listRequests() -> [QuarantineRequest] {
        Array(requestsById.values)
    }
}
