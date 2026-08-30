import Foundation

public enum QuarantineState: String, Sendable {
    case requested
    case approved
    case quarantined
    case restored
    case readyForDeletion
}

public struct QuarantineRequest: Identifiable, Sendable, Equatable, Codable {
    public let id: UUID
    public let resourceId: String
    public let requesterId: String
    public let justification: String
    public let requestedAt: Date
    public var approvals: [String]
    public var state: QuarantineState

    public init(id: UUID = UUID(), resourceId: String, requesterId: String, justification: String, requestedAt: Date = Date(), approvals: [String] = [], state: QuarantineState = .requested) {
        self.id = id
        self.resourceId = resourceId
        self.requesterId = requesterId
        self.justification = justification
        self.requestedAt = requestedAt
        self.approvals = approvals
        self.state = state
    }

    enum CodingKeys: String, CodingKey {
        case id, resourceId, requesterId, justification, requestedAt, approvals, state
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let idString = try container.decodeIfPresent(String.self, forKey: .id)
        if let idString = idString, let uuid = UUID(uuidString: idString) {
            self.id = uuid
        } else if let uuid = try? container.decodeIfPresent(UUID.self, forKey: .id) {
            self.id = uuid ?? UUID()
        } else {
            self.id = UUID()
        }
        self.resourceId = try container.decode(String.self, forKey: .resourceId)
        self.requesterId = try container.decode(String.self, forKey: .requesterId)
        self.justification = try container.decode(String.self, forKey: .justification)
        let ts = try container.decode(TimeInterval.self, forKey: .requestedAt)
        self.requestedAt = Date(timeIntervalSince1970: ts)
        self.approvals = try container.decode([String].self, forKey: .approvals)
        self.state = QuarantineState(rawValue: try container.decode(String.self, forKey: .state)) ?? .requested
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id.uuidString, forKey: .id)
        try container.encode(resourceId, forKey: .resourceId)
        try container.encode(requesterId, forKey: .requesterId)
        try container.encode(justification, forKey: .justification)
        try container.encode(requestedAt.timeIntervalSince1970, forKey: .requestedAt)
        try container.encode(approvals, forKey: .approvals)
        try container.encode(state.rawValue, forKey: .state)
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
