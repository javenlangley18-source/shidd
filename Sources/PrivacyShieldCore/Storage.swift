import Foundation

// Simple JSON-backed storage. Default is in-memory (no persistence) unless PRIVACY_SHIELD_DB env var provides a path.

public final class Storage {
    public static let shared = Storage()

    private let path: String?
    private var state: StorageState
    private let queue = DispatchQueue(label: "Storage.json")

    private struct StorageState: Codable {
        var auditEvents: [AuditEvent] = []
        var quarantineRequests: [QuarantineRequestRecord] = []
        var tokens: [TokenRecord] = []
    }

    // QuarantineRecord keeps the persistent id and fields
    private struct QuarantineRequestRecord: Codable {
        let id: String
        let resourceId: String
        let requesterId: String
        let justification: String
        let requestedAt: TimeInterval
        let approvals: [String]
        let state: String
    }

    public struct TokenRecord: Codable {
        public let token: String
        public let userId: String
        public let createdAt: TimeInterval
        public let expiresAt: TimeInterval?
        public let revoked: Bool

        public init(token: String, userId: String, createdAt: TimeInterval, expiresAt: TimeInterval?, revoked: Bool) {
            self.token = token
            self.userId = userId
            self.createdAt = createdAt
            self.expiresAt = expiresAt
            self.revoked = revoked
        }
    }

    private init() {
        let envPath = ProcessInfo.processInfo.environment["PRIVACY_SHIELD_DB"]
        if let p = envPath, !p.isEmpty {
            self.path = p
            if let data = try? Data(contentsOf: URL(fileURLWithPath: p)), let s = try? JSONDecoder().decode(StorageState.self, from: data) {
                self.state = s
            } else {
                self.state = StorageState()
                persist()
            }
        } else {
            self.path = nil
            self.state = StorageState()
        }
    }

    private func persist() {
        guard let path = path else { return }
        queue.async {
            if let data = try? JSONEncoder().encode(self.state) {
                try? data.write(to: URL(fileURLWithPath: path))
            }
        }
    }

    // Helper to expose raw token records for TokenManager initialization
    public func stateTokens() -> [TokenRecord] {
        queue.sync { state.tokens }
    }

    public func upsertToken(_ token: Token) {
        queue.sync {
            let rec = TokenRecord(token: token.token, userId: token.userId, createdAt: token.createdAt.timeIntervalSince1970, expiresAt: token.expiresAt?.timeIntervalSince1970, revoked: token.revoked)
            if let idx = state.tokens.firstIndex(where: { $0.token == rec.token }) {
                state.tokens[idx] = rec
            } else {
                state.tokens.append(rec)
            }
            persist()
        }
    }


    // MARK: - Audit
    public func insertAuditEvent(_ ev: AuditEvent) {
        queue.sync {
            state.auditEvents.append(ev)
            persist()
        }
    }

    public func fetchAllAuditEvents() -> [AuditEvent] {
        queue.sync { state.auditEvents }
    }

    // MARK: - Quarantine
    public func upsertQuarantineRequest(_ req: QuarantineRequest) {
        queue.sync {
            // Represent with a record that preserves the UUID
            let rec = QuarantineRequestRecord(id: req.id.uuidString, resourceId: req.resourceId, requesterId: req.requesterId, justification: req.justification, requestedAt: req.requestedAt.timeIntervalSince1970, approvals: req.approvals, state: req.state.rawValue)
            if let idx = state.quarantineRequests.firstIndex(where: { $0.id == rec.id }) {
                state.quarantineRequests[idx] = rec
            } else {
                state.quarantineRequests.append(rec)
            }
            persist()
        }
    }

    public func fetchQuarantineRequest(id: UUID) -> QuarantineRequest? {
        queue.sync {
            guard let rec = state.quarantineRequests.first(where: { $0.id == id.uuidString }) else { return nil }
            return QuarantineRequest(resourceId: rec.resourceId, requesterId: rec.requesterId, justification: rec.justification, requestedAt: Date(timeIntervalSince1970: rec.requestedAt), approvals: rec.approvals, state: QuarantineState(rawValue: rec.state) ?? .requested)
        }
    }

    public func listQuarantineRequests() -> [QuarantineRequest] {
        queue.sync {
            state.quarantineRequests.map { rec in
                QuarantineRequest(resourceId: rec.resourceId, requesterId: rec.requesterId, justification: rec.justification, requestedAt: Date(timeIntervalSince1970: rec.requestedAt), approvals: rec.approvals, state: QuarantineState(rawValue: rec.state) ?? .requested)
            }
        }
    }
}
