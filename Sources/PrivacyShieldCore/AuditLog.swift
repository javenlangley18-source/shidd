import Foundation

public struct AuditEvent: Identifiable, Equatable, Sendable {
    public let id: UUID
    public let timestamp: Date
    public let actor: String
    public let action: String
    public let target: String?
    public let details: String?

    public init(id: UUID = UUID(), timestamp: Date = Date(), actor: String, action: String, target: String? = nil, details: String? = nil) {
        self.id = id
        self.timestamp = timestamp
        self.actor = actor
        self.action = action
        self.target = target
        self.details = details
    }
}

public actor AuditLog: Sendable {
    public static let shared = AuditLog()

    private var events: [AuditEvent] = []

    public init() {}

    public func record(actor: String, action: String, target: String? = nil, details: String? = nil) async {
        let ev = AuditEvent(actor: actor, action: action, target: target, details: details)
        events.append(ev)
        // Persist to storage (best-effort)
        Storage.shared.insertAuditEvent(ev)
    }

    public func allEvents() -> [AuditEvent] {
        // Prefer persisted events if available
        let persisted = Storage.shared.fetchAllAuditEvents()
        return persisted
    }

    public func clear() {
        events.removeAll()
        // Clearing persisted storage is intentionally not implemented here to avoid accidental data loss
    }
}
