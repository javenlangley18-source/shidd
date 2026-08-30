import Foundation

public enum SensitiveCapability: String, CaseIterable, Sendable {
    case location
    case camera
    case microphone
    case photos
    case contacts
    case tracking
}

public enum AuthorizationState: String, Sendable {
    case authorized
    case denied
    case restricted
    case notDetermined
    case unavailable
}

public struct PermissionRecord: Identifiable, Equatable, Sendable {
    public let id: SensitiveCapability
    public let state: AuthorizationState

    public init(capability: SensitiveCapability, state: AuthorizationState) {
        self.id = capability
        self.state = state
    }
}

public struct AppPermissionSummary: Identifiable, Equatable, Sendable {
    public let id: String
    public let displayName: String
    public let permissions: [PermissionRecord]

    public init(bundleIdentifier: String, displayName: String, permissions: [PermissionRecord]) {
        self.id = bundleIdentifier
        self.displayName = displayName
        self.permissions = permissions

        // Non-blocking audit: record that a permission summary was created.
        // Use a detached task so this initializer remains synchronous for callers.
        let details = permissions.map { "\($0.id.rawValue)=\($0.state.rawValue)" }.joined(separator: ",")
        Task { await AuditLog.shared.record(actor: "system", action: "permission_summary_created", target: bundleIdentifier, details: details) }
    }

    public var authorizedCapabilities: [SensitiveCapability] {
        permissions.filter { $0.state == .authorized }.map(\.id)
    }
}