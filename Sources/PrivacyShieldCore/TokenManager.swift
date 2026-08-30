import Foundation

public struct Token: Codable, Sendable, Equatable {
    public let token: String
    public let userId: String
    public let createdAt: Date
    public let expiresAt: Date?
    public var revoked: Bool

    public init(token: String = UUID().uuidString.replacingOccurrences(of: "-", with: ""), userId: String, createdAt: Date = Date(), expiresAt: Date? = nil, revoked: Bool = false) {
        self.token = token
        self.userId = userId
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.revoked = revoked
    }
}

public actor TokenManager: Sendable {
    public static let shared = TokenManager()

    private var tokensByValue: [String: Token] = [:]

    public init() {
        // load tokens from storage
        let records = Storage.shared.stateTokens() // helper to get raw records
        for rec in records {
            let t = Token(token: rec.token, userId: rec.userId, createdAt: Date(timeIntervalSince1970: rec.createdAt), expiresAt: rec.expiresAt.map { Date(timeIntervalSince1970: $0) }, revoked: rec.revoked)
            tokensByValue[t.token] = t
        }
    }

    public func createToken(userId: String, ttlSeconds: Int?) async -> Token {
        let expires = ttlSeconds.map { Date(timeIntervalSinceNow: TimeInterval($0)) }
        let t = Token(userId: userId, expiresAt: expires)
        tokensByValue[t.token] = t
        Storage.shared.upsertToken(t)
        await AuditLog.shared.record(actor: "system", action: "token_created", target: userId, details: "token=****")
        return t
    }

    public func revokeToken(_ tokenValue: String, actorId: String) async -> Bool {
        guard var t = tokensByValue[tokenValue] else { return false }
        t.revoked = true
        tokensByValue[tokenValue] = t
        Storage.shared.upsertToken(t)
        await AuditLog.shared.record(actor: actorId, action: "token_revoked", target: t.userId, details: "token=****")
        return true
    }

    public func validate(_ tokenValue: String) async -> String? {
        guard let t = tokensByValue[tokenValue], !t.revoked else { return nil }
        if let exp = t.expiresAt, exp < Date() { return nil }
        return t.userId
    }

    public func listTokens() async -> [Token] {
        Array(tokensByValue.values)
    }
}
