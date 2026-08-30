import Foundation
import SQLite3

public final class Storage {
    public static let shared = Storage()

    private var db: OpaquePointer?
    private let queue = DispatchQueue(label: "Storage.sqlite")

    private init() {
        // Default to in-memory so unit tests remain hermetic. If the env var PRIVACY_SHIELD_DB is set,
        // use that path instead.
        let path = ProcessInfo.processInfo.environment["PRIVACY_SHIELD_DB"] ?? ":memory:"
        open(path: path)
        createTables()
    }

    deinit {
        if let db = db { sqlite3_close(db) }
    }

    private func open(path: String) {
        let flags = SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE | (path == ":memory:" ? SQLITE_OPEN_MEMORY : 0)
        if sqlite3_open_v2(path, &db, flags, nil) != SQLITE_OK {
            fatalError("Unable to open sqlite db at \(path): \(String(cString: sqlite3_errmsg(db)))")
        }
    }

    private func createTables() {
        let createAudit = """
        CREATE TABLE IF NOT EXISTS audit_events (
            id TEXT PRIMARY KEY,
            timestamp REAL,
            actor TEXT,
            action TEXT,
            target TEXT,
            details TEXT
        );
        """

        let createQuarantine = """
        CREATE TABLE IF NOT EXISTS quarantine_requests (
            id TEXT PRIMARY KEY,
            resource_id TEXT,
            requester_id TEXT,
            justification TEXT,
            requested_at REAL,
            approvals TEXT,
            state TEXT
        );
        """

        exec(sql: createAudit)
        exec(sql: createQuarantine)
    }

    private func exec(sql: String) {
        var err: UnsafeMutablePointer<Int8>? = nil
        if sqlite3_exec(db, sql, nil, nil, &err) != SQLITE_OK {
            let msg = err.map { String(cString: $0) } ?? "unknown"
            sqlite3_free(err)
            fatalError("SQLite exec error: \(msg)")
        }
    }

    // MARK: - Audit

    public func insertAuditEvent(_ ev: AuditEvent) {
        queue.sync {
            let sql = "INSERT OR REPLACE INTO audit_events (id, timestamp, actor, action, target, details) VALUES (?,?,?,?,?,?);"
            var stmt: OpaquePointer?
            sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
            defer { sqlite3_finalize(stmt) }
            sqlite3_bind_text(stmt, 1, ev.id.uuidString, -1, nil)
            sqlite3_bind_double(stmt, 2, ev.timestamp.timeIntervalSince1970)
            sqlite3_bind_text(stmt, 3, ev.actor, -1, nil)
            sqlite3_bind_text(stmt, 4, ev.action, -1, nil)
            if let target = ev.target { sqlite3_bind_text(stmt, 5, target, -1, nil) } else { sqlite3_bind_null(stmt, 5) }
            if let details = ev.details { sqlite3_bind_text(stmt, 6, details, -1, nil) } else { sqlite3_bind_null(stmt, 6) }
            if sqlite3_step(stmt) != SQLITE_DONE {
                let msg = String(cString: sqlite3_errmsg(db))
                print("Failed to insert audit event: \(msg)")
            }
        }
    }

    public func fetchAllAuditEvents() -> [AuditEvent] {
        queue.sync {
            var res: [AuditEvent] = []
            let sql = "SELECT id, timestamp, actor, action, target, details FROM audit_events ORDER BY timestamp ASC;"
            var stmt: OpaquePointer?
            sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
            defer { sqlite3_finalize(stmt) }
            while sqlite3_step(stmt) == SQLITE_ROW {
                guard let idText = sqlite3_column_text(stmt, 0) else { continue }
                let id = UUID(uuidString: String(cString: idText)) ?? UUID()
                let ts = sqlite3_column_double(stmt, 1)
                let actor = String(cString: sqlite3_column_text(stmt, 2))
                let action = String(cString: sqlite3_column_text(stmt, 3))
                let target = sqlite3_column_text(stmt, 4).map { String(cString: $0) }
                let details = sqlite3_column_text(stmt, 5).map { String(cString: $0) }
                res.append(AuditEvent(id: id, timestamp: Date(timeIntervalSince1970: ts), actor: actor, action: action, target: target, details: details))
            }
            return res
        }
    }

    // MARK: - Quarantine

    public func upsertQuarantineRequest(_ req: QuarantineRequest) {
        queue.sync {
            let sql = "INSERT OR REPLACE INTO quarantine_requests (id, resource_id, requester_id, justification, requested_at, approvals, state) VALUES (?,?,?,?,?,?,?);"
            var stmt: OpaquePointer?
            sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
            defer { sqlite3_finalize(stmt) }
            sqlite3_bind_text(stmt, 1, req.id.uuidString, -1, nil)
            sqlite3_bind_text(stmt, 2, req.resourceId, -1, nil)
            sqlite3_bind_text(stmt, 3, req.requesterId, -1, nil)
            sqlite3_bind_text(stmt, 4, req.justification, -1, nil)
            sqlite3_bind_double(stmt, 5, req.requestedAt.timeIntervalSince1970)
            // Store approvals as a JSON array string
            if let approvalsData = try? JSONEncoder().encode(req.approvals), let approvalsStr = String(data: approvalsData, encoding: .utf8) {
                sqlite3_bind_text(stmt, 6, approvalsStr, -1, nil)
            } else {
                sqlite3_bind_text(stmt, 6, "[]", -1, nil)
            }
            sqlite3_bind_text(stmt, 7, req.state.rawValue, -1, nil)
            if sqlite3_step(stmt) != SQLITE_DONE {
                let msg = String(cString: sqlite3_errmsg(db))
                print("Failed to upsert quarantine request: \(msg)")
            }
        }
    }

    public func fetchQuarantineRequest(id: UUID) -> QuarantineRequest? {
        queue.sync {
            let sql = "SELECT id, resource_id, requester_id, justification, requested_at, approvals, state FROM quarantine_requests WHERE id = ? LIMIT 1;"
            var stmt: OpaquePointer?
            sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
            defer { sqlite3_finalize(stmt) }
            sqlite3_bind_text(stmt, 1, id.uuidString, -1, nil)
            if sqlite3_step(stmt) == SQLITE_ROW {
                guard let idText = sqlite3_column_text(stmt, 0) else { return nil }
                let id = UUID(uuidString: String(cString: idText)) ?? UUID()
                let resourceId = String(cString: sqlite3_column_text(stmt, 1))
                let requesterId = String(cString: sqlite3_column_text(stmt, 2))
                let justification = String(cString: sqlite3_column_text(stmt, 3))
                let requestedAt = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 4))
                let approvalsText = sqlite3_column_text(stmt, 5).map { String(cString: $0) } ?? "[]"
                let approvals = (try? JSONDecoder().decode([String].self, from: Data(approvalsText.utf8))) ?? []
                let stateStr = String(cString: sqlite3_column_text(stmt, 6))
                let state = QuarantineState(rawValue: stateStr) ?? .requested
                return QuarantineRequest(resourceId: resourceId, requesterId: requesterId, justification: justification, requestedAt: requestedAt, approvals: approvals, state: state)
            }
            return nil
        }
    }

    public func listQuarantineRequests() -> [QuarantineRequest] {
        queue.sync {
            var res: [QuarantineRequest] = []
            let sql = "SELECT id, resource_id, requester_id, justification, requested_at, approvals, state FROM quarantine_requests ORDER BY requested_at ASC;"
            var stmt: OpaquePointer?
            sqlite3_prepare_v2(db, sql, -1, &stmt, nil)
            defer { sqlite3_finalize(stmt) }
            while sqlite3_step(stmt) == SQLITE_ROW {
                let idText = sqlite3_column_text(stmt, 0).map { String(cString: $0) } ?? UUID().uuidString
                let resourceId = String(cString: sqlite3_column_text(stmt, 1))
                let requesterId = String(cString: sqlite3_column_text(stmt, 2))
                let justification = String(cString: sqlite3_column_text(stmt, 3))
                let requestedAt = Date(timeIntervalSince1970: sqlite3_column_double(stmt, 4))
                let approvalsText = sqlite3_column_text(stmt, 5).map { String(cString: $0) } ?? "[]"
                let approvals = (try? JSONDecoder().decode([String].self, from: Data(approvalsText.utf8))) ?? []
                let stateStr = String(cString: sqlite3_column_text(stmt, 6))
                let state = QuarantineState(rawValue: stateStr) ?? .requested
                var req = QuarantineRequest(resourceId: resourceId, requesterId: requesterId, justification: justification, requestedAt: requestedAt, approvals: approvals, state: state)
                if let uuid = UUID(uuidString: idText) { req = QuarantineRequest(resourceId: resourceId, requesterId: requesterId, justification: justification, requestedAt: requestedAt, approvals: approvals, state: state); /* preserve id */ _ = uuid }
                res.append(req)
            }
            return res
        }
    }
}
