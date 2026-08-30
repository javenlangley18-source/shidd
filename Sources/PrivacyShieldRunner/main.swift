#if os(Linux)
import Glibc
#else
import Darwin
#endif
import Foundation
import PrivacyShieldCore

// Simple TCP control server — listens on two ports and accepts basic newline-terminated commands.
// Commands: LIST_REQUESTS, LIST_AUDIT, REQUEST_QUARANTINE <resource> <requester> <justification>, APPROVE <id> <approver>, APPLY <id> <actor>, MARK_READY <id> <actor>, GET_REQUEST <id>

let ports = [8080, 9090]

func startListener(on port: Int) {
    DispatchQueue.global().async {
        let sock = socket(AF_INET, Int32(1), 0) // SOCK_STREAM == 1
        guard sock >= 0 else { fatalError("socket() failed") }
        var opt: Int32 = 1
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(UInt16(port).bigEndian)
        // Bind to localhost for safety (only accessible from this machine)
        addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

        let bindResult = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { ptr in
                bind(sock, ptr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult >= 0 else { print("bind failed on port \(port)"); close(sock); return }
        guard listen(sock, 10) >= 0 else { print("listen failed on port \(port)"); close(sock); return }
        print("Listening on port \(port)")
        while true {
            var clientAddr = sockaddr_in()
            var len = socklen_t(MemoryLayout<sockaddr_in>.size)
            let client = withUnsafeMutablePointer(to: &clientAddr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { ptr in
                    accept(sock, ptr, &len)
                }
            }
            if client < 0 { continue }
            DispatchQueue.global().async {
                handleClient(fd: client)
                close(client)
            }
        }
    }
}

func readLine(fd: Int32) -> String? {
    var buf = [UInt8](repeating: 0, count: 8192)
    var idx = 0
    while true {
        let n = read(fd, &buf[idx], 1)
        if n <= 0 { break }
        if buf[idx] == 10 { // \n
            return String(bytes: buf[0..<idx], encoding: .utf8)
        }
        idx += 1
        if idx >= buf.count { break }
    }
    return nil
}

func handleClient(fd: Int32) {
    guard let line = readLine(fd: fd) else { return }
    Task {
        var cmdLine = line.trimmingCharacters(in: .whitespacesAndNewlines)
        let envSecret = ProcessInfo.processInfo.environment["PRIVACY_SHIELD_SECRET"]?.trimmingCharacters(in: .whitespacesAndNewlines)
        var actorUserId: String? = nil

        if let secret = envSecret, !secret.isEmpty {
            if cmdLine == secret {
                let resp = "ERR no command provided after secret\n"
                _ = resp.withCString { ptr in write(fd, ptr, strlen(ptr)) }
                return
            }
            if cmdLine.hasPrefix(secret + " ") {
                // Admin command authenticated
                cmdLine = String(cmdLine.dropFirst(secret.count + 1))
                actorUserId = "admin"
            } else {
                // Try token auth: first token word is token
                let firstWord = cmdLine.split(separator: " ", maxSplits: 1).first.map(String.init) ?? ""
                if !firstWord.isEmpty {
                    if let user = await TokenManager.shared.validate(firstWord) {
                        // strip token from line
                        if cmdLine.count > firstWord.count + 1 {
                            cmdLine = String(cmdLine.dropFirst(firstWord.count + 1))
                        } else {
                            let resp = "ERR no command provided after token\n"
                            _ = resp.withCString { ptr in write(fd, ptr, strlen(ptr)) }
                            return
                        }
                        actorUserId = user
                    } else {
                        let resp = "ERR auth failed\n"
                        _ = resp.withCString { ptr in write(fd, ptr, strlen(ptr)) }
                        return
                    }
                } else {
                    let resp = "ERR auth failed\n"
                    _ = resp.withCString { ptr in write(fd, ptr, strlen(ptr)) }
                    return
                }
            }
        } else {
            // No env secret configured: treat first word as token and attempt validation (optional)
            let firstWord = cmdLine.split(separator: " ", maxSplits: 1).first.map(String.init) ?? ""
            if !firstWord.isEmpty, let user = await TokenManager.shared.validate(firstWord) {
                if cmdLine.count > firstWord.count + 1 {
                    cmdLine = String(cmdLine.dropFirst(firstWord.count + 1))
                    actorUserId = user
                } else {
                    let resp = "ERR no command provided after token\n"
                    _ = resp.withCString { ptr in write(fd, ptr, strlen(ptr)) }
                    return
                }
            }
        }

        let parts = cmdLine.split(separator: " ", maxSplits: 3, omittingEmptySubsequences: false).map(String.init)
        let cmd = parts.first ?? ""
        var response = ""
        switch cmd {
        case "LIST_REQUESTS":
            let reqs = await QuarantineManager.shared.listRequests()
            if let data = try? JSONEncoder().encode(reqs), let s = String(data: data, encoding: .utf8) { response = s }
        case "LIST_AUDIT":
            let events = await AuditLog.shared.allEvents()
            if let data = try? JSONEncoder().encode(events), let s = String(data: data, encoding: .utf8) { response = s }
        case "CREATE_TOKEN":
            // Admin-only: CREATE_TOKEN <userId> <ttlSeconds|0 for none>
            if actorUserId == "admin" {
                if parts.count >= 3, let ttl = Int(parts[2]) {
                    let userId = parts[1]
                    let token = await TokenManager.shared.createToken(userId: userId, ttlSeconds: ttl == 0 ? nil : ttl)
                    response = token.token
                } else { response = "ERR args: CREATE_TOKEN <userId> <ttlSeconds|0>" }
            } else { response = "ERR admin only" }
        case "REVOKE_TOKEN":
            // Admin-only: REVOKE_TOKEN <token>
            if actorUserId == "admin" {
                if parts.count >= 2 {
                    let t = parts[1]
                    let ok = await TokenManager.shared.revokeToken(t, actorId: "admin")
                    response = ok ? "OK" : "ERR not found"
                } else { response = "ERR args" }
            } else { response = "ERR admin only" }
        case "LIST_TOKENS":
            if actorUserId == "admin" {
                let tokens = await TokenManager.shared.listTokens()
                if let data = try? JSONEncoder().encode(tokens), let s = String(data: data, encoding: .utf8) { response = s }
            } else { response = "ERR admin only" }
        case "REQUEST_QUARANTINE":
            if parts.count >= 4 {
                let resource = parts[1]
                let requester = parts[2]
                let justification = parts[3]
                let id = await QuarantineManager.shared.requestQuarantine(resourceId: resource, requesterId: requester, justification: justification)
                response = id.uuidString
            } else {
                response = "ERR Missing args: REQUEST_QUARANTINE <resource> <requester> <justification>"
            }
        case "APPROVE":
            if parts.count >= 3, let uuid = UUID(uuidString: parts[1]) {
                let approver = parts[2]
                if let req = await QuarantineManager.shared.approve(requestId: uuid, approverId: approver) {
                    if let data = try? JSONEncoder().encode(req), let s = String(data: data, encoding: .utf8) { response = s }
                } else { response = "ERR not found" }
            } else { response = "ERR args" }
        case "APPLY":
            if parts.count >= 3, let uuid = UUID(uuidString: parts[1]) {
                let actor = parts[2]
                if let req = await QuarantineManager.shared.applyQuarantine(requestId: uuid, actorId: actor) {
                    if let data = try? JSONEncoder().encode(req), let s = String(data: data, encoding: .utf8) { response = s }
                } else { response = "ERR not allowed" }
            } else { response = "ERR args" }
        case "MARK_READY":
            if parts.count >= 3, let uuid = UUID(uuidString: parts[1]) {
                let actor = parts[2]
                if let req = await QuarantineManager.shared.markReadyForDeletion(requestId: uuid, actorId: actor) {
                    if let data = try? JSONEncoder().encode(req), let s = String(data: data, encoding: .utf8) { response = s }
                } else { response = "ERR not allowed" }
            } else { response = "ERR args" }
        case "GET_REQUEST":
            if parts.count >= 2, let uuid = UUID(uuidString: parts[1]) {
                if let req = await QuarantineManager.shared.getRequest(uuid) {
                    if let data = try? JSONEncoder().encode(req), let s = String(data: data, encoding: .utf8) { response = s }
                } else { response = "ERR not found" }
            } else { response = "ERR args" }
        default:
            response = "ERR unknown command"
        }
        response += "\n"
        _ = response.withCString { ptr in
            write(fd, ptr, strlen(ptr))
        }
    }
}

// Start listeners
for port in ports { startListener(on: port) }

// Keep the main thread alive
RunLoop.current.run()
