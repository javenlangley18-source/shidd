import Foundation
import PrivacyShieldCore

// Simple TCP control server — listens on two ports and accepts basic newline-terminated commands.
// Commands: LIST_REQUESTS, LIST_AUDIT, REQUEST_QUARANTINE <resource> <requester> <justification>, APPROVE <id> <approver>, APPLY <id> <actor>, MARK_READY <id> <actor>, GET_REQUEST <id>

let ports = [8080, 9090]

func startListener(on port: Int) {
    DispatchQueue.global().async {
        let sock = socket(AF_INET, SOCK_STREAM, 0)
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
    let parts = line.split(separator: " ", maxSplits: 3, omittingEmptySubsequences: false).map(String.init)
    let cmd = parts.first ?? ""
    Task {
        var response = ""
        switch cmd {
        case "LIST_REQUESTS":
            let reqs = await QuarantineManager.shared.listRequests()
            if let data = try? JSONEncoder().encode(reqs), let s = String(data: data, encoding: .utf8) { response = s }
        case "LIST_AUDIT":
            let events = await AuditLog.shared.allEvents()
            if let data = try? JSONEncoder().encode(events), let s = String(data: data, encoding: .utf8) { response = s }
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
