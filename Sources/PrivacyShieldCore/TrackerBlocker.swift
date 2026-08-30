import Foundation

public struct TrackerBlocker: Sendable {
    private let blockedDomains: Set<String>

    public init(blockedDomains: Set<String>) {
        self.blockedDomains = Set(blockedDomains.compactMap(Self.normalize))
    }

    public func shouldBlock(host: String) -> Bool {
        guard let normalizedHost = Self.normalize(host) else { return false }

        return blockedDomains.contains { blockedDomain in
            normalizedHost == blockedDomain || normalizedHost.hasSuffix("." + blockedDomain)
        }
    }

    private static func normalize(_ host: String) -> String? {
        let value = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let withoutTrailingDot = value.hasSuffix(".") ? String(value.dropLast()) : value
        guard !withoutTrailingDot.isEmpty,
              withoutTrailingDot.count <= 253,
              withoutTrailingDot.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "." || $0 == "-" ) }),
              !withoutTrailingDot.contains("..") else {
            return nil
        }
        return withoutTrailingDot
    }
}