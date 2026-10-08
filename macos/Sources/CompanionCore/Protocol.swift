import Foundation

public enum CompanionError: Error, Equatable, LocalizedError {
    case configuration, invalidResponse, oversized, transport, rejected(String)
    public var errorDescription: String? {
        switch self {
        case .configuration: return "Trusted setup is incomplete or invalid."
        case .invalidResponse: return "Provider returned an invalid response."
        case .oversized: return "Provider response exceeded the size limit."
        case .transport: return "Provider unavailable or TLS authentication failed."
        case .rejected(let code): return "Provider rejected the request: \(code)."
        }
    }
}

public func validHex(_ value: String, count: Int) -> Bool {
    value.utf8.count == count && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
}
public func validRequestID(_ value: String) -> Bool {
    value.utf8.count == 43 && value.utf8.allSatisfy {
        (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 95
    }
}

/// JSONDecoder normally ignores unknown keys. Every v1 object is closed, including
/// nested review metadata and status variants, so validate the original key set.
private struct WireKey: CodingKey {
    let stringValue: String
    var intValue: Int? { nil }
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { return nil }
}
private func requireKeys(_ decoder: Decoder, _ expected: Set<String>) throws {
    let container = try decoder.container(keyedBy: WireKey.self)
    guard Set(container.allKeys.map(\.stringValue)) == expected else { throw CompanionError.invalidResponse }
}

public struct DirectStatus: Decodable, Equatable, Sendable {
    public let status: String
    public let exitCode: UInt8?
    public let reason: String?
    enum CodingKeys: String, CodingKey { case status, exitCode = "exit_code", reason }
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        status = try c.decode(String.self, forKey: .status)
        exitCode = try c.decodeIfPresent(UInt8.self, forKey: .exitCode)
        reason = try c.decodeIfPresent(String.self, forKey: .reason)
        switch status {
        case "pending", "approved", "denied", "expired", "running":
            try requireKeys(decoder, ["status"])
        case "completed":
            try requireKeys(decoder, ["status", "exit_code"])
            guard exitCode != nil else { throw CompanionError.invalidResponse }
        case "failed":
            try requireKeys(decoder, ["status", "reason"])
            guard let reason, ["review_unavailable", "execution_unavailable", "execution_rejected", "execution_nonzero", "execution_signaled"].contains(reason) else { throw CompanionError.invalidResponse }
        default: throw CompanionError.invalidResponse
        }
    }
    public var summary: String {
        if let exitCode { return "\(status) (exit \(exitCode))" }
        if let reason { return "\(status): \(reason)" }
        return status
    }
}

public struct ReviewCredential: Decodable, Equatable, Sendable {
    public let label: String
    public let useType: String
    enum CodingKeys: String, CodingKey { case label, useType = "use_type" }
    public init(from decoder: Decoder) throws {
        try requireKeys(decoder, ["label", "use_type"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        label = try c.decode(String.self, forKey: .label)
        useType = try c.decode(String.self, forKey: .useType)
    }
}
public struct DirectReview: Decodable, Equatable, Sendable, Identifiable {
    public let id: String
    public let requester: String
    public let operation: String
    public let effect: String
    public let target: String
    public let arguments: [String]
    public let credentials: [ReviewCredential]
    public let executableDigest: String
    public let policyDigest: String
    public let argumentsDigest: String
    public let expiresAtUnixSeconds: UInt64
    public let oneTime: String
    public let status: DirectStatus
    enum CodingKeys: String, CodingKey {
        case id, requester, operation, effect, target, arguments, credentials, status
        case executableDigest = "executable_digest", policyDigest = "policy_digest"
        case argumentsDigest = "arguments_digest", expiresAtUnixSeconds = "expires_at_unix_seconds", oneTime = "one_time"
    }
    public init(from decoder: Decoder) throws {
        try requireKeys(decoder, ["id", "requester", "operation", "effect", "target", "arguments", "credentials", "executable_digest", "policy_digest", "arguments_digest", "expires_at_unix_seconds", "one_time", "status"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        requester = try c.decode(String.self, forKey: .requester)
        operation = try c.decode(String.self, forKey: .operation)
        effect = try c.decode(String.self, forKey: .effect)
        target = try c.decode(String.self, forKey: .target)
        arguments = try c.decode([String].self, forKey: .arguments)
        credentials = try c.decode([ReviewCredential].self, forKey: .credentials)
        executableDigest = try c.decode(String.self, forKey: .executableDigest)
        policyDigest = try c.decode(String.self, forKey: .policyDigest)
        argumentsDigest = try c.decode(String.self, forKey: .argumentsDigest)
        expiresAtUnixSeconds = try c.decode(UInt64.self, forKey: .expiresAtUnixSeconds)
        oneTime = try c.decode(String.self, forKey: .oneTime)
        status = try c.decode(DirectStatus.self, forKey: .status)
    }
    public func validate() throws {
        guard validRequestID(id), [executableDigest, policyDigest, argumentsDigest].allSatisfy({ validHex($0, count: 64) }) else { throw CompanionError.invalidResponse }
    }
}
public struct SessionResponse: Decodable, Sendable {
    public let version: Int
    public let state: String
    public let generation: UInt64
    enum CodingKeys: String, CodingKey { case version, state, generation }
    public init(from decoder: Decoder) throws {
        try requireKeys(decoder, ["version", "state", "generation"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        version = try c.decode(Int.self, forKey: .version)
        state = try c.decode(String.self, forKey: .state)
        generation = try c.decode(UInt64.self, forKey: .generation)
    }
}
public struct ReviewResponse: Decodable, Sendable {
    public let version: Int
    public let review: DirectReview
    public let ticket: String?
    public let generation: UInt64
    enum CodingKeys: String, CodingKey { case version, review, ticket, generation }
    public init(from decoder: Decoder) throws {
        try requireKeys(decoder, ["version", "review", "ticket", "generation"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        version = try c.decode(Int.self, forKey: .version)
        review = try c.decode(DirectReview.self, forKey: .review)
        ticket = try c.decodeIfPresent(String.self, forKey: .ticket)
        generation = try c.decode(UInt64.self, forKey: .generation)
    }
}
struct ListResponse: Decodable {
    let version: Int; let requests: [String]
    enum CodingKeys: String, CodingKey { case version, requests }
    init(from decoder: Decoder) throws {
        try requireKeys(decoder, ["version", "requests"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        version = try c.decode(Int.self, forKey: .version)
        requests = try c.decode([String].self, forKey: .requests)
    }
}
struct StatusResponse: Decodable {
    let version: Int; let status: DirectStatus
    enum CodingKeys: String, CodingKey { case version, status }
    init(from decoder: Decoder) throws {
        try requireKeys(decoder, ["version", "status"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        version = try c.decode(Int.self, forKey: .version)
        status = try c.decode(DirectStatus.self, forKey: .status)
    }
}
struct ErrorResponse: Decodable {
    let version: Int; let error: String
    static let httpStatus = ["invalid_request": 400, "unauthorized": 403, "stale": 409,
                           "authentication_failed": 422, "rate_limited": 429, "unavailable": 503]
    enum CodingKeys: String, CodingKey { case version, error }
    init(from decoder: Decoder) throws {
        try requireKeys(decoder, ["version", "error"])
        let c = try decoder.container(keyedBy: CodingKeys.self)
        version = try c.decode(Int.self, forKey: .version)
        error = try c.decode(String.self, forKey: .error)
        guard version == 1, Self.httpStatus[error] != nil else { throw CompanionError.invalidResponse }
    }
}

public struct Command: Encodable, Sendable {
    let version = 1
    let command: String
    let requestID: String?
    let ticket: String?
    let decision: String?
    let password: String?
    enum CodingKeys: String, CodingKey { case version, command, requestID = "request_id", ticket, decision, password }
    init(_ command: String, requestID: String? = nil, ticket: String? = nil, decision: String? = nil, password: String? = nil) {
        self.command = command; self.requestID = requestID; self.ticket = ticket; self.decision = decision; self.password = password
    }
}

public protocol CompanionTransport: Sendable {
    func send(_ body: Data) async throws -> Data
}
public protocol CompanionServing: Sendable {
    func session() async throws -> SessionResponse
    func list() async throws -> [String]
    func review(_ id: String) async throws -> ReviewResponse
    func status(_ id: String) async throws -> DirectStatus
    func decide(_ review: ReviewResponse, approve: Bool, password: String?) async throws -> DirectStatus
    func unlock(_ password: String) async throws -> SessionResponse
}
public struct CompanionClient: CompanionServing {
    private let transport: any CompanionTransport
    public init(transport: any CompanionTransport) { self.transport = transport }
    private func request<T: Decodable>(_ command: Command, as: T.Type) async throws -> T {
        let data = try JSONEncoder().encode(command)
        guard data.count <= 16_384 else { throw CompanionError.oversized }
        let response = try await transport.send(data)
        guard response.count <= 1_048_576 else { throw CompanionError.oversized }
        let decoder = JSONDecoder()
        if let error = try? decoder.decode(ErrorResponse.self, from: response) {
            throw CompanionError.rejected(error.error)
        }
        return try decoder.decode(T.self, from: response)
    }
    public func session() async throws -> SessionResponse {
        let r = try await request(Command("session"), as: SessionResponse.self)
        try validate(r); return r
    }
    private func validate(_ r: SessionResponse) throws {
        guard r.version == 1, ["locked", "unlocked"].contains(r.state) else { throw CompanionError.invalidResponse }
    }
    public func list() async throws -> [String] {
        let r = try await request(Command("list"), as: ListResponse.self)
        guard r.version == 1, r.requests.count <= 256, r.requests.allSatisfy(validRequestID), Set(r.requests).count == r.requests.count else { throw CompanionError.invalidResponse }
        return r.requests
    }
    public func review(_ id: String) async throws -> ReviewResponse {
        guard validRequestID(id) else { throw CompanionError.invalidResponse }
        let r = try await request(Command("review", requestID: id), as: ReviewResponse.self)
        try r.review.validate()
        guard r.version == 1, r.review.id == id, r.ticket.map({ validHex($0, count: 64) }) ?? true,
              r.ticket == nil || r.review.status.status == "pending" else { throw CompanionError.invalidResponse }
        return r
    }
    public func status(_ id: String) async throws -> DirectStatus {
        guard validRequestID(id) else { throw CompanionError.invalidResponse }
        let r = try await request(Command("status", requestID: id), as: StatusResponse.self)
        guard r.version == 1 else { throw CompanionError.invalidResponse }; return r.status
    }
    public func decide(_ review: ReviewResponse, approve: Bool, password: String?) async throws -> DirectStatus {
        guard let ticket = review.ticket, validHex(ticket, count: 64), validRequestID(review.review.id), review.review.status.status == "pending" else { throw CompanionError.invalidResponse }
        if approve { try validatePassword(password) }
        let r = try await request(Command("decision", requestID: review.review.id, ticket: ticket, decision: approve ? "approve" : "deny", password: approve ? password : nil), as: StatusResponse.self)
        guard r.version == 1 else { throw CompanionError.invalidResponse }; return r.status
    }
    public func unlock(_ password: String) async throws -> SessionResponse {
        try validatePassword(password)
        let r = try await request(Command("unlock", password: password), as: SessionResponse.self)
        try validate(r); return r
    }
    private func validatePassword(_ value: String?) throws {
        guard let value, !value.isEmpty, value.utf8.count <= 4096 else { throw CompanionError.configuration }
    }
}

/// Render canonical text visibly without letting directional or invisible Unicode
/// change what an operator thinks is being authorized. Literal escapes remain
/// distinguishable from escaped scalars, and quotes expose empty/edge whitespace.
public func visibleReviewText(_ value: String) -> String {
    var result = "\""
    for scalar in value.unicodeScalars {
        switch scalar.value {
        case 0x22: result += "\\\""
        case 0x5c: result += "\\\\"
        default:
            if scalar.properties.isDefaultIgnorableCodePoint {
                result += String(format: "\\u{%04x}", scalar.value)
                continue
            }
            switch scalar.properties.generalCategory {
            case .control, .format, .lineSeparator, .paragraphSeparator:
                result += String(format: "\\u{%04x}", scalar.value)
            default: result.unicodeScalars.append(scalar)
            }
        }
    }
    return result + "\""
}
