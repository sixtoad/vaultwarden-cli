import XCTest
@testable import CompanionCore

func sharedReviewData() throws -> Data {
    let source = URL(fileURLWithPath: #filePath)
    let root = source.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    return try Data(contentsOf: root.appendingPathComponent("tests/fixtures/companion/review.json"))
}
func fixtureReview() throws -> ReviewResponse { try JSONDecoder().decode(ReviewResponse.self, from: sharedReviewData()) }

actor ScriptedTransport: CompanionTransport {
    var commands: [String] = []
    var replies: [Result<Data, CompanionError>]
    init(_ replies: [Result<Data, CompanionError>]) { self.replies = replies }
    func send(_ body: Data) async throws -> Data {
        let value = try JSONSerialization.jsonObject(with: body) as! [String: Any]
        commands.append(value["command"] as! String)
        guard !replies.isEmpty else { throw CompanionError.transport }
        return try replies.removeFirst().get()
    }
}
actor HeldReviewTransport: CompanionTransport {
    private var pending: CheckedContinuation<Data, Error>?
    private var started: CheckedContinuation<Void, Never>?
    func send(_ body: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            pending = continuation; started?.resume(); started = nil
        }
    }
    func waitForRequest() async {
        if pending != nil { return }
        await withCheckedContinuation { started = $0 }
    }
    func release(_ data: Data) { pending?.resume(returning: data); pending = nil }
    func fail() { pending?.resume(throwing: CompanionError.transport); pending = nil }
}
final class ProtocolTests: XCTestCase {
    func testSharedCanonicalReviewIncludesEveryField() throws {
        let response = try fixtureReview()
        let review = response.review
        try review.validate()
        XCTAssertEqual(response.version, 1)
        XCTAssertEqual(response.generation, 1)
        XCTAssertEqual(response.ticket, String(repeating: "d", count: 64))
        XCTAssertEqual(review.id, String(repeating: "A", count: 43))
        XCTAssertEqual(review.requester, "agent synthetic (synthetic fingerprint)")
        XCTAssertEqual(review.operation, "deploy")
        XCTAssertEqual(review.effect, "Deploy synthetic application")
        XCTAssertEqual(review.target, "staging")
        XCTAssertEqual(review.arguments, ["staging"])
        XCTAssertEqual(review.credentials.first?.label, "Synthetic login")
        XCTAssertEqual(review.credentials.first?.useType, "login")
        XCTAssertEqual(review.executableDigest, String(repeating: "a", count: 64))
        XCTAssertEqual(review.policyDigest, String(repeating: "b", count: 64))
        XCTAssertEqual(review.argumentsDigest, String(repeating: "c", count: 64))
        XCTAssertEqual(review.expiresAtUnixSeconds, 2_000_000_000)
        XCTAssertEqual(review.oneTime, "Approve this operation once")
        XCTAssertEqual(review.status.summary, "pending")
    }
    func testReviewTextExposesInvisibleAndDirectionalScalars() {
        XCTAssertEqual(visibleReviewText(""), "\"\"")
        XCTAssertEqual(visibleReviewText(" staging "), "\" staging \"")
        XCTAssertEqual(visibleReviewText("agent\u{202e}evil\u{2069}"), "\"agent\\u{202e}evil\\u{2069}\"")
        XCTAssertEqual(visibleReviewText("label\u{200b}\n"), "\"label\\u{200b}\\u{000a}\"")
        XCTAssertNotEqual(visibleReviewText("\u{202e}"), visibleReviewText("\\u{202e}"))
        for scalar in ["\u{034f}", "\u{fe0f}", "\u{115f}"] {
            let escape = String(format: "\\u{%04x}", scalar.unicodeScalars.first!.value)
            XCTAssertEqual(visibleReviewText("a" + scalar + "b"), "\"a" + escape + "b\"")
            XCTAssertNotEqual(visibleReviewText(scalar), visibleReviewText(escape))
        }
        XCTAssertEqual(visibleReviewText("ordinary café"), "\"ordinary café\"")
    }
    func testInvalidStatusesFailClosed() throws {
        for json in ["{\"status\":\"completed\",\"exit_code\":256}", "{\"status\":\"completed\"}", "{\"status\":\"pending\",\"reason\":\"execution_nonzero\"}", "{\"status\":\"failed\",\"reason\":\"unknown\"}", "{\"status\":\"unknown\"}"] {
            XCTAssertThrowsError(try JSONDecoder().decode(DirectStatus.self, from: Data(json.utf8)))
        }
    }
    func testClosedV1ResponseAndNestedReviewKeys() throws {
        let fixture = try JSONSerialization.jsonObject(with: sharedReviewData()) as! [String: Any]
        for location in ["response", "review", "credential", "status", "ticket"] {
            var value = fixture
            var review = value["review"] as! [String: Any]
            switch location {
            case "response": value["unknown"] = NSNull()
            case "review": review["unknown"] = NSNull(); value["review"] = review
            case "credential":
                var credentials = review["credentials"] as! [[String: Any]]
                credentials[0]["unknown"] = NSNull(); review["credentials"] = credentials; value["review"] = review
            case "status":
                var status = review["status"] as! [String: Any]
                status["unknown"] = NSNull(); review["status"] = status; value["review"] = review
            default: value.removeValue(forKey: "ticket")
            }
            XCTAssertThrowsError(try JSONDecoder().decode(ReviewResponse.self, from: JSONSerialization.data(withJSONObject: value)), location)
        }
        var withoutTicket = fixture; withoutTicket["ticket"] = NSNull()
        XCTAssertNil(try JSONDecoder().decode(ReviewResponse.self, from: JSONSerialization.data(withJSONObject: withoutTicket)).ticket)
        XCTAssertThrowsError(try JSONDecoder().decode(SessionResponse.self, from: Data(#"{"version":1,"state":"unlocked","generation":1,"unknown":null}"#.utf8)))
        XCTAssertThrowsError(try JSONDecoder().decode(ListResponse.self, from: Data(#"{"version":1,"requests":[],"unknown":null}"#.utf8)))
        XCTAssertThrowsError(try JSONDecoder().decode(StatusResponse.self, from: Data(#"{"version":1,"status":{"status":"pending"},"unknown":null}"#.utf8)))
        XCTAssertThrowsError(try JSONDecoder().decode(ErrorResponse.self, from: Data(#"{"version":1,"error":"stale","unknown":null}"#.utf8)))
        for json in [#"{"status":"pending","exit_code":null}"#, #"{"status":"completed","exit_code":0,"reason":null}"#, #"{"status":"failed","reason":"execution_nonzero","exit_code":null}"#] {
            XCTAssertThrowsError(try JSONDecoder().decode(DirectStatus.self, from: Data(json.utf8)))
        }
    }
    @MainActor func testAmbiguousProviderErrorsUseOnlyStatusAndNeverResend() async throws {
        for code in ["stale", "unavailable"] {
            let statusReplies: [Result<Data, CompanionError>] = [
                .success(Data(#"{"version":1,"status":{"status":"pending"}}"#.utf8)),
                .failure(.transport)
            ]
            for statusReply in statusReplies {
                let transport = ScriptedTransport([
                    .success(try sharedReviewData()),
                    .success(Data("{\"version\":1,\"error\":\"\(code)\"}".utf8)), statusReply
                ])
                let controller = DecisionController(client: CompanionClient(transport: transport))
                await controller.load(try fixtureReview().review.id)
                await controller.decide(approve: true, password: "synthetic-only")
                XCTAssertTrue(controller.uncertain, code)
                XCTAssertFalse(controller.canDecide)
                XCTAssertNil(controller.review)
                await controller.decide(approve: true, password: "must-not-be-sent")
                let commands = await transport.commands
                XCTAssertEqual(commands, ["review", "decision", "status"])
            }
        }
    }
    @MainActor func testDifferentSelectionPreservesUnresolvedDecisionUntilItsStatusIsKnown() async throws {
        let transport = ScriptedTransport([
            .success(try sharedReviewData()), .failure(.transport),
            .failure(.transport),
            .success(Data(#"{"version":1,"status":{"status":"completed","exit_code":0}}"#.utf8))
        ])
        let controller = DecisionController(client: CompanionClient(transport: transport))
        await controller.load(try fixtureReview().review.id)
        await controller.decide(approve: true, password: "synthetic-only")
        await controller.load(String(repeating: "B", count: 43))
        XCTAssertTrue(controller.uncertain)
        XCTAssertNil(controller.review)
        XCTAssertFalse(controller.canDecide)
        await controller.refreshUncertainStatus()
        XCTAssertFalse(controller.uncertain)
        XCTAssertEqual(controller.message, "completed (exit 0)")
        let commands = await transport.commands
        XCTAssertEqual(commands, ["review", "decision", "status", "status"])
    }
    @MainActor func testExplicitSameRequestReviewCanRecoverPendingUncertainty() async throws {
        let transport = ScriptedTransport([
            .success(try sharedReviewData()), .failure(.transport),
            .success(Data(#"{"version":1,"status":{"status":"pending"}}"#.utf8)),
            .success(try sharedReviewData())
        ])
        let controller = DecisionController(client: CompanionClient(transport: transport))
        let id = try fixtureReview().review.id
        await controller.load(id)
        await controller.decide(approve: true, password: "synthetic-only")
        await controller.load(id)
        XCTAssertFalse(controller.uncertain)
        XCTAssertTrue(controller.canDecide)
        let commands = await transport.commands
        XCTAssertEqual(commands, ["review", "decision", "status", "review"])
    }
    @MainActor func testLateReviewErrorCannotMutateInvalidatedMessage() async throws {
        let transport = HeldReviewTransport()
        let controller = DecisionController(client: CompanionClient(transport: transport))
        let id = try fixtureReview().review.id
        let load = Task { await controller.load(id) }
        await transport.waitForRequest()
        controller.invalidate()
        let before = controller.message
        await transport.fail()
        await load.value
        XCTAssertEqual(controller.message, before)
        XCTAssertNil(controller.review)
    }
    func testBoundedInputAndVersion() async throws {
        let transport = ScriptedTransport([.success(Data("{\"version\":2,\"state\":\"unlocked\",\"generation\":1}".utf8))])
        let client = CompanionClient(transport: transport)
        do { _ = try await client.session(); XCTFail("accepted wrong version") } catch {}
        do { _ = try await client.unlock(String(repeating: "x", count: 4097)); XCTFail("accepted oversized password") } catch {}
        do { _ = try await client.review("../invalid"); XCTFail("accepted invalid request id") } catch {}
        let commands = await transport.commands
        XCTAssertEqual(commands, ["session"])
    }
    @MainActor func testLostDecisionNeverResendsAndPendingRemainsUncertain() async throws {
        let transport = ScriptedTransport([
            .success(try sharedReviewData()), .failure(.transport),
            .success(Data("{\"version\":1,\"status\":{\"status\":\"pending\"}}".utf8))
        ])
        let controller = DecisionController(client: CompanionClient(transport: transport))
        await controller.load(try fixtureReview().review.id)
        XCTAssertTrue(controller.canDecide)
        await controller.decide(approve: true, password: "synthetic-only")
        XCTAssertTrue(controller.uncertain)
        XCTAssertNil(controller.review)
        await controller.decide(approve: true, password: "must-not-be-sent")
        let commands = await transport.commands
        XCTAssertEqual(commands, ["review", "decision", "status"])
    }
    @MainActor func testWrongPasswordConsumesVisibleTicket() async throws {
        let transport = ScriptedTransport([.success(try sharedReviewData()), .success(Data("{\"version\":1,\"error\":\"authentication_failed\"}".utf8))])
        let controller = DecisionController(client: CompanionClient(transport: transport))
        await controller.load(try fixtureReview().review.id)
        await controller.decide(approve: true, password: "synthetic-wrong")
        XCTAssertNil(controller.review)
        XCTAssertFalse(controller.uncertain)
        XCTAssertFalse(controller.canDecide)
        let commands = await transport.commands
        XCTAssertEqual(commands, ["review", "decision"])
    }
    @MainActor func testLateReviewCannotUndoAuthorityInvalidation() async throws {
        let transport = HeldReviewTransport()
        let controller = DecisionController(client: CompanionClient(transport: transport))
        let id = try fixtureReview().review.id
        let load = Task { await controller.load(id) }
        await transport.waitForRequest()
        controller.invalidate()
        await transport.release(try sharedReviewData())
        await load.value
        XCTAssertNil(controller.review)
        XCTAssertFalse(controller.canDecide)
    }
    @MainActor func testGenerationOrDisconnectInvalidationDisablesDecision() async throws {
        let transport = ScriptedTransport([.success(try sharedReviewData())])
        let controller = DecisionController(client: CompanionClient(transport: transport))
        await controller.load(try fixtureReview().review.id)
        controller.invalidate()
        await controller.decide(approve: true, password: "must-not-be-sent")
        let commands = await transport.commands
        XCTAssertEqual(commands, ["review"])
    }
}
