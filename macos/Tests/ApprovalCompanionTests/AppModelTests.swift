import XCTest
@testable import ApprovalCompanion
import CompanionCore

private let requestID = String(repeating: "A", count: 43)
private func session(_ state: String = "unlocked", generation: Int = 1) -> Data {
    Data("{\"version\":1,\"state\":\"\(state)\",\"generation\":\(generation)}".utf8)
}
private func inbox() -> Data { Data("{\"version\":1,\"requests\":[\"\(requestID)\"]}".utf8) }
private func reviewData() throws -> Data {
    let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    return try Data(contentsOf: root.appendingPathComponent("tests/fixtures/companion/review.json"))
}
private actor ModelTransport: CompanionTransport {
    private var replies: [Result<Data, CompanionError>]
    private let heldCommand: String?
    private var held: CheckedContinuation<Data, Error>?
    private var waiting: CheckedContinuation<Void, Never>?
    private(set) var commands: [String] = []
    init(_ replies: [Result<Data, CompanionError>] = [], holding: String? = nil) {
        self.replies = replies; heldCommand = holding
    }
    func send(_ body: Data) async throws -> Data {
        let json = try JSONSerialization.jsonObject(with: body) as! [String: Any]
        let command = json["command"] as! String
        commands.append(command)
        if command == heldCommand {
            return try await withCheckedThrowingContinuation {
                held = $0; waiting?.resume(); waiting = nil
            }
        }
        guard !replies.isEmpty else { throw CompanionError.transport }
        return try replies.removeFirst().get()
    }
    func waitUntilHeld() async {
        if held != nil { return }
        await withCheckedContinuation { waiting = $0 }
    }
    func release(_ result: Result<Data, CompanionError>) {
        switch result {
        case .success(let data): held?.resume(returning: data)
        case .failure(let error): held?.resume(throwing: error)
        }
        held = nil
    }
}

final class AppModelTests: XCTestCase {
    @MainActor func testActualPollingInvalidatesReviewForGenerationChangeAndDisconnect() async throws {
        for disconnect in [false, true] {
            var replies: [Result<Data, CompanionError>] = [.success(session()), .success(inbox()), .success(try reviewData())]
            replies += disconnect ? [.failure(.transport)] : [.success(session(generation: 2)), .success(inbox())]
            let transport = ModelTransport(replies)
            let model = AppModel(client: CompanionClient(transport: transport))
            let firstPoll = await model.pollOnce()
            XCTAssertTrue(firstPoll)
            await model.controller?.load(requestID)
            XCTAssertEqual(model.controller?.canDecide, true)
            let nextPoll = await model.pollOnce()
            XCTAssertEqual(nextPoll, !disconnect)
            XCTAssertNil(model.controller?.review)
            XCTAssertEqual(model.controller?.canDecide, false)
            XCTAssertEqual(model.sessionState, disconnect ? "unavailable" : "unlocked")
            await model.controller?.decide(approve: true, password: "must-not-be-sent")
            let commands = await transport.commands
            XCTAssertFalse(commands.contains("decision"))
        }
    }

    @MainActor func testLateUnlockCannotMutateReplacementOrClearItsBusyFlag() async {
        for oldReply in [Result<Data, CompanionError>.success(session()), .failure(.transport)] {
            let old = ModelTransport(holding: "unlock")
            let replacement = ModelTransport(holding: "unlock")
            let model = AppModel(client: CompanionClient(transport: old))
            let oldTask = Task { await model.unlock("old-transient") }
            await old.waitUntilHeld()
            model.replaceClient(CompanionClient(transport: replacement))
            let newTask = Task { await model.unlock("new-transient") }
            await replacement.waitUntilHeld()
            let connection = model.connection
            await old.release(oldReply)
            await oldTask.value
            XCTAssertTrue(model.unlockBusy, "old cleanup must not clear replacement operation")
            XCTAssertEqual(model.sessionState, "unavailable")
            XCTAssertEqual(model.connection, connection)
            await replacement.release(.success(session()))
            await newTask.value
            XCTAssertFalse(model.unlockBusy)
            XCTAssertEqual(model.sessionState, "unlocked")
        }
    }

    @MainActor func testLateUnlockCannotUndoSleepOrRefresh() async {
        for sleep in [false, true] {
            for reply in [Result<Data, CompanionError>.success(session()), .failure(.transport)] {
                let transport = ModelTransport(holding: "unlock")
                let model = AppModel(client: CompanionClient(transport: transport))
                let task = Task { await model.unlock("transient") }
                await transport.waitUntilHeld()
                if sleep { model.sleeping() } else { model.start() }
                let connection = model.connection
                await transport.release(reply)
                await task.value
                XCTAssertEqual(model.sessionState, "unavailable")
                XCTAssertEqual(model.connection, connection)
                XCTAssertFalse(model.unlockBusy)
            }
        }
    }

    @MainActor func testLateNotificationSessionOrListCannotUndoLifecycleChange() async {
        for command in ["session", "list"] {
            for change in ["sleep", "refresh", "replacement"] {
                for fail in [false, true] {
                    let transport = ModelTransport(command == "list" ? [.success(session())] : [], holding: command)
                    let model = AppModel(client: CompanionClient(transport: transport))
                    let task = Task { await model.openNotificationReview() }
                    await transport.waitUntilHeld()
                    switch change {
                    case "sleep": model.sleeping()
                    case "refresh": model.start()
                    default: model.replaceClient(CompanionClient(transport: ModelTransport()))
                    }
                    let connection = model.connection
                    await transport.release(fail ? .failure(.transport) : .success(command == "session" ? session() : inbox()))
                    await task.value
                    XCTAssertEqual(model.sessionState, "unavailable")
                    XCTAssertEqual(model.connection, connection)
                    XCTAssertTrue(model.pending.isEmpty)
                    XCTAssertNil(model.controller?.review)
                    let commands = await transport.commands
                    XCTAssertFalse(commands.contains("review"))
                }
            }
        }
    }

    @MainActor func testSleepDuringNotificationReviewLoadingCannotRestoreReview() async throws {
        for fail in [false, true] {
            let transport = ModelTransport([.success(session()), .success(inbox())], holding: "review")
            let model = AppModel(client: CompanionClient(transport: transport))
            let task = Task { await model.openNotificationReview() }
            await transport.waitUntilHeld()
            model.sleeping()
            let message = model.controller?.message
            await transport.release(fail ? .failure(.transport) : .success(try reviewData()))
            await task.value
            XCTAssertEqual(model.sessionState, "unavailable")
            XCTAssertEqual(model.connection, "Sleeping. Inbox refreshes after wake.")
            XCTAssertTrue(model.pending.isEmpty)
            XCTAssertNil(model.controller?.review)
            XCTAssertEqual(model.controller?.canDecide, false)
            XCTAssertEqual(model.controller?.message, message)
        }
    }

    @MainActor func testLatePollCannotMutateReplacementOrSleepingState() async {
        for replace in [false, true] {
            for fail in [false, true] {
                let transport = ModelTransport(holding: "session")
                let model = AppModel(client: CompanionClient(transport: transport))
                let task = Task { await model.pollOnce() }
                await transport.waitUntilHeld()
                if replace { model.replaceClient(CompanionClient(transport: ModelTransport())) }
                else { model.sleeping() }
                let connection = model.connection
                await transport.release(fail ? .failure(.transport) : .success(session()))
                let connected = await task.value
                XCTAssertFalse(connected)
                XCTAssertEqual(model.sessionState, "unavailable")
                XCTAssertEqual(model.connection, connection)
            }
        }
    }

    @MainActor func testUnlockPasswordClearsOnSessionProviderAndLifecycleChanges() async {
        let transport = ModelTransport([
            .success(session("locked")), .success(session("locked")),
            .success(session("locked", generation: 2)),
            .success(session("unlocked", generation: 2)), .success(inbox()), .failure(.transport)
        ])
        let model = AppModel(client: CompanionClient(transport: transport))
        await model.pollOnce()
        model.unlockPassword = "transient"
        await model.pollOnce()
        XCTAssertEqual(model.unlockPassword, "transient", "an unchanged locked poll keeps active input")
        await model.pollOnce()
        XCTAssertEqual(model.unlockPassword, "", "a changed authority generation clears input")
        model.unlockPassword = "transient"
        await model.pollOnce()
        XCTAssertEqual(model.unlockPassword, "", "hidden locked controls cannot retain a password")
        model.unlockPassword = "transient"
        await model.pollOnce()
        XCTAssertEqual(model.unlockPassword, "", "disconnect clears input")
        model.unlockPassword = "transient"; model.start()
        XCTAssertEqual(model.unlockPassword, "")
        model.unlockPassword = "transient"; model.sleeping()
        XCTAssertEqual(model.unlockPassword, "")
        model.unlockPassword = "transient"
        model.replaceClient(CompanionClient(transport: ModelTransport()))
        XCTAssertEqual(model.unlockPassword, "")
    }

    @MainActor func testFullInboxExplainsCapacity() async {
        let model = AppModel(client: CompanionClient(transport: ModelTransport()))
        XCTAssertNil(model.inboxCapacityExplanation)
        model.pending = Array(repeating: requestID, count: 255)
        XCTAssertNil(model.inboxCapacityExplanation)
        model.pending.append(requestID)
        XCTAssertEqual(model.inboxCapacityExplanation, "Showing up to 256 pending requests. Later requests appear as slots become available.")
    }
}
