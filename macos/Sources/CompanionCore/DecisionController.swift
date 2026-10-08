import Combine
import Foundation

/// Holds one visible review. A ticket is removed before the first send and can only
/// be obtained again through an explicit human review action.
@MainActor public final class DecisionController: ObservableObject {
    @Published public private(set) var review: ReviewResponse?
    @Published public private(set) var busy = false
    @Published public private(set) var uncertain = false
    @Published public private(set) var message = "Select a request to review."
    private let client: any CompanionServing
    private var reviewedAt: Date?
    private var unresolvedID: String?
    private var reviewEpoch: UInt64 = 0
    public init(client: any CompanionServing) { self.client = client }
    public func invalidate() { review = nil; reviewedAt = nil; reviewEpoch &+= 1 }
    public func load(_ id: String) async {
        guard !busy else { return }
        if let unresolvedID, unresolvedID != id {
            message = "Resolve the earlier uncertain decision before reviewing another request. Refresh its status or explicitly review that request again."
            return
        }
        busy = true; invalidate()
        let epoch = reviewEpoch
        defer { busy = false }
        do {
            let response = try await client.review(id)
            guard epoch == reviewEpoch else { return }
            review = response; reviewedAt = Date(); uncertain = false; unresolvedID = nil
            message = response.review.status.summary
        } catch {
            guard epoch == reviewEpoch else { return }
            message = uncertain ? "Outcome uncertain: review unavailable. Refresh status; no decision was resent." : "Review unavailable. Refresh the inbox and select again."
        }
    }
    public var canDecide: Bool {
        guard !busy, !uncertain, let review, review.ticket != nil, let reviewedAt else { return false }
        return Date().timeIntervalSince(reviewedAt) < 55 && Date().timeIntervalSince1970 < Double(review.review.expiresAtUnixSeconds)
    }
    public func decide(approve: Bool, password: String?) async {
        guard canDecide, let snapshot = review else { invalidate(); return }
        busy = true; invalidate()
        defer { busy = false }
        do {
            let status = try await client.decide(snapshot, approve: approve, password: password)
            uncertain = false; unresolvedID = nil; message = status.summary
        } catch let error as CompanionError {
            // These codes are emitted only before the provider commits a decision.
            // stale/unavailable can follow commit and must retain uncertainty.
            if case .rejected(let code) = error,
               ["invalid_request", "unauthorized", "authentication_failed", "rate_limited"].contains(code) {
                uncertain = false; unresolvedID = nil; message = "Decision rejected (\(code)). Obtain a fresh review before trying again."
            } else { await recover(snapshot.review.id) }
        } catch { await recover(snapshot.review.id) }
    }
    private func recover(_ id: String) async {
        uncertain = true; unresolvedID = id
        message = "Decision outcome uncertain. Checking status; the decision will not be resent."
        await refreshUncertainStatus()
    }
    public func refreshUncertainStatus() async {
        guard let id = unresolvedID else { return }
        do {
            let status = try await client.status(id)
            guard unresolvedID == id else { return }
            if status.status == "pending" {
                message = "Outcome uncertain: still pending. A new explicit review and decision are required."
            } else {
                uncertain = false; unresolvedID = nil; message = status.summary
            }
        } catch {
            guard unresolvedID == id else { return }
            message = "Outcome uncertain: status unavailable. No decision was resent."
        }
    }
}
