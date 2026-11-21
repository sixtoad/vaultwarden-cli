/// One request-bound biometric authorization (#60). An attempt belongs to
/// the request id it started on; it stops counting the moment it is retired.
class ApprovalAttempt {
  ApprovalAttempt._(this.requestId, this._epoch);
  final String requestId;
  final int _epoch;
}

/// The lifecycle rule every approval client shares (macOS, Android, iOS):
///
/// * At most one attempt is open. Backgrounding, locking, an interruption,
///   navigation, selecting a request (even the same one again) and any
///   provider invalidation [retire] it.
/// * A completion (a signature returned by the platform) is used only when
///   [admits] says so: the attempt is still the open, unretired one AND the
///   shown review is still for its request id. A late completion after a
///   retirement is never attributed to the next attempt or request, even
///   when the user reopened the same request meanwhile.
///
/// Rust independently refuses a signature for a review prepared before the
/// current one (`StaleHandle`); this rule keeps Dart from even trying.
class ApprovalAttempts {
  int _epoch = 0;
  ApprovalAttempt? _open;

  bool get open => _open != null;

  /// Opens an attempt for [requestId], retiring any earlier one.
  ApprovalAttempt begin(String requestId) =>
      _open = ApprovalAttempt._(requestId, ++_epoch);

  void retire() {
    _epoch++;
    _open = null;
  }

  bool admits(ApprovalAttempt attempt, String shownRequestId) =>
      identical(_open, attempt) &&
      attempt._epoch == _epoch &&
      attempt.requestId == shownRequestId;

  /// Closes [attempt] when it finished (whatever its outcome).
  void end(ApprovalAttempt attempt) {
    if (identical(_open, attempt)) _open = null;
  }
}
