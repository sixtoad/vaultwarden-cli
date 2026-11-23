import '../../src/rust/api/provider.dart' as core;
import 'validity.dart';

/// Where a pending review is: reading it, authorizing (second step of an
/// approval) or confirming a denial. Held by the page for one request ID.
enum ReviewStep { review, authorize, deny }

/// Page-held view state of the review on screen: the authorization or denial
/// step, bound to one request ID, and the countdown of the loaded review.
/// Holds no secret and no authority; Rust still decides admission.
class ReviewSession {
  ReviewStep _step = ReviewStep.review;
  String _stepId = '';
  DateTime? _flightAt;
  bool _seenReview = false, _expired = false;
  String _loadedId = '', _loadedText = '';
  ReviewDeadline? _deadline;

  /// The request last asked for and when: its ticket started no later.
  String _askedId = '';
  DateTime? _askedAt;

  /// The step for the review of [requestId]; any other request reads as the
  /// plain review (the step never follows a selection).
  ReviewStep step(String requestId) {
    final bound = requestId.isNotEmpty && requestId == _stepId;
    return bound ? _step : ReviewStep.review; // mutation: step binding
  }

  void setStep(String requestId, ReviewStep step) {
    _stepId = requestId;
    _step = step;
  }

  /// Selection, navigation, notification, back and suspension close any open
  /// step and forget the last ask: a review loaded afterwards without a new
  /// ask (a notification's) counts from its own flight, never from an older
  /// ask that failed (which would read as expired at once).
  void closeStep() {
    _stepId = '';
    _step = ReviewStep.review;
    _askedId = '';
    _askedAt = null;
  }

  /// A review of [requestId] was asked for at [now]: forget the previous
  /// load, so an expiry latched for it never stands for a load that did not
  /// arrive. Its countdown starts at [now] even when its review replaces
  /// another with no empty snapshot in between.
  void beginLoad(String requestId, DateTime now) {
    closeStep();
    _askedId = requestId;
    _askedAt = now;
    _loadedId = '';
    _loadedText = '';
    _deadline = null;
    _expired = false;
  }

  /// The request whose review was last loaded, and its deadline.
  String get loadedId => _loadedId;
  ReviewDeadline? get deadline => _deadline;

  /// Follows every snapshot. A review appearing (after none, or for another
  /// request) is a new load: its ticket started when the review command went
  /// out, which the first busy snapshot without a review approximates from
  /// above by microseconds (Rust counts from the command's begin).
  ///
  /// Returns true when typed secrets must be cleared: the shown scope changed
  /// under an open step (the step closes; it never carries over to a
  /// different scope), or the countdown has just reached zero.
  bool observe(core.ProviderSnapshot state, DateTime now) {
    final review = state.review;
    if (review == null) {
      _flightAt = state.busy ? (_flightAt ?? now) : null;
      _seenReview = false;
      return false;
    }
    var clear = false;
    if (!_seenReview || state.reviewId != _loadedId) {
      final asked = state.reviewId == _askedId
          ? _askedAt
          : null; // mutation: countdown from request
      if (state.reviewId == _loadedId && state.reviewText != _loadedText) {
        clear = _stepId.isNotEmpty;
        closeStep(); // mutation: changed scope closes step
      }
      _loadedId = state.reviewId;
      _loadedText = state.reviewText;
      _askedId = '';
      _askedAt = null;
      _deadline = ReviewDeadline(
        loadedAt: asked ?? _flightAt ?? now,
        expiresAtUnixSeconds: review.expiresAtUnixSeconds,
      );
      _expired = false;
    }
    _seenReview = true;
    _flightAt = null;
    final before = _expired;
    if (expiredAt(now) && !before) {
      clear = true;
      closeStep();
    }
    return clear;
  }

  /// Whether the loaded review's countdown reached zero. Latched: a clock
  /// moving backwards never re-enables a decision on the same load.
  bool expiredAt(DateTime now) {
    final deadline = _deadline;
    final reached = deadline != null && deadline.expiredAt(now);
    if (reached) _expired = true; // mutation: expiry reached
    return _expired; // mutation: expiry latch
  }

  Duration remaining(DateTime now) =>
      _deadline?.remaining(now) ?? Duration.zero;
}
