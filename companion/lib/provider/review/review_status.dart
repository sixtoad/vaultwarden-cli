import 'dart:convert';

import 'package:flutter/material.dart';

/// The provider's request status (`docs/companion-protocol.md`, DirectStatus).
/// There is no `cancelled` request status: closing a review or cancelling an
/// authorization retires the local ticket, never the request.
enum ReviewPhase {
  pending,
  approved,
  running,
  completed,
  failed,
  denied,
  expired,

  /// Not JSON, not an object, or a status this companion does not know.
  /// Treated as final: no approval controls.
  unreadable,
}

/// The status of one review, read from the raw status JSON Rust projects.
/// Only the status object is read; `effect` and every other scope value are
/// displayed verbatim and never interpreted.
@immutable
class ReviewStatus {
  const ReviewStatus(this.phase, {this.exitCode, this.reason = ''});
  final ReviewPhase phase;

  /// `completed` only; null when the provider did not report an integer.
  final int? exitCode;

  /// `failed` only: the provider's reason string, shown verbatim.
  final String reason;

  static ReviewStatus parse(String raw) {
    Object? decoded;
    try {
      decoded = jsonDecode(raw);
    } catch (_) {
      return const ReviewStatus(ReviewPhase.unreadable);
    }
    if (decoded is! Map<String, dynamic>) {
      return const ReviewStatus(ReviewPhase.unreadable);
    }
    final code = decoded['exit_code'], reason = decoded['reason'];
    return switch (decoded['status']) {
      'pending' => const ReviewStatus(ReviewPhase.pending),
      'approved' => const ReviewStatus(ReviewPhase.approved),
      'running' => const ReviewStatus(ReviewPhase.running),
      'completed' => ReviewStatus(
        ReviewPhase.completed,
        exitCode: code is int ? code : null,
      ),
      'failed' => ReviewStatus(
        ReviewPhase.failed,
        reason: reason is String ? reason : '',
      ),
      'denied' => const ReviewStatus(ReviewPhase.denied),
      'expired' => const ReviewStatus(ReviewPhase.expired),
      _ => const ReviewStatus(ReviewPhase.unreadable),
    };
  }

  /// Anything but `pending` is final for this companion.
  bool get isFinal => phase != ReviewPhase.pending;

  /// Approved or running: the decision is recorded, execution is not done.
  bool get executing =>
      phase == ReviewPhase.approved || phase == ReviewPhase.running;

  /// The status label shown next to the request ID.
  String get label => switch (phase) {
    ReviewPhase.pending => 'Awaiting your approval',
    ReviewPhase.approved => 'Approved · not completed',
    ReviewPhase.running => 'Running · not completed',
    ReviewPhase.completed =>
      exitCode == null
          ? 'Completed · exit code not reported'
          : 'Completed · exit code $exitCode',
    ReviewPhase.failed => 'Failed',
    ReviewPhase.denied => 'Denied',
    ReviewPhase.expired => 'Expired',
    ReviewPhase.unreadable => 'Status not readable',
  };

  IconData get icon => switch (phase) {
    ReviewPhase.pending => Icons.schedule,
    ReviewPhase.approved || ReviewPhase.running => Icons.sync,
    ReviewPhase.completed => Icons.check_circle_outline,
    ReviewPhase.failed => Icons.error_outline,
    ReviewPhase.denied => Icons.block,
    ReviewPhase.expired => Icons.timer_off_outlined,
    ReviewPhase.unreadable => Icons.help_outline,
  };
}
