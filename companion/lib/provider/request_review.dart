import 'package:flutter/material.dart';

import '../design/components.dart';
import '../design/metrics.dart';
import '../src/rust/api/provider.dart' as core;
import 'review/authorization_step.dart';
import 'review/consequence.dart';
import 'review/deny_confirm.dart';
import 'review/final_state.dart';
import 'review/request_header.dart';
import 'review/review_session.dart';
import 'review/review_status.dart';
import 'review/scope_facts.dart';
import 'review/validity.dart';

export 'review/review_session.dart' show ReviewStep;

/// Displays Rust's complete escaped projection verbatim; never parses authority
/// or reconstructs arguments, identities, credentials or deadlines from text.
/// Only the status object is read, to choose the view.
class RequestReview extends StatelessWidget {
  const RequestReview({
    super.key,
    required this.state,
    required this.endpoint,
    this.origin = '',
    required this.password,
    required this.onApprove,
    required this.onDeny,
    required this.onClose,
    required this.step,
    required this.onStep,
    required this.left,
    required this.expired,
    required this.onReload,
    this.onActivity,
    this.touchIdOffered = false,
    this.onTouchId,
    this.touchIdNote = '',
    this.touchIdMessage = '',
  });
  final core.ProviderSnapshot state;
  final String endpoint, origin;
  final TextEditingController password;
  final VoidCallback onApprove, onDeny, onClose, onReload;
  final VoidCallback? onActivity;
  final ReviewStep step;
  final ValueChanged<ReviewStep> onStep;

  /// Time left on this review, and whether it ran out (latched by the page:
  /// once expired, this load never admits a decision again).
  final Duration left;
  final bool expired;

  /// Whether this Mac has Touch ID. Without it only the password path shows.
  final bool touchIdOffered;

  /// Null when Touch ID cannot approve this review; `touchIdNote` says why.
  final VoidCallback? onTouchId;
  final String touchIdNote, touchIdMessage;

  /// Whether the provider's status is final (anything but `pending`). An
  /// unreadable status counts as final: no approval controls for it.
  static bool isFinal(String status) => ReviewStatus.parse(status).isFinal;

  @override
  Widget build(BuildContext context) {
    final review = state.review;
    if (review == null) return const SizedBox.shrink();
    final status = ReviewStatus.parse(review.status);
    final scope = [
      ScopeFacts(review: review, endpoint: endpoint, origin: origin),
      const SizedBox(height: 16),
    ];
    final message = [
      if (touchIdMessage.isNotEmpty) ...[
        Text(touchIdMessage, key: const Key('touch-id-message')),
        const SizedBox(height: 16),
      ],
    ];
    return AccessPanel(
      child: Column(
        key: const Key('provider-review'),
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          RequestHeader(review: review, status: status),
          const SizedBox(height: 24),
          if (status.isFinal) ...[
            FinalState(status: status, onBack: onClose, onActivity: onActivity),
            const SizedBox(height: 24),
            ...message,
            ...scope,
            VerificationDetails(review: review),
          ] else ...[
            ...scope,
            Consequence(review: review),
            const SizedBox(height: 24),
            // Always rendered, before any decision control (owner, #50 Q1).
            VerificationDetails(review: review),
            const SizedBox(height: 24),
            ValidityLine(left: left, expired: expired),
            const SizedBox(height: 16),
            ...message,
            _decision(context, review),
          ],
        ],
      ),
    );
  }

  Widget _decision(BuildContext context, core.ProviderReview review) {
    final enabled = state.canDecide && !expired;
    if (expired) {
      // mutation: expired view
      return Column(
        key: const Key('review-expired'),
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const AccessNotice(
            child: Text(
              'This review expired before a decision. Nothing was sent. Reload it to see the request’s current scope and status.',
            ),
          ),
          const SizedBox(height: 16),
          AccessActions(
            children: [
              FilledButton(
                key: const Key('reload-review'),
                onPressed: onReload,
                child: const Text('Reload review'),
              ),
              TextButton(onPressed: onClose, child: const Text('Close review')),
            ],
          ),
        ],
      );
    }
    return switch (step) {
      ReviewStep.authorize => AuthorizationStep(
        review: review,
        password: password,
        enabled: enabled,
        onApprove: onApprove,
        onCancel: () => onStep(ReviewStep.review),
        touchIdOffered: touchIdOffered,
        onTouchId: onTouchId,
        touchIdNote: touchIdNote,
      ),
      ReviewStep.deny => DenyConfirm(
        requestId: review.id,
        enabled: enabled,
        onDeny: onDeny,
        onKeep: () => onStep(ReviewStep.review),
      ),
      ReviewStep.review => _choice(context, enabled),
    };
  }

  /// Deny… and Approve… (the second step follows), then a quiet close.
  Widget _choice(BuildContext context, bool enabled) {
    final small = Theme.of(context).textTheme.labelSmall;
    final deny = OutlinedButton(
      key: const Key('deny-start'),
      onPressed: enabled ? () => onStep(ReviewStep.deny) : null,
      child: const Text('Deny…'),
    );
    final approve = FilledButton(
      key: const Key('approve-start'),
      onPressed: enabled ? () => onStep(ReviewStep.authorize) : null,
      child: const Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Flexible(child: Text('Approve…')),
          SizedBox(width: 12),
          Icon(Icons.arrow_forward, size: 18),
        ],
      ),
    );
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        LayoutBuilder(
          builder: (context, constraints) =>
              constraints.maxWidth < 320 ||
                  AccessMetrics.of(context).largeText(context)
              ? Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [approve, const SizedBox(height: 12), deny],
                )
              : Row(
                  children: [
                    Expanded(flex: 10, child: deny),
                    const SizedBox(width: 12),
                    Expanded(flex: 17, child: approve),
                  ],
                ),
        ),
        const SizedBox(height: 12),
        SizedBox(
          width: double.infinity,
          child: Text(
            touchIdOffered && onTouchId != null
                ? 'Touch ID or password next · approval applies to this request only'
                : 'Password required next · approval applies to this request only',
            textAlign: TextAlign.center,
            style: small,
          ),
        ),
        const SizedBox(height: 8),
        Center(
          child: TextButton(
            key: const Key('close-review'),
            onPressed: onClose,
            child: const Text('Close review'),
          ),
        ),
        SizedBox(
          width: double.infinity,
          child: Text(
            'Closing the review keeps the request pending. Approval and execution completion are separate states.',
            textAlign: TextAlign.center,
            style: small,
          ),
        ),
      ],
    );
  }
}
