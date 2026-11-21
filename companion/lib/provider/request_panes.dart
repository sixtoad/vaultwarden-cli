import 'dart:async';

import 'package:flutter/material.dart';

import '../design/components.dart';
import '../design/typography.dart';
import 'controller.dart';
import 'request_review.dart';
import 'review/latest_status.dart';
import 'review/review_status.dart';
import 'review/review_session.dart';
import 'requests_view.dart';
import 'touch_id.dart';

/// The pending list: configuration and lock state, unlock (separate from
/// approval), refresh and one row per pending request ID.
class RequestListPane extends StatelessWidget {
  const RequestListPane({
    super.key,
    required this.controller,
    required this.unlockPassword,
    required this.notificationNote,
    required this.selectedId,
    required this.onUnlock,
    required this.onOpenRequest,
    required this.onOpenSettings,
  });
  final ProviderController controller;
  final TextEditingController unlockPassword;
  final String notificationNote, selectedId;
  final VoidCallback onUnlock, onOpenSettings;
  final ValueChanged<String> onOpenRequest;
  @override
  Widget build(BuildContext context) {
    final state = controller.state, config = controller.configuration;
    final kicker = AccessType.of(context).kicker;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        if (!config.configured) ...[
          const Text(
            'Connect a dedicated development identity in Settings to load requests.',
          ),
          const SizedBox(height: 16),
          OutlinedButton(
            onPressed: onOpenSettings,
            child: const Text('Open advanced setup'),
          ),
        ] else ...[
          StatusLabel(
            state.locked
                ? 'Provider locked or authority not refreshed'
                : 'Provider unlocked',
            icon: state.locked ? Icons.lock_outline : Icons.lock_open,
          ),
          const SizedBox(height: 16),
          if (state.locked && controller.recoveryId.isEmpty) ...[
            AccessNotice(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text(
                    'Unlock is separate from approval. After unlocking, the agent must submit a new request.',
                  ),
                  const SizedBox(height: 12),
                  accessPassword(unlockPassword, 'Provider unlock password'),
                  const SizedBox(height: 12),
                  OutlinedButton(
                    onPressed: controller.busy ? null : onUnlock,
                    child: const Text('Unlock provider'),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 12),
          ],
          OutlinedButton(
            onPressed: controller.busy ? null : controller.refresh,
            child: const Text('Refresh authority and inbox'),
          ),
          if (notificationNote.isNotEmpty) ...[
            const SizedBox(height: 16),
            Text(notificationNote, key: const Key('notification-note')),
          ],
          const SizedBox(height: 24),
          Semantics(
            label: 'Pending requests: ${state.requests.length} of 256 maximum',
            excludeSemantics: true,
            child: Text(
              'PENDING · ${state.requests.length} OF 256 MAX',
              style: kicker,
            ),
          ),
          Text(
            'The provider caps the inbox at 256; this is not pagination.',
            style: Theme.of(context).textTheme.labelSmall,
          ),
          const SizedBox(height: 12),
          if (state.requests.isEmpty)
            const Text('No pending request IDs are currently available.'),
          for (final id in state.requests)
            RequestRow(
              id: id,
              selected: id == selectedId,
              status: _knownStatus(id),
              onOpen:
                  controller.busy ||
                      state.locked ||
                      controller.recoveryId.isNotEmpty
                  ? null
                  : () => onOpenRequest(id),
            ),
        ],
      ],
    );
  }

  /// The freshest final status the companion holds for an inbox ID: the open
  /// review's, else the latest status after a decision or status check. The
  /// inbox lists pending IDs only, so anything unknown, unreadable or still
  /// pending shows as pending until the next inbox read drops a final one.
  ReviewStatus _knownStatus(String id) {
    final state = controller.state;
    final review = state.review;
    final raw = review != null && state.reviewId == id
        ? review.status
        : state.statusId == id
        ? state.statusText
        : '';
    final status = ReviewStatus.parse(raw);
    return status.phase == ReviewPhase.unreadable
        ? const ReviewStatus(ReviewPhase.pending)
        : status;
  }
}

/// The detail pane: the fresh review, or why there is none (loading, the
/// notification's request unavailable, the latest status, an expired review).
class RequestDetailPane extends StatelessWidget {
  const RequestDetailPane({
    super.key,
    required this.controller,
    required this.touchId,
    required this.approvalPassword,
    required this.notificationRequest,
    required this.openedRequest,
    required this.session,
    required this.now,
    required this.onApprove,
    required this.onDeny,
    required this.onBack,
    required this.onStep,
    required this.onReload,
    this.onActivity,
    this.revealOnOpen = false,
  });
  final ProviderController controller;
  final TouchIdController touchId;
  final TextEditingController approvalPassword;
  final String notificationRequest, openedRequest;
  final ReviewSession session;
  final DateTime now;
  final VoidCallback onApprove, onDeny, onBack, onReload;
  final VoidCallback? onActivity;
  final ValueChanged<ReviewStep> onStep;

  /// Single-pane layouts (compact, large text): scroll each newly loaded
  /// review to its own top, so the status, operation and "who wants what"
  /// sentence are on screen instead of the provider status above it.
  final bool revealOnOpen;
  @override
  Widget build(BuildContext context) {
    final state = controller.state;
    final review = state.review;
    if (review == null) return _absent(context);
    final detail = RequestReview(
      state: state,
      endpoint: controller.configuration.endpoint,
      origin: controller.management.originId == controller.state.reviewId
          ? controller.management.originText
          : '',
      password: approvalPassword, // secrets-ignore: UI controller
      onApprove: onApprove,
      onDeny: onDeny,
      onClose: onBack,
      step: session.step(state.reviewId),
      onStep: onStep,
      left: session.remaining(now),
      expired: session.expiredAt(now),
      onReload: onReload,
      onActivity: onActivity,
      touchIdOffered: touchId.available,
      onTouchId: touchId.canApprove ? () => unawaited(touchId.approve()) : null,
      touchIdNote: touchId.working ? '' : touchId.unavailableReason,
      touchIdMessage: touchId.messageFor(state.reviewId),
    );
    if (!revealOnOpen) return detail;
    return _RevealOnOpen(key: ValueKey(state.reviewId), child: detail);
  }

  Widget _absent(BuildContext context) {
    final state = controller.state;
    final loading =
        controller.busy ||
        controller.pendingReview == notificationRequest &&
            notificationRequest.isNotEmpty;
    // The review of the opened request ran out and Rust retired it.
    final expired =
        !loading &&
        notificationRequest.isEmpty &&
        openedRequest.isNotEmpty &&
        session.loadedId == openedRequest &&
        state.statusId != openedRequest &&
        session.expiredAt(now);
    return AccessPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const AccessHeading(
            'Request review',
            'A fresh validated review is required for every decision.',
          ),
          if (loading)
            const Text('Loading or finishing the original operation…')
          else if (notificationRequest.isNotEmpty)
            const Text(
              'The request from the notification could not be loaded. It may have been removed or the provider is locked or unreachable. Pending requests are listed.',
              key: Key('notification-unavailable'),
            )
          else if (expired) ...[
            AccessNotice(
              key: const Key('review-expired'),
              child: Text(
                'The review of $openedRequest expired before a decision. Nothing was sent.',
              ),
            ),
            const SizedBox(height: 16),
            FilledButton(
              key: const Key('reload-review'),
              onPressed: controller.busy ? null : onReload,
              child: const Text('Reload review'),
            ),
          ] else if (state.statusId.isEmpty || state.statusId != openedRequest)
            const Text(
              'No active review. Select a pending request to load its complete scope. Expired or retired reviews cannot authorize an operation.',
            ),
          if (touchId.messageFor(openedRequest).isNotEmpty) ...[
            const SizedBox(height: 16),
            Text(
              touchId.messageFor(openedRequest),
              key: const Key('touch-id-message'),
            ),
          ],
          if (state.statusId.isNotEmpty) ...[
            const SizedBox(height: 16),
            LatestStatus(
              requestId: state.statusId,
              progress: state.statusProgress,
              text: state.statusText,
            ),
          ],
          const SizedBox(height: 16),
          TextButton(onPressed: onBack, child: const Text('Back to requests')),
        ],
      ),
    );
  }
}

/// Brings its child to the top of the enclosing scroll view once, after the
/// first frame it is laid out in. Keyed by request ID, so each loaded review
/// is revealed once; later rebuilds (polling, steps) keep the reader's place.
class _RevealOnOpen extends StatefulWidget {
  const _RevealOnOpen({super.key, required this.child});
  final Widget child;
  @override
  State<_RevealOnOpen> createState() => _RevealOnOpenState();
}

class _RevealOnOpenState extends State<_RevealOnOpen> {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) unawaited(Scrollable.ensureVisible(context));
    });
  }

  @override
  Widget build(BuildContext context) => widget.child;
}
