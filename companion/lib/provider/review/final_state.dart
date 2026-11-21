import 'package:flutter/material.dart';

import '../../design/components.dart';
import 'review_status.dart';

/// What a final status means, in one sentence per provider status. Approved
/// and running are never presented as completed; there is no "cancelled".
String finalSentence(ReviewStatus status) => switch (status.phase) {
  ReviewPhase.approved => 'Approval was recorded. The provider has not reported completion, so this is not a completed operation. Do not approve again.',
  ReviewPhase.running => 'Running on the provider. Approval was recorded; execution has not completed. Do not approve again.',
  ReviewPhase.completed =>
    status.exitCode == null
        ? 'The provider reports the operation completed without an exit code. Output is not shown here.'
        : 'The provider reports the operation completed with exit code ${status.exitCode}. Output is not shown here.',
  ReviewPhase.failed => 'The provider reports execution failed. There is no automatic retry; inspect Activity before requesting new work.',
  ReviewPhase.denied =>
    'Denied. Nothing will execute. A new request needs a new review.',
  ReviewPhase.expired => 'Expired before a decision. Nothing will execute. A new request needs a new review.',
  ReviewPhase.unreadable => 'The provider status could not be read. Nothing can be approved or denied from this review.',
  ReviewPhase.pending => '',
};

/// The state notice of a final review (#61): no password, no approval or
/// denial controls; back to the list or on to Activity.
class FinalState extends StatelessWidget {
  const FinalState({
    super.key,
    required this.status,
    required this.onBack,
    this.onActivity,
  });
  final ReviewStatus status;
  final VoidCallback onBack;
  final VoidCallback? onActivity;
  @override
  Widget build(BuildContext context) => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Semantics(
        liveRegion: true,
        child: AccessNotice(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              StatusLabel(status.label, icon: status.icon),
              const SizedBox(height: 6),
              Text(finalSentence(status), key: const Key('review-final')),
              if (status.phase == ReviewPhase.failed &&
                  status.reason.isNotEmpty) ...[
                const SizedBox(height: 6),
                SelectableText(
                  'Reason reported by the provider: ${status.reason}',
                  key: const Key('review-failure-reason'),
                ),
              ],
              const SizedBox(height: 6),
              const Text('This request can no longer be approved or denied.'),
            ],
          ),
        ),
      ),
      const SizedBox(height: 16),
      AccessActions(
        children: [
          OutlinedButton(
            onPressed: onBack,
            child: const Text('Back to requests'),
          ),
          if (onActivity != null)
            TextButton(
              onPressed: onActivity,
              child: const Text('View activity'),
            ),
        ],
      ),
    ],
  );
}
