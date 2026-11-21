import 'package:flutter/material.dart';

import '../../design/components.dart';

/// A decision whose reply was lost (`recoveryId`): the operation may have run.
/// Only the original request's status is checked; nothing is resubmitted.
/// Shown on every destination until the original status settles.
class OutcomeUnknownNotice extends StatelessWidget {
  const OutcomeUnknownNotice({
    super.key,
    required this.requestId,
    required this.onCheck,
  });
  final String requestId;

  /// Null while the provider is busy.
  final VoidCallback? onCheck;
  @override
  Widget build(BuildContext context) => Semantics(
    container: true,
    liveRegion: true,
    child: AccessNotice(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const StatusLabel('Outcome unknown', icon: Icons.help_outline),
          const SizedBox(height: 8),
          Text(
            'Connection lost after a decision.',
            style: Theme.of(context).textTheme.titleMedium,
          ),
          const SizedBox(height: 4),
          const Text(
            'The operation may have run. Checking the original request is safe; resubmitting is not. A pending or unavailable status stays unknown, and the decision and any unlock are never resent.',
          ),
          const SizedBox(height: 8),
          SelectableText(
            'Original request: $requestId',
            key: const Key('provider-uncertain'),
          ),
          const SizedBox(height: 12),
          FilledButton(
            key: const Key('check-status'),
            onPressed: onCheck,
            child: const Text('Check status'),
          ),
        ],
      ),
    ),
  );
}
