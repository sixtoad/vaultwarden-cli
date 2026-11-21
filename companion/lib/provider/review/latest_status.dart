import 'package:flutter/material.dart';

import '../../design/components.dart';
import '../../src/rust/api/provider.dart' as core;
import 'final_state.dart';
import 'review_status.dart';

/// The latest status Rust holds for one request after a decision or a status
/// check (`statusId`/`statusText`/`statusProgress`). A provider status object
/// gets its own label and sentence; Rust's own prose (a rejection, a decision
/// in flight) is shown verbatim under the typed progress.
class LatestStatus extends StatelessWidget {
  const LatestStatus({
    super.key,
    required this.requestId,
    required this.progress,
    required this.text,
  });
  final String requestId, text;
  final core.ProviderStatusProgress progress;
  @override
  Widget build(BuildContext context) {
    final status = ReviewStatus.parse(text);
    final readable = status.phase != ReviewPhase.unreadable;
    final (label, icon) = readable
        ? (status.label, status.icon)
        : switch (progress) {
            core.ProviderStatusProgress.committed => (
              'Executing · not completed',
              Icons.sync,
            ),
            core.ProviderStatusProgress.pending => (
              'Still pending',
              Icons.schedule,
            ),
            core.ProviderStatusProgress.terminal => (
              'Final',
              Icons.info_outline,
            ),
            core.ProviderStatusProgress.none => ('Status', Icons.info_outline),
          };
    final sentence = !readable
        ? ''
        : status.phase == ReviewPhase.pending
        ? 'The provider still reports this request as pending.'
        : finalSentence(status);
    return Semantics(
      liveRegion: true,
      child: AccessNotice(
        key: const Key('latest-status'),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            StatusLabel(label, icon: icon),
            if (sentence.isNotEmpty) ...[
              const SizedBox(height: 6),
              Text(sentence),
            ],
            const SizedBox(height: 8),
            FactRow('Latest status request', requestId, mono: true),
            FactRow('Provider status', text, mono: readable),
          ],
        ),
      ),
    );
  }
}
