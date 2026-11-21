import 'package:flutter/material.dart';

import '../../design/access_theme.dart';
import '../../design/typography.dart';
import '../../src/rust/api/provider.dart' as core;
import 'review_status.dart';

/// Status label and monospace request ID, the operation as the title, and
/// "`requester` wants to `effect`". Every value is Rust's escaped projection,
/// verbatim: the sentence is display only and never interpreted.
class RequestHeader extends StatelessWidget {
  const RequestHeader({super.key, required this.review, required this.status});
  final core.ProviderReview review;
  final ReviewStatus status;
  @override
  Widget build(BuildContext context) {
    final c = AccessTheme.of(context), text = Theme.of(context).textTheme;
    final statusStyle = text.labelMedium!.copyWith(color: c.statusText);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Wrap(
          spacing: 12,
          runSpacing: 6,
          crossAxisAlignment: WrapCrossAlignment.center,
          alignment: WrapAlignment.spaceBetween,
          children: [
            Row(
              key: const Key('review-status-label'),
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(status.icon, size: 16, color: c.statusText),
                const SizedBox(width: 6),
                Flexible(child: Text(status.label, style: statusStyle)),
              ],
            ),
            // The ID stays one selectable value (key kept for the full scope).
            KeyedSubtree(
              key: const Key('review-id'),
              child: SelectableText(
                review.id,
                style: AccessType.of(context).mono.copyWith(color: c.secondary),
              ),
            ),
          ],
        ),
        const SizedBox(height: 16),
        Semantics(
          header: true,
          child: Text(review.operation, style: text.headlineSmall),
        ),
        const SizedBox(height: 8),
        Text(
          '${review.requester} wants to ${review.effect}',
          key: const Key('review-description'),
          style: text.bodyMedium!.copyWith(color: c.secondary, height: 1.7),
        ),
      ],
    );
  }
}
