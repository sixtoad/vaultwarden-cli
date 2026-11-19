import 'package:flutter/material.dart';

import '../../design/access_theme.dart';
import '../../design/metrics.dart';
import '../../src/rust/api/provider.dart' as core;

/// "What you're allowing": the provider's effect text verbatim (never parsed
/// into authority) and the fixed one-request sentence.
class Consequence extends StatelessWidget {
  const Consequence({super.key, required this.review});
  final core.ProviderReview review;
  @override
  Widget build(BuildContext context) {
    final c = AccessTheme.of(context), m = AccessMetrics.of(context);
    final text = Theme.of(context).textTheme;
    final quiet = text.bodySmall!.copyWith(color: c.secondary, height: 1.7);
    return DecoratedBox(
      decoration: BoxDecoration(
        color: c.soft,
        borderRadius: BorderRadius.circular(m.radius),
      ),
      child: SizedBox(
        width: double.infinity,
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Semantics(
                header: true,
                child: Text('What you’re allowing', style: text.titleMedium),
              ),
              const SizedBox(height: 6),
              Text('Effect, as the provider states it', style: text.labelSmall),
              KeyedSubtree(
                key: const Key('review-effect'),
                child: SelectableText(
                  review.effect,
                  style: text.bodySmall!.copyWith(fontWeight: FontWeight.w500),
                ),
              ),
              const SizedBox(height: 6),
              Text(
                'This request only. Approving runs this exact operation once and does not authorize later requests.',
                style: quiet,
              ),
            ],
          ),
        ),
      ),
    );
  }
}
