import 'package:flutter/material.dart';

import 'access_theme.dart';
import 'metrics.dart';

/// A status: always an icon and its text, never color alone.
class StatusLabel extends StatelessWidget {
  const StatusLabel(this.label, {super.key, this.icon = Icons.info_outline});
  final String label;
  final IconData icon;
  @override
  Widget build(BuildContext context) => Row(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Icon(icon, size: 20, color: AccessTheme.of(context).statusText),
      const SizedBox(width: 8),
      Expanded(child: Text(label)),
    ],
  );
}

/// A small count, e.g. pending requests. Its semantics carry [semantics]
/// ("2 pending") so the number is never announced without its meaning.
class CountBadge extends StatelessWidget {
  const CountBadge(this.count, {super.key, required this.semantics});
  final int count;
  final String semantics;
  @override
  Widget build(BuildContext context) {
    final c = AccessTheme.of(context);
    return Semantics(
      label: semantics,
      excludeSemantics: true,
      child: DecoratedBox(
        decoration: BoxDecoration(
          color: c.actionFill,
          borderRadius: BorderRadius.circular(
            AccessMetrics.of(context).badgeRadius,
          ),
        ),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 1),
          child: Text(
            count > 256 ? '256+' : '$count',
            style: Theme.of(context).textTheme.labelMedium!
                .copyWith(color: Colors.white),
          ),
        ),
      ),
    );
  }
}
