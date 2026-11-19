import 'package:flutter/material.dart';

import 'access_theme.dart';
import 'metrics.dart';
import 'typography.dart';

/// One labelled fact. Two columns (label, value) when there is room, stacked
/// on narrow widths and at large text. The value is the only selectable text
/// in the row; [sub] adds a secondary line and [mono] sets the value in the
/// monospace face (IDs, digests, targets).
class FactRow extends StatelessWidget {
  const FactRow(
    this.label,
    this.value, {
    super.key,
    this.sub = '',
    this.mono = false,
  });
  final String label, value, sub;
  final bool mono;

  /// Below this width the label sits above its value.
  static const gridMinWidth = 480.0;

  @override
  Widget build(BuildContext context) {
    final c = AccessTheme.of(context), m = AccessMetrics.of(context);
    final text = Theme.of(context).textTheme;
    final labelText = Text(
      label,
      style: text.bodySmall!.copyWith(color: c.secondary),
    );
    final valueStyle = mono
        ? AccessType.of(context).mono
        : text.bodySmall!.copyWith(fontWeight: FontWeight.w500);
    final valueText = Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SelectableText(value, style: valueStyle),
        if (sub.isNotEmpty) Text(sub, style: text.labelSmall),
      ],
    );
    return Container(
      width: double.infinity,
      decoration: BoxDecoration(
        border: Border(bottom: BorderSide(color: c.divider)),
      ),
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 12),
        child: LayoutBuilder(
          builder: (context, constraints) {
            final grid =
                constraints.maxWidth >= gridMinWidth && !m.largeText(context);
            if (!grid) {
              return Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [labelText, const SizedBox(height: 2), valueText],
              );
            }
            return Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                SizedBox(width: m.factLabelWidth, child: labelText),
                SizedBox(width: m.factGap),
                Expanded(child: valueText),
              ],
            );
          },
        ),
      ),
    );
  }
}
