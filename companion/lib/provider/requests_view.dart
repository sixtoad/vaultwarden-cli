import 'package:flutter/material.dart';

import '../design/access_theme.dart';
import '../design/components.dart';
import '../design/metrics.dart';
import '../design/typography.dart';
import 'controller.dart';

/// Shown above every destination: an unresolved decision outcome, the
/// provider's status line and the busy indicator.
class ProviderStatusArea extends StatelessWidget {
  const ProviderStatusArea({super.key, required this.controller});
  final ProviderController controller;
  @override
  Widget build(BuildContext context) => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      if (controller.recoveryId.isNotEmpty) ...[
        AccessNotice(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const StatusLabel(
                'Decision outcome requires recovery',
                icon: Icons.help_outline,
              ),
              const SizedBox(height: 8),
              SelectableText(
                'Uncertain decision for request: ${controller.recoveryId}',
                key: const Key('provider-uncertain'),
              ),
              const Text(
                'Only the original request status will be checked. A pending or unavailable status remains uncertain; decisions and unlocks are never resent.',
              ),
              const SizedBox(height: 12),
              OutlinedButton(
                onPressed: controller.busy ? null : controller.refresh,
                child: const Text('Refresh original request status'),
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),
      ],
      Text(controller.state.message, key: const Key('provider-status')),
      if (controller.diagnostic.isNotEmpty) Text(controller.diagnostic),
      if (controller.busy) const LinearProgressIndicator(),
      const SizedBox(height: 16),
    ],
  );
}

/// The Requests destination: the pending list next to the detail when the
/// content area fits both (#50 §1.3), otherwise list then detail.
class RequestsView extends StatelessWidget {
  const RequestsView({
    super.key,
    required this.width,
    required this.detailOpen,
    required this.list,
    required this.detail,
  });
  final double width;
  final bool detailOpen;
  final Widget list, detail;
  @override
  Widget build(BuildContext context) {
    final m = AccessMetrics.of(context);
    final master = m.masterWidth(context, width);
    if (master == null) return detailOpen ? detail : list;
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(width: master, child: list),
        SizedBox(width: m.space[4]),
        Expanded(
          child: Align(
            alignment: AlignmentDirectional.topStart,
            child: ConstrainedBox(
              constraints: BoxConstraints(maxWidth: m.detailMaxWidth),
              child: detail,
            ),
          ),
        ),
      ],
    );
  }
}

/// One pending request: its ID in monospace and a "Pending" status. The
/// open request carries the soft fill and a 3 px accent rule.
class RequestRow extends StatelessWidget {
  const RequestRow({
    super.key,
    required this.id,
    required this.selected,
    required this.onOpen,
  });
  final String id;
  final bool selected;
  final VoidCallback? onOpen;
  @override
  Widget build(BuildContext context) {
    final c = AccessTheme.of(context), m = AccessMetrics.of(context);
    final text = Theme.of(context).textTheme;
    final enabled = onOpen != null;
    // Disabled rows (busy, locked, recovery) are visibly muted, not only in
    // semantics.
    final ink = enabled ? c.text : c.secondary;
    final status = enabled ? c.statusText : c.secondary;
    final shape = RoundedRectangleBorder(
      borderRadius: BorderRadius.circular(m.radius),
    );
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: TextButton(
        key: Key('request-row-$id'),
        onPressed: onOpen,
        style:
            TextButton.styleFrom(
              alignment: AlignmentDirectional.centerStart,
              backgroundColor: selected ? c.soft : c.surface,
              disabledForegroundColor: c.secondary,
              shape: shape,
              padding: EdgeInsetsDirectional.zero,
            ).copyWith(
              // Keep the theme's 3 px focus ring; otherwise the divider outline.
              side: WidgetStateProperty.resolveWith(
                (states) => states.contains(WidgetState.focused)
                    ? BorderSide(color: c.text, width: 3)
                    : BorderSide(color: c.divider),
              ),
            ),
        child: Semantics(
          selected: selected,
          label: 'Review request $id, pending',
          excludeSemantics: true,
          child: IntrinsicHeight(
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                // The selected rule sits inside the rounded shape, so the
                // focus ring is never clipped.
                SizedBox(
                  width: m.selectedRule,
                  child: selected ? ColoredBox(color: c.accent) : null,
                ),
                Expanded(
                  child: Padding(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 13,
                      vertical: 12,
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          id,
                          style: AccessType.of(context).mono
                              .copyWith(color: ink),
                        ),
                        const SizedBox(height: 4),
                        Row(
                          children: [
                            Icon(Icons.schedule, size: 14, color: status),
                            const SizedBox(width: 4),
                            Text(
                              'Pending',
                              style: text.labelMedium!.copyWith(color: status),
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
