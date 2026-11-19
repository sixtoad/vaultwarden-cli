import 'package:flutter/material.dart';

import '../design/access_theme.dart';
import '../design/metrics.dart';
import '../design/status.dart';
import '../design/typography.dart';
import 'shell_status.dart';

/// Sidebar brand block: mark, product name and one-line purpose.
class ShellBrand extends StatelessWidget {
  const ShellBrand({super.key});
  @override
  Widget build(BuildContext context) {
    final text = Theme.of(context).textTheme;
    return Padding(
      padding: const EdgeInsets.fromLTRB(12, 8, 12, 24),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          ExcludeSemantics(
            child: Text('v·', style: AccessType.of(context).brand),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Vaultwarden Access', style: text.titleMedium),
                Text('Approve agent requests', style: text.labelSmall),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

/// One destination. Selected: surface fill, 1 px divider and a 3 px accent
/// rule on the leading edge (sidebar) or top edge (bottom bar).
class ShellDestination extends StatelessWidget {
  const ShellDestination({
    super.key,
    required this.buttonKey,
    required this.label,
    required this.icon,
    required this.selected,
    required this.vertical,
    required this.onPressed,
    this.badge = 0,
  });

  /// On the button itself, so its semantics node (button, selected) is the
  /// one a finder by this key reaches.
  final Key buttonKey;
  final String label;
  final IconData icon;
  final bool selected, vertical;
  final VoidCallback onPressed;
  final int badge;
  @override
  Widget build(BuildContext context) {
    final c = AccessTheme.of(context), m = AccessMetrics.of(context);
    final rule = BorderSide(color: c.accent, width: m.selectedRule);
    final edge = BorderSide(color: c.divider);
    final count = badge > 0
        ? CountBadge(badge, semantics: '$badge pending')
        : null;
    final icon = Icon(this.icon, color: selected ? c.statusText : c.secondary);
    final name = Text(
      label,
      textAlign: vertical ? TextAlign.center : TextAlign.start,
      style: Theme.of(context).textTheme.labelLarge!
          .copyWith(fontWeight: selected ? FontWeight.w600 : FontWeight.w400),
    );
    return Padding(
      padding: EdgeInsets.all(vertical ? 2 : 0).copyWith(bottom: 2),
      child: DecoratedBox(
        decoration: BoxDecoration(
          color: selected ? c.surface : null,
          border: selected
              ? vertical
                    ? Border(top: rule, left: edge, right: edge, bottom: edge)
                    : BorderDirectional(
                        start: rule,
                        top: edge,
                        end: edge,
                        bottom: edge,
                      )
              : null,
        ),
        child: TextButton(
          key: buttonKey,
          style: TextButton.styleFrom(
            shape: const RoundedRectangleBorder(),
            alignment: vertical ? Alignment.center : Alignment.centerLeft,
          ),
          onPressed: onPressed,
          child: Semantics(
            selected: selected,
            child: vertical
                ? Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          icon,
                          if (count != null) ...[
                            const SizedBox(width: 4),
                            count,
                          ],
                        ],
                      ),
                      const SizedBox(height: 4),
                      name,
                    ],
                  )
                : Row(
                    children: [
                      icon,
                      const SizedBox(width: 12),
                      Expanded(child: name),
                      ?count,
                    ],
                  ),
          ),
        ),
      ),
    );
  }
}

/// Provider connection, what executes, and this device's role.
class ShellStatusBlock extends StatelessWidget {
  const ShellStatusBlock({
    super.key,
    required this.status,
    this.compact = false,
  });
  final ShellStatus status;
  final bool compact;
  @override
  Widget build(BuildContext context) {
    final c = AccessTheme.of(context), text = Theme.of(context).textTheme;
    final connection = Row(
      children: [
        Icon(status.connection.icon, size: 16, color: c.statusText),
        const SizedBox(width: 6),
        Flexible(
          child: Text(
            status.connection.label,
            key: const Key('shell-connection'),
            style: text.labelMedium,
          ),
        ),
      ],
    );
    if (compact) {
      return ColoredBox(
        color: c.soft,
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
          child: Wrap(
            spacing: 12,
            crossAxisAlignment: WrapCrossAlignment.center,
            children: [
              connection,
              Text(status.executesText, style: text.labelSmall),
            ],
          ),
        ),
      );
    }
    return Padding(
      padding: const EdgeInsets.all(12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          connection,
          const SizedBox(height: 4),
          Text(
            status.executesText,
            key: const Key('shell-executes'),
            style: text.labelSmall,
          ),
          Text(
            status.capabilities.roleText,
            key: const Key('shell-role'),
            style: text.labelSmall,
          ),
        ],
      ),
    );
  }
}
