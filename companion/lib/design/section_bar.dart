import 'package:flutter/material.dart';

import 'access_theme.dart';

/// The top bar of a section on wide layouts: title, one-line subtitle and an
/// optional trailing action. The title is a semantic header.
class AccessSectionBar extends StatelessWidget {
  const AccessSectionBar({
    super.key,
    required this.title,
    this.subtitle = '',
    this.trailing,
  });
  final String title, subtitle;
  final Widget? trailing;
  @override
  Widget build(BuildContext context) {
    final c = AccessTheme.of(context), text = Theme.of(context).textTheme;
    return DecoratedBox(
      decoration: BoxDecoration(
        color: c.surface,
        border: Border(bottom: BorderSide(color: c.divider)),
      ),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 24),
        child: Row(
          children: [
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Semantics(
                    header: true,
                    child: Text(title, style: text.titleLarge),
                  ),
                  if (subtitle.isNotEmpty)
                    Text(
                      subtitle,
                      style: text.bodySmall!.copyWith(color: c.secondary),
                    ),
                ],
              ),
            ),
            ?trailing,
          ],
        ),
      ),
    );
  }
}
