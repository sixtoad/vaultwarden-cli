import 'package:flutter/material.dart';

import 'access_theme.dart';
import 'metrics.dart';

/// A notice: soft background with a 2 px accent rule on its leading edge.
class AccessNotice extends StatelessWidget {
  const AccessNotice({super.key, required this.child});
  final Widget child;
  @override
  Widget build(BuildContext context) {
    final c = AccessTheme.of(context), m = AccessMetrics.of(context);
    return DecoratedBox(
      decoration: BoxDecoration(
        color: c.soft,
        border: BorderDirectional(
          start: BorderSide(color: c.accent, width: m.noticeRule),
        ),
      ),
      child: SizedBox(
        width: double.infinity,
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 17, vertical: 14),
          child: child,
        ),
      ),
    );
  }
}
