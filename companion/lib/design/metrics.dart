import 'package:flutter/material.dart';

/// Quiet Instrument spacing, sizes, radii and breakpoints (#50, direction A).
/// One set for both themes; read with [AccessMetrics.of].
@immutable
class AccessMetrics extends ThemeExtension<AccessMetrics> {
  const AccessMetrics({
    this.space = const [4, 8, 12, 16, 24, 32],
    this.sidebarWidth = 212,
    this.sidebarCompressedWidth = 176,
    this.sidebarBreakpoint = 850,
    this.fullBreakpoint = 1150,
    this.listWidth = 270,
    this.listCompressedWidth = 220,
    this.detailMinWidth = 480,
    this.detailMaxWidth = 790,
    this.workpageMaxWidth = 850,
    this.factLabelWidth = 110,
    this.factLabelCompactWidth = 95,
    this.factGap = 20,
    this.factCompactGap = 12,
    this.target = 48,
    this.radius = 7,
    this.badgeRadius = 5,
    this.tileRadius = 8,
    this.selectedRule = 3,
    this.noticeRule = 2,
    this.largeTextBody = 21,
  });

  /// The spacing scale: 4, 8, 12, 16, 24, 32.
  final List<double> space;
  final double sidebarWidth, sidebarCompressedWidth;

  /// Window widths: sidebar navigation from [sidebarBreakpoint], the full
  /// (uncompressed) sidebar and list from [fullBreakpoint].
  final double sidebarBreakpoint, fullBreakpoint;
  final double listWidth, listCompressedWidth, detailMinWidth;
  final double detailMaxWidth, workpageMaxWidth;
  final double factLabelWidth, factLabelCompactWidth, factGap, factCompactGap;

  /// Minimum interactive target (48 on every platform, kept from #51).
  final double target;
  final double radius, badgeRadius, tileRadius;

  /// Left rules: selected list row, notice.
  final double selectedRule, noticeRule;

  /// Scaled size of 15 px body text above which layouts stay single column
  /// (text scale > 1.4, e.g. 200% text).
  final double largeTextBody;

  static const standard = AccessMetrics();

  static AccessMetrics of(BuildContext context) =>
      Theme.of(context).extension<AccessMetrics>() ?? standard;

  /// Whether text is scaled beyond what side-by-side layouts accommodate.
  bool largeText(BuildContext context) =>
      MediaQuery.textScalerOf(context).scale(15) > largeTextBody;

  /// Width of a master list next to a detail pane in a content area of
  /// [contentWidth], or null when the two must be shown one at a time.
  /// Only a window with sidebar navigation shows both; the list is full
  /// width from [fullBreakpoint], as the sidebar is.
  double? masterWidth(BuildContext context, double contentWidth) {
    final window = MediaQuery.sizeOf(context).width;
    if (largeText(context) || window < sidebarBreakpoint) return null;
    final list = window >= fullBreakpoint ? listWidth : listCompressedWidth;
    return contentWidth >= list + space[4] + detailMinWidth ? list : null;
  }

  @override
  AccessMetrics copyWith() => this;

  @override
  AccessMetrics lerp(AccessMetrics? other, double t) => this;
}
