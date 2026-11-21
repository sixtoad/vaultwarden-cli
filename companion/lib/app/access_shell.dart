import 'package:flutter/material.dart';

import '../design/access_theme.dart';
import '../design/metrics.dart';
import '../design/section_bar.dart';
import 'shell_parts.dart';
import 'shell_status.dart';

enum AccessDestination { requests, devices, activity, settings }

/// The four-section frame. Wide: sidebar (brand, destinations, status) and a
/// section bar over the content. Compact or large text: app bar, a one-line
/// status strip and bottom navigation. System back closes an open request.
class AccessShell extends StatelessWidget {
  const AccessShell({
    super.key,
    required this.destination,
    required this.onDestination,
    required this.detailOpen,
    required this.onBack,
    required this.body,
    this.pendingCount = 0,
    this.status = ShellStatus.unknown,
  });
  final AccessDestination destination;
  final ValueChanged<AccessDestination> onDestination;
  final bool detailOpen;
  final VoidCallback onBack;
  final Widget body;

  /// Pending request IDs; badges the Requests destination when non-zero.
  final int pendingCount;
  final ShellStatus status;
  static const labels = [
    'Requests',
    'Devices & agents',
    'Activity',
    'Settings',
  ];
  static const subtitles = [
    'Pending decisions from your agents',
    'Who can request and approve on this provider',
    'What happened to recent requests',
    'This app, this device and the provider connection',
  ];
  static const icons = [
    Icons.inbox_outlined,
    Icons.devices_outlined,
    Icons.history,
    Icons.settings_outlined,
  ];

  Widget _destination(int i, {required bool vertical}) => ShellDestination(
    buttonKey: Key('destination-${AccessDestination.values[i].name}'),
    label: vertical && i == 1 ? 'Devices' : labels[i],
    icon: icons[i],
    selected: i == destination.index,
    vertical: vertical,
    badge: i == 0 ? pendingCount : 0,
    onPressed: () => onDestination(AccessDestination.values[i]),
  );

  Widget _back() => IconButton(
    tooltip: 'Back to requests',
    onPressed: onBack,
    icon: const Icon(Icons.arrow_back),
  );

  @override
  Widget build(BuildContext context) => LayoutBuilder(
    builder: (context, constraints) {
      final m = AccessMetrics.of(context);
      final wide =
          constraints.maxWidth >= m.sidebarBreakpoint && !m.largeText(context);
      return PopScope(
        canPop: !detailOpen,
        onPopInvokedWithResult: (didPop, result) {
          if (!didPop && detailOpen) onBack();
        },
        child: wide
            ? _wide(context, constraints.maxWidth)
            : _compact(context, constraints.maxWidth),
      );
    },
  );

  Widget _wide(BuildContext context, double width) {
    final c = AccessTheme.of(context), m = AccessMetrics.of(context);
    return Scaffold(
      body: SafeArea(
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            SizedBox(
              width: width >= m.fullBreakpoint
                  ? m.sidebarWidth
                  : m.sidebarCompressedWidth,
              child: FocusTraversalGroup(
                child: DecoratedBox(
                  decoration: BoxDecoration(
                    color: c.soft,
                    border: Border(right: BorderSide(color: c.divider)),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      Expanded(
                        child: ListView(
                          padding: const EdgeInsets.all(12),
                          children: [
                            const ShellBrand(),
                            for (var i = 0; i < labels.length; i++)
                              _destination(i, vertical: false),
                          ],
                        ),
                      ),
                      Divider(height: 1, color: c.divider),
                      ShellStatusBlock(status: status),
                    ],
                  ),
                ),
              ),
            ),
            Expanded(
              child: ColoredBox(
                color: c.surface,
                // Keyboard order: after the sidebar, the section bar (and its
                // Back) comes before the content, whatever their geometry.
                child: FocusTraversalGroup(
                  policy: OrderedTraversalPolicy(),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      FocusTraversalOrder(
                        order: const NumericFocusOrder(0),
                        child: AccessSectionBar(
                          title: labels[destination.index],
                          subtitle: subtitles[destination.index],
                          trailing: detailOpen ? _back() : null,
                        ),
                      ),
                      Expanded(
                        child: FocusTraversalOrder(
                          order: const NumericFocusOrder(1),
                          child: FocusTraversalGroup(child: body),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _compact(BuildContext context, double width) {
    final c = AccessTheme.of(context), m = AccessMetrics.of(context);
    return Scaffold(
      appBar: AppBar(
        title: Text(labels[destination.index]),
        // The prototype's mobile section title: 28 px semibold. At large
        // text the default title keeps the scaled title inside the toolbar.
        titleTextStyle: m.largeText(context)
            ? null
            : Theme.of(context).textTheme.headlineMedium,
        backgroundColor: c.surface,
        leading: detailOpen ? _back() : null,
      ),
      body: SafeArea(
        child: ColoredBox(
          color: c.surface,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              ShellStatusBlock(status: status, compact: true),
              Expanded(child: body),
            ],
          ),
        ),
      ),
      bottomNavigationBar: SafeArea(
        top: false,
        child: DecoratedBox(
          decoration: BoxDecoration(
            color: c.soft,
            border: Border(top: BorderSide(color: c.divider)),
          ),
          child: Wrap(
            children: [
              for (var i = 0; i < labels.length; i++)
                SizedBox(
                  width: width / (m.largeText(context) ? 2 : 4),
                  child: _destination(i, vertical: true),
                ),
            ],
          ),
        ),
      ),
    );
  }
}
