import 'package:flutter/material.dart';

import '../design/access_theme.dart';

enum AccessDestination { requests, devices, activity, settings }

class AccessShell extends StatelessWidget {
  const AccessShell({
    super.key,
    required this.destination,
    required this.onDestination,
    required this.detailOpen,
    required this.onBack,
    required this.body,
  });
  final AccessDestination destination;
  final ValueChanged<AccessDestination> onDestination;
  final bool detailOpen;
  final VoidCallback onBack;
  final Widget body;
  static const labels = [
    'Requests',
    'Devices & agents',
    'Activity',
    'Settings',
  ];
  static const icons = [
    Icons.inbox_outlined,
    Icons.devices_outlined,
    Icons.history,
    Icons.settings_outlined,
  ];
  @override
  Widget build(BuildContext context) => LayoutBuilder(
    builder: (context, constraints) {
      final wide =
          constraints.maxWidth >= 1040 &&
          MediaQuery.textScalerOf(context).scale(15) <= 21;
      Widget destinationButton(int i) => Padding(
        padding: const EdgeInsets.all(4),
        child: TextButton(
          key: Key('destination-${AccessDestination.values[i].name}'),
          style: TextButton.styleFrom(
            backgroundColor: i == destination.index
                ? AccessTheme.of(context).divider
                : null,
          ),
          onPressed: () => onDestination(AccessDestination.values[i]),
          child: Semantics(
            selected: i == destination.index,
            child: wide
                ? Row(
                    children: [
                      Icon(icons[i]),
                      const SizedBox(width: 12),
                      Expanded(child: Text(labels[i])),
                    ],
                  )
                : Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(icons[i]),
                      const SizedBox(height: 4),
                      Text(
                        i == 1 ? 'Devices' : labels[i],
                        textAlign: TextAlign.center,
                      ),
                    ],
                  ),
          ),
        ),
      );
      return PopScope(
        canPop: !detailOpen,
        onPopInvokedWithResult: (didPop, result) {
          if (!didPop && detailOpen) onBack();
        },
        child: Scaffold(
          appBar: AppBar(
            title: const Text('Vaultwarden Access'),
            leading: detailOpen
                ? IconButton(
                    tooltip: 'Back to requests',
                    onPressed: onBack,
                    icon: const Icon(Icons.arrow_back),
                  )
                : null,
          ),
          body: SafeArea(
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                if (wide)
                  SizedBox(
                    width: 224,
                    child: ColoredBox(
                      color: AccessTheme.of(context).surface,
                      child: ListView(
                        padding: const EdgeInsets.all(12),
                        children: [
                          const Padding(
                            padding: EdgeInsets.all(12),
                            child: Text('COMPANION\nDevelopment application'),
                          ),
                          for (var i = 0; i < labels.length; i++)
                            destinationButton(i),
                        ],
                      ),
                    ),
                  ),
                Expanded(child: body),
              ],
            ),
          ),
          bottomNavigationBar: wide
              ? null
              : SafeArea(
                  top: false,
                  child: ColoredBox(
                    color: AccessTheme.of(context).surface,
                    child: Wrap(
                      children: [
                        for (var i = 0; i < labels.length; i++)
                          SizedBox(
                            width:
                                constraints.maxWidth /
                                (MediaQuery.textScalerOf(context).scale(15) > 21
                                    ? 2
                                    : 4),
                            child: destinationButton(i),
                          ),
                      ],
                    ),
                  ),
                ),
        ),
      );
    },
  );
}
