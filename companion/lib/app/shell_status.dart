import 'package:flutter/material.dart';

import 'capabilities.dart';

/// Provider connection as the shell shows it; always icon plus text.
enum ShellConnection {
  unavailable('Unavailable on this platform', Icons.block),
  notConfigured('Not configured', Icons.link_off),
  disconnected('Disconnected', Icons.cloud_off_outlined),
  locked('Locked', Icons.lock_outline),
  connected('Connected', Icons.check_circle_outline);

  const ShellConnection(this.label, this.icon);
  final String label;
  final IconData icon;

  /// Lock state is only shown while connected: without current authority
  /// the provider's lock state is not known.
  static ShellConnection of({
    required bool available,
    required bool configured,
    required bool connected,
    required bool locked,
  }) {
    if (!available) return unavailable;
    if (!configured) return notConfigured;
    if (!connected) return disconnected;
    return locked ? ShellConnection.locked : ShellConnection.connected;
  }
}

/// Everything the shell's status block shows; derived, never stored.
@immutable
class ShellStatus {
  const ShellStatus({
    required this.connection,
    required this.endpoint,
    required this.capabilities,
  });
  final ShellConnection connection;
  final String endpoint;
  final DeviceCapabilities capabilities;

  static const unknown = ShellStatus(
    connection: ShellConnection.notConfigured,
    endpoint: '',
    capabilities: DeviceCapabilities.none,
  );

  /// The provider's host (no scheme, path or credentials), or '' when the
  /// endpoint is empty or unparseable.
  String get host {
    final uri = Uri.tryParse(endpoint.trim());
    if (uri == null || uri.host.isEmpty) return '';
    return uri.hasPort ? '${uri.host}:${uri.port}' : uri.host;
  }

  String get executesText => host.isEmpty
      ? 'Executes: no provider configured'
      : 'Executes: provider at $host';
}
