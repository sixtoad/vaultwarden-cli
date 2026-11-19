import 'package:flutter/foundation.dart';

/// What this device can actually do (#50 §3.1). A platform label is never a
/// capability: each role is derived from an implemented adapter.
@immutable
class DeviceCapabilities {
  const DeviceCapabilities({
    required this.canRequest,
    required this.canApprove,
    required this.canExecute,
    required this.biometric,
    required this.notifications,
    required this.cliInstall,
  });

  /// The desktop bundle ships the protected-access requester CLI
  /// (`vw-access`): macOS and Linux. Windows bundles only the vault CLI.
  final bool canRequest;

  /// The provider approval transport exists on this platform.
  final bool canApprove;

  /// Always false: the companion app never executes operations. Execution
  /// belongs to the provider at the configured endpoint, even when that
  /// provider happens to run on this computer.
  final bool canExecute;

  /// A request-bound biometric signer (Touch ID) is available.
  final bool biometric;

  /// Review notifications can be posted.
  final bool notifications;

  /// Bundled CLI enablement/repair is offered (desktop only, never phones).
  final bool cliInstall;

  static const none = DeviceCapabilities(
    canRequest: false,
    canApprove: false,
    canExecute: false,
    biometric: false,
    notifications: false,
    cliInstall: false,
  );

  /// Derives the capabilities from `Platform.operatingSystem` and the
  /// runtime availability reported by each native adapter.
  factory DeviceCapabilities.derive({
    required String operatingSystem,
    required bool providerTransport,
    required bool biometricSigner,
    required bool reviewNotifications,
  }) {
    const desktop = {'macos', 'linux', 'windows'};
    if (!desktop.contains(operatingSystem) &&
        !const {'android', 'ios'}.contains(operatingSystem)) {
      return none;
    }
    return DeviceCapabilities(
      canRequest: const {'macos', 'linux'}.contains(operatingSystem),
      canApprove: providerTransport,
      canExecute: false,
      biometric: providerTransport && biometricSigner,
      notifications: reviewNotifications,
      cliInstall: desktop.contains(operatingSystem),
    );
  }

  /// The shell footer's description of this device's role.
  String get roleText => canApprove
      ? 'This device: approval client'
      : 'This device: approval unavailable';

  @override
  bool operator ==(Object other) =>
      other is DeviceCapabilities &&
      other.canRequest == canRequest &&
      other.canApprove == canApprove &&
      other.canExecute == canExecute &&
      other.biometric == biometric &&
      other.notifications == notifications &&
      other.cliInstall == cliInstall;

  @override
  int get hashCode => Object.hash(
    canRequest,
    canApprove,
    canExecute,
    biometric,
    notifications,
    cliInstall,
  );
}
