import 'dart:io';

import 'package:flutter/services.dart';

/// The operating systems whose native side implements the approval-client
/// channel contract (`docs/mobile-clients.md`): the provider transport, the
/// approval key and review notifications. macOS is the reference
/// implementation (`companion/macos/Runner`); Android and iOS implement the
/// same channels, methods, arguments and closed reply schemas.
const approvalClientSystems = {'macos', 'android', 'ios'};

/// Phones: no desktop CLI, no installation controls (#60).
const mobileSystems = {'android', 'ios'};

bool isApprovalClientSystem(String operatingSystem) =>
    approvalClientSystems.contains(operatingSystem);

bool isMobileSystem(String operatingSystem) =>
    mobileSystems.contains(operatingSystem);

/// How the approval key verifies the user before each signature. The key's
/// own access control enforces it; this value only labels the prompt.
enum UserVerification {
  touchId('Touch ID'),
  faceId('Face ID'),

  /// Android Class 3 (strong) biometrics.
  biometric('biometrics'),

  /// The device PIN, pattern or passcode, required for every signature.
  deviceCredential('device credential'),
  unavailable('unavailable');

  const UserVerification(this.label);
  final String label;
}

/// The native `availability` replies each system may give. Anything else,
/// including another system's value, is `unavailable`: macOS reports only
/// `touchID`, exactly as before.
const verificationReplies = <String, Map<String, UserVerification>>{
  'macos': {'touchID': UserVerification.touchId},
  'ios': {
    'touchID': UserVerification.touchId,
    'faceID': UserVerification.faceId,
    'deviceCredential': UserVerification.deviceCredential,
  },
  'android': {
    'biometric': UserVerification.biometric,
    'deviceCredential': UserVerification.deviceCredential,
  },
};

UserVerification parseUserVerification(String operatingSystem, Object? reply) =>
    verificationReplies[operatingSystem]?[reply] ??
    UserVerification.unavailable;

/// Implemented by an approval key platform that can say which verification
/// its key requires (Face ID, Android biometrics, ...).
abstract interface class UserVerificationPlatform {
  Future<UserVerification> verification();
}

/// Device events that must retire a pending authorization at once, beyond
/// Flutter's own `AppLifecycleState` (which every platform already gets).
enum DeviceSignal {
  /// The screen locked or protected data became unavailable.
  locked,

  /// Another app or a system surface took over (a call, the app switcher)
  /// without a lifecycle change Flutter reports.
  interrupted,
}

/// Native device signals (`dev.vaultwarden.companionSlice/lifecycle`, method
/// `signal`, argument `locked` or `interrupted`). macOS sends none: its
/// native signer and provider adapter already cancel on sleep, screen lock,
/// session switch and window close.
abstract interface class DeviceSignalPlatform {
  bool get available;

  /// Registers [onSignal]; the returned function unregisters it.
  void Function() listen(void Function(DeviceSignal signal) onSignal);
}

class NoDeviceSignals implements DeviceSignalPlatform {
  const NoDeviceSignals();
  @override
  bool get available => false;
  @override
  void Function() listen(void Function(DeviceSignal signal) onSignal) => () {};
}

class NativeDeviceSignalPlatform implements DeviceSignalPlatform {
  NativeDeviceSignalPlatform({String? operatingSystem, MethodChannel? channel})
    : available = isMobileSystem(operatingSystem ?? Platform.operatingSystem),
      _channel =
          channel ??
          const MethodChannel('dev.vaultwarden.companionSlice/lifecycle');
  @override
  final bool available;
  final MethodChannel _channel;
  static final Map<String, Object> _owners = {};

  @override
  void Function() listen(void Function(DeviceSignal signal) onSignal) {
    if (!available) return () {};
    final owner = Object();
    _owners[_channel.name] = owner;
    _channel.setMethodCallHandler((call) async {
      if (!identical(_owners[_channel.name], owner) ||
          call.method != 'signal') {
        return;
      }
      final signal = DeviceSignal.values
          .where((s) => s.name == call.arguments)
          .firstOrNull;
      if (signal != null) onSignal(signal);
    });
    return () {
      if (identical(_owners[_channel.name], owner)) {
        _owners.remove(_channel.name);
        _channel.setMethodCallHandler(null);
      }
    };
  }
}
