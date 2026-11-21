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
  unavailable('unavailable');

  const UserVerification(this.label);
  final String label;
}

/// The native `availability` replies each system may give. Anything else,
/// including another system's value, is `unavailable`: macOS reports only
/// `touchID`, exactly as before. No system approves with its passcode alone
/// (docs/mobile-clients.md section 2): a `deviceCredential` reply is
/// `unavailable`, and password approval is the fallback.
const verificationReplies = <String, Map<String, UserVerification>>{
  'macos': {'touchID': UserVerification.touchId},
  'ios': {
    'touchID': UserVerification.touchId,
    'faceID': UserVerification.faceId,
  },
  'android': {'biometric': UserVerification.biometric},
};

UserVerification parseUserVerification(String operatingSystem, Object? reply) =>
    verificationReplies[operatingSystem]?[reply] ??
    UserVerification.unavailable;

/// How the approval UI names the user verification and this device (#60).
/// macOS keeps its historical wording ("Touch ID", "this Mac") whatever the
/// reply; phones use the verification's [UserVerification.label].
class VerificationWording {
  const VerificationWording._(this.method, this.device, this.change);

  /// The wording for [operatingSystem] when its key reports [verification]
  /// (when `unavailable`, the method the system would normally use).
  factory VerificationWording.of(
    String operatingSystem,
    UserVerification verification,
  ) {
    if (!isMobileSystem(operatingSystem)) return macOS;
    final method = verification != UserVerification.unavailable
        ? verification.label
        : operatingSystem == 'ios'
        ? 'Face ID or Touch ID'
        : UserVerification.biometric.label;
    return VerificationWording._(method, 'this device', 'biometric enrollment');
  }

  static const macOS = VerificationWording._(
    'Touch ID',
    'this Mac',
    'fingerprint',
  );

  /// The verification as written mid-sentence ("Touch ID", "biometrics").
  final String method;

  /// This device, mid-sentence ("this Mac", "this device").
  final String device;

  /// What invalidates the key ("fingerprint", "biometric enrollment").
  final String change;

  /// [method] at the start of a sentence.
  String get startMethod => _capital(method);

  /// [device] at the start of a sentence.
  String get startDevice => _capital(device);

  static String _capital(String text) =>
      text.isEmpty ? text : text[0].toUpperCase() + text.substring(1);
}

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
