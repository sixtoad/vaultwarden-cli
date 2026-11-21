import 'package:companion_slice/platform/approval_client.dart';
import 'package:companion_slice/platform/approval_key.dart';
import 'package:companion_slice/platform/core_loader.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

/// The platform contract every approval client meets (#60,
/// docs/mobile-clients.md).
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

  test('approval clients are macOS, Android and iOS; never other desktops', () {
    for (final os in ['macos', 'android', 'ios']) {
      expect(isApprovalClientSystem(os), isTrue, reason: os);
    }
    for (final os in ['linux', 'windows', 'fuchsia', '']) {
      expect(isApprovalClientSystem(os), isFalse, reason: os);
    }
    expect(mobileSystems, {'android', 'ios'});
  });

  test('each system accepts only its own verification replies', () {
    expect(parseUserVerification('macos', 'touchID'), UserVerification.touchId);
    // macOS stays exactly as strict as before #60.
    for (final reply in ['faceID', 'biometric', 'deviceCredential', null, 1]) {
      expect(
        parseUserVerification('macos', reply),
        UserVerification.unavailable,
        reason: '$reply',
      );
    }
    expect(parseUserVerification('ios', 'faceID'), UserVerification.faceId);
    expect(
      parseUserVerification('ios', 'biometric'),
      UserVerification.unavailable,
    );
    expect(
      parseUserVerification('android', 'biometric'),
      UserVerification.biometric,
    );
    // No system approves with the passcode alone (docs/mobile-clients.md
    // section 2): a device-credential reply is unavailable everywhere.
    for (final os in ['macos', 'ios', 'android']) {
      expect(
        parseUserVerification(os, 'deviceCredential'),
        UserVerification.unavailable,
        reason: os,
      );
    }
    expect(UserVerification.values.map((v) => v.name), [
      'touchId',
      'faceId',
      'biometric',
      'unavailable',
    ]);
    expect(
      parseUserVerification('android', 'touchID'),
      UserVerification.unavailable,
    );
    expect(
      parseUserVerification('linux', 'touchID'),
      UserVerification.unavailable,
    );
  });

  test('phones word the verification by its label; macOS keeps Touch ID', () {
    for (final v in UserVerification.values) {
      final mac = VerificationWording.of('macos', v);
      expect((mac.method, mac.device), ('Touch ID', 'this Mac'));
    }
    final face = VerificationWording.of('ios', UserVerification.faceId);
    expect((face.method, face.device), ('Face ID', 'this device'));
    expect(
      VerificationWording.of('ios', UserVerification.unavailable).method,
      'Face ID or Touch ID',
    );
    final android = VerificationWording.of(
      'android',
      UserVerification.biometric,
    );
    expect(
      (android.startMethod, android.startDevice),
      ('Biometrics', 'This device'),
    );
  });

  test('the native key channel reports the platform verification', () async {
    const channel = MethodChannel('test-mobile-key');
    var reply = 'biometric';
    messenger.setMockMethodCallHandler(channel, (call) async {
      expect(call.method, 'availability');
      return reply;
    });
    final android = NativeApprovalKeyPlatform(
      channel: channel,
      operatingSystem: 'android',
    );
    expect(await android.verification(), UserVerification.biometric);
    expect(await android.touchIdAvailable(), isTrue);
    reply = 'faceID';
    expect(await android.touchIdAvailable(), isFalse);
    final mac = NativeApprovalKeyPlatform(macOS: true, channel: channel);
    expect(await mac.touchIdAvailable(), isFalse, reason: 'faceID on macOS');
    reply = 'touchID';
    expect(await mac.touchIdAvailable(), isTrue);
    final linux = NativeApprovalKeyPlatform(
      channel: channel,
      operatingSystem: 'linux',
    );
    expect(await linux.touchIdAvailable(), isFalse, reason: 'no channel call');
    messenger.setMockMethodCallHandler(channel, null);
  });

  test(
    'device signals: only mobile listens, only known signals pass',
    () async {
      const channel = MethodChannel('test-device-signals');
      expect(
        NativeDeviceSignalPlatform(operatingSystem: 'macos').available,
        isFalse,
      );
      final signals = <DeviceSignal>[];
      final platform = NativeDeviceSignalPlatform(
        operatingSystem: 'ios',
        channel: channel,
      );
      final stop = platform.listen(signals.add);
      Future<void> send(String method, Object? argument) =>
          messenger.handlePlatformMessage(
            channel.name,
            channel.codec.encodeMethodCall(MethodCall(method, argument)),
            (_) {},
          );
      await send('signal', 'locked');
      await send('signal', 'interrupted');
      await send('signal', 'unlocked');
      await send('other', 'locked');
      expect(signals, [DeviceSignal.locked, DeviceSignal.interrupted]);
      stop();
      await send('signal', 'locked');
      expect(signals, hasLength(2), reason: 'unregistered');
    },
  );

  test('the packaged core is found where each platform bundles it', () {
    expect(
      packagedCorePath('macos', '/A.app/Contents/MacOS'),
      '/A.app/Contents/Frameworks/libcompanion_core.dylib',
    );
    expect(
      packagedCorePath('linux', '/opt/a'),
      '/opt/a/lib/libcompanion_core.so',
    );
    expect(packagedCorePath('windows', r'C:\a'), r'C:\a/companion_core.dll');
    expect(packagedCorePath('android', '/system/bin'), 'libcompanion_core.so');
    expect(packagedCorePath('ios', '/x'), isNull, reason: 'statically linked');
    expect(() => packagedCorePath('fuchsia', '/x'), throwsUnsupportedError);
  });
}
