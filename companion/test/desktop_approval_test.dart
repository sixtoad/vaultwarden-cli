import 'dart:typed_data';

import 'package:companion_slice/platform/approval_client.dart';
import 'package:companion_slice/platform/approval_key.dart';
import 'package:companion_slice/platform/core_approval_key.dart';
import 'package:companion_slice/platform/core_provider.dart';
import 'package:companion_slice/src/rust/api/desktop_key.dart' as key;
import 'package:companion_slice/src/rust/api/desktop_provider.dart' as core;
import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';

/// Windows and Linux approval (docs/implementation/desktop-approval-spec.md):
/// the Rust-core transport and the Windows Hello key behind the same Dart
/// contracts as the native channels. The bridge is faked here; the Rust
/// side has its own tests.
class FakeTransport implements CoreProviderApi {
  core.DesktopProviderConfiguration saved =
      const core.DesktopProviderConfiguration(
        configured: false,
        endpoint: '',
        pin: '',
        fingerprint: '',
        uncertainId: '',
        managementRecovery: '',
      );
  final sent = <(Uint8List, bool)>[];
  final setups = <List<String>>[];
  final settled = <String>[];
  int invalidated = 0;
  Uint8List reply = Uint8List.fromList([123, 125]);

  @override
  Future<core.DesktopProviderConfiguration> configuration() async => saved;
  @override
  Future<core.DesktopProviderConfiguration> setup(
    String endpoint,
    String pin,
    String caPath,
    String identityPath,
    String passphrase,
  ) async {
    setups.add([endpoint, pin, caPath, identityPath, passphrase]);
    return saved;
  }

  @override
  Future<Uint8List> send(Uint8List body, bool foreground) async {
    sent.add((body, foreground));
    return reply;
  }

  @override
  Future<void> settle(String id) async => settled.add(id);
  @override
  void invalidate() => invalidated++;
}

core.DesktopProviderConfiguration configured({
  String fingerprint = '',
  String uncertainId = '',
}) => core.DesktopProviderConfiguration(
  configured: true,
  endpoint: 'https://127.0.0.1:8443/v1/companion',
  pin: 'a' * 64,
  fingerprint: fingerprint.isEmpty ? 'b' * 64 : fingerprint,
  uncertainId: uncertainId,
  managementRecovery: '',
);

class FakeKeys implements CoreKeyApi {
  String availabilityReply = 'windowsHello';
  key.DesktopKeyReply next = reply('present', key: 65);
  final calls = <List<Object?>>[];
  final cancels = <(String, int)>[];

  static key.DesktopKeyReply reply(
    String outcome, {
    int key = 0,
    int signature = 0,
    int data = 0,
  }) => key_(outcome, key, signature, data);
  static key.DesktopKeyReply key_(String o, int k, int s, int d) =>
      key.DesktopKeyReply(
        outcome: o,
        publicKey: Uint8List.fromList(
          k == 0 ? [] : [4, ...List.filled(k - 1, 1)],
        ),
        signature: Uint8List(s),
        authenticatorData: Uint8List(d),
      );

  @override
  Future<String> availability() async => availabilityReply;
  @override
  Future<key.DesktopKeyReply> call(
    String method,
    KeyBinding binding, {
    String session = '',
    int token = 0,
    String purpose = '',
    Uint8List? transcript,
  }) async {
    calls.add([method, binding.providerIdentity, session, token, purpose]);
    return next;
  }

  @override
  void cancel(String session, int token) => cancels.add((session, token));
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('core transport', () {
    test('serves Windows and Linux only', () {
      expect(coreTransportSystems, {'linux', 'windows'});
      for (final os in ['macos', 'android', 'ios', 'fuchsia']) {
        expect(CoreProviderPlatform(operatingSystem: os).available, isFalse);
      }
      // The native channel systems are unchanged.
      expect(isApprovalClientSystem('linux'), isFalse);
      expect(isApprovalClientSystem('windows'), isFalse);
    });

    test('configuration keeps the native closed schema', () async {
      final api = FakeTransport();
      final platform = CoreProviderPlatform(operatingSystem: 'linux', api: api);
      expect((await platform.configuration()).configured, isFalse);
      api.saved = configured(uncertainId: 'A' * 43);
      final saved = await platform.configuration();
      expect(
        (saved.endpoint, saved.uncertainId),
        ('https://127.0.0.1:8443/v1/companion', 'A' * 43),
      );
      for (final bad in [
        configured(fingerprint: 'B' * 64),
        configured(uncertainId: 'short'),
      ]) {
        api.saved = bad;
        await expectLater(platform.configuration(), throwsFormatException);
      }
      final other = CoreProviderPlatform(operatingSystem: 'macos', api: api);
      expect((await other.configuration()).configured, isFalse);
      await expectLater(other.send(Uint8List(1)), throwsUnsupportedError);
    });

    test('setup reads files by path and never takes the dialog path', () async {
      final api = FakeTransport()..saved = configured();
      final platform = CoreProviderPlatform(
        operatingSystem: 'windows',
        api: api,
      );
      await expectLater(
        platform.setup('https://p', 'a' * 64, 'pw'),
        throwsUnsupportedError,
      );
      final saved = await platform.setupFromFiles(
        'https://p',
        'a' * 64,
        r'C:\ca.der',
        r'C:\id.p12',
        'pw',
      );
      expect(saved.configured, isTrue);
      expect(api.setups.single, [
        'https://p',
        'a' * 64,
        r'C:\ca.der',
        r'C:\id.p12',
        'pw',
      ]);
    });

    test('send keeps the size limits and reports the foreground', () async {
      final api = FakeTransport();
      var state = AppLifecycleState.resumed;
      final platform = CoreProviderPlatform(
        operatingSystem: 'linux',
        api: api,
        lifecycle: () => state,
      );
      await expectLater(platform.send(Uint8List(16385)), throwsFormatException);
      expect(api.sent, isEmpty);
      await platform.send(Uint8List(16384));
      state = AppLifecycleState.inactive;
      await platform.send(Uint8List(1));
      expect(api.sent.map((s) => s.$2), [true, false]);
      api.reply = Uint8List(1048577);
      await expectLater(platform.send(Uint8List(1)), throwsFormatException);
      await platform.settle('A' * 43);
      expect(api.settled, ['A' * 43]);
    });

    testWidgets('leaving the foreground invalidates; hiding retires', (
      tester,
    ) async {
      final api = FakeTransport();
      final platform = CoreProviderPlatform(
        operatingSystem: 'windows',
        api: api,
      );
      var retired = 0;
      final stop = platform.onInvalidation(() => retired++);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
      expect((api.invalidated, retired), (1, 0));
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
      expect((api.invalidated, retired), (2, 1));
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
      expect((api.invalidated, retired), (3, 1));
      stop();
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
      expect(api.invalidated, 3);
    });
  });

  group('Windows Hello key', () {
    const binding = KeyBinding('p', 'c');

    test('Linux and every other system are unavailable', () async {
      final keys = FakeKeys();
      for (final os in ['linux', 'macos', 'android']) {
        final platform = CoreApprovalKeyPlatform(
          operatingSystem: os,
          api: keys,
        );
        expect(await platform.verification(), UserVerification.unavailable);
        expect((await platform.read(binding)).outcome, KeyOutcome.unavailable);
        await platform.cancel(1);
      }
      expect(keys.calls, isEmpty);
      expect(keys.cancels, isEmpty);
    });

    test('availability accepts only windowsHello', () async {
      final keys = FakeKeys();
      final platform = CoreApprovalKeyPlatform(
        operatingSystem: 'windows',
        api: keys,
      );
      expect(await platform.verification(), UserVerification.windowsHello);
      expect(await platform.touchIdAvailable(), isTrue);
      for (final other in ['touchID', 'biometric', 'deviceCredential', '']) {
        keys.availabilityReply = other;
        expect(
          await platform.verification(),
          UserVerification.unavailable,
          reason: other,
        );
      }
    });

    test('signatures carry exactly 37 bytes of authenticator data', () async {
      KeyReply parse(key.DesktopKeyReply r) => parseCoreKeyReply(r);
      final signed = parse(
        FakeKeys.reply('signed', key: 65, signature: 70, data: 37),
      );
      expect(signed.outcome, KeyOutcome.signed);
      expect(signed.authenticatorData.length, 37);
      for (final bad in [
        FakeKeys.reply('signed', key: 65, signature: 70), // a raw proof
        FakeKeys.reply('signed', key: 65, signature: 70, data: 36),
        FakeKeys.reply('cancelled', data: 37),
        FakeKeys.reply('signed', key: 33, signature: 70, data: 37),
        FakeKeys.reply('signed', key: 65, signature: 73, data: 37),
        FakeKeys.reply('bogus'),
      ]) {
        expect(parse(bad).outcome, KeyOutcome.failed);
      }
      expect(
        parse(FakeKeys.reply('present', key: 65)).outcome,
        KeyOutcome.present,
      );
    });

    test('sign names its session, token and purpose; cancel its own', () async {
      final keys = FakeKeys()
        ..next = FakeKeys.reply('signed', key: 65, signature: 70, data: 37);
      final platform = CoreApprovalKeyPlatform(
        operatingSystem: 'windows',
        api: keys,
      );
      final reply = await platform.sign(
        binding,
        KeyPurpose.enroll,
        Uint8List(3),
        7,
      );
      expect(reply.outcome, KeyOutcome.signed);
      final call = keys.calls.single;
      expect(call[0], 'sign');
      expect(call[2], matches(RegExp(r'^[0-9a-f]{32}$')));
      expect((call[3], call[4]), (7, 'enroll'));
      await platform.cancel(7);
      expect(keys.cancels.single, (call[2], 7));
    });

    test('native channels never carry authenticator data', () {
      final reply = parseKeyReply({
        'outcome': 'signed',
        'publicKey': Uint8List.fromList([4, ...List.filled(64, 1)]),
        'signature': Uint8List(70),
      });
      expect(reply.authenticatorData, isEmpty);
    });
  });

  test('Windows and Linux never say Touch ID', () {
    for (final v in UserVerification.values) {
      final windows = VerificationWording.of('windows', v);
      expect((windows.method, windows.device), ('Windows Hello', 'this PC'));
      final linux = VerificationWording.of('linux', v);
      expect(linux.method, isNot(contains('Touch ID')));
      expect(linux.device, 'this computer');
    }
    expect(UserVerification.windowsHello.label, 'Windows Hello');
    expect(
      parseUserVerification('macos', 'windowsHello'),
      UserVerification.unavailable,
    );
  });
}
