import 'dart:convert';
import 'dart:io';

import 'package:companion_slice/app/capabilities.dart';
import 'package:companion_slice/platform/approval_client.dart';
import 'package:companion_slice/platform/approval_key.dart';
import 'package:companion_slice/platform/provider.dart';
import 'package:flutter/foundation.dart' show setEquals;
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

/// The iOS native channels (#60 phase 2, companion/ios/Runner) against the
/// shared Dart clients. A fake platform answers exactly as
/// `MobileApprovalKeyChannel.swift` does: the argument keys it requires, the
/// `availability` names it sends and its closed `{outcome, publicKey,
/// signature}` replies. Real Face ID needs a physical iPhone
/// (scripts/ios-approval-hardware-evidence.sh).
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  final golden = jsonDecode(
    File('../tests/fixtures/approval-v2-golden.json').readAsStringSync(),
  ) as Map<String, Object?>;
  Uint8List b64url(String text) =>
      base64Url.decode(text.padRight((text.length + 3) ~/ 4 * 4, '='));
  Uint8List hex(String text) => Uint8List.fromList([
    for (var i = 0; i < text.length; i += 2)
      int.parse(text.substring(i, i + 2), radix: 16),
  ]);
  final approval = golden['approval']! as Map<String, Object?>;
  final publicKey = b64url(golden['public_key']! as String);
  final signature = b64url(approval['signature']! as String);
  final transcript = hex(approval['transcript_hex']! as String);
  final binding = KeyBinding(
    approval['provider_identity']! as String,
    approval['approval_client']! as String,
  );

  /// The iOS native side's `binding(_:keys:)` and reply encoding.
  const bindingKeys = {'providerIdentity', 'approvalClient'};
  const signKeys = {
    ...bindingKeys,
    'session',
    'token',
    'purpose',
    'transcript',
  };
  Map<String, Object> reply(String outcome, [Uint8List? key, Uint8List? sig]) =>
      {
        'outcome': outcome,
        'publicKey': key ?? Uint8List(0),
        'signature': sig ?? Uint8List(0),
      };

  late MethodChannel channel;
  late String availability;
  late Map<String, Object> signReply;
  final calls = <MethodCall>[];

  setUp(() {
    channel = const MethodChannel('test-ios-approval-key');
    availability = 'faceID';
    signReply = reply('cancelled');
    calls.clear();
    messenger.setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      final args = call.arguments;
      switch (call.method) {
        case 'availability':
          return availability;
        case 'read' || 'create' || 'delete':
          if (args is! Map ||
              args.keys.toSet().difference(bindingKeys).isNotEmpty ||
              args.length != 2) {
            throw PlatformException(code: 'invalid_request');
          }
          return reply('absent');
        case 'sign':
          if (args is! Map ||
              !setEquals(args.keys.toSet(), signKeys) ||
              args['transcript'] is! Uint8List ||
              !['approve', 'enroll'].contains(args['purpose'])) {
            throw PlatformException(code: 'invalid_request');
          }
          return signReply;
        case 'cancel':
          return null;
      }
      throw MissingPluginException();
    });
  });
  tearDown(() => messenger.setMockMethodCallHandler(channel, null));

  NativeApprovalKeyPlatform ios() =>
      NativeApprovalKeyPlatform(channel: channel, operatingSystem: 'ios');

  test(
    'Face ID and Touch ID are the iOS verifications; anything else is not',
    () async {
      expect(await ios().verification(), UserVerification.faceId);
      expect(await ios().touchIdAvailable(), isTrue);
      availability = 'touchID';
      expect(await ios().verification(), UserVerification.touchId);
      for (final other in ['unavailable', 'biometric', 'opticID']) {
        availability = other;
        expect(await ios().touchIdAvailable(), isFalse, reason: other);
      }
    },
  );

  test('sign sends exactly the keys the iOS channel admits', () async {
    signReply = reply('signed', publicKey, signature);
    final result = await ios().sign(binding, KeyPurpose.approve, transcript, 1);
    expect(result.outcome, KeyOutcome.signed);
    expect(result.signature, signature);
    expect(result.publicKey, publicKey);
    final call = calls.singleWhere((c) => c.method == 'sign');
    expect(call.arguments['transcript'], transcript, reason: 'exact bytes');
    expect(call.arguments['purpose'], 'approve');
  });

  test('cancel and errors from iOS never yield a signature', () async {
    for (final outcome in [
      'cancelled',
      'unavailable',
      'invalidated',
      'refused',
      'failed',
      'unsafe',
    ]) {
      signReply = reply(outcome);
      final result = await ios().sign(
        binding,
        KeyPurpose.approve,
        transcript,
        1,
      );
      expect(result.outcome.name, outcome);
      expect(result.signature, isEmpty);
    }
    // A cancel that wrongly carried bytes is refused by the closed schema.
    signReply = reply('cancelled', publicKey, signature);
    expect(
      (await ios().sign(binding, KeyPurpose.approve, transcript, 1)).outcome,
      KeyOutcome.failed,
    );
    // A native refusal of the call itself is `failed`, never `signed`.
    messenger.setMockMethodCallHandler(
      channel,
      (_) async => throw PlatformException(code: 'invalid_request'),
    );
    expect(
      (await ios().sign(binding, KeyPurpose.approve, transcript, 1)).outcome,
      KeyOutcome.failed,
    );
  });

  test('key operations send only the binding', () async {
    expect((await ios().read(binding)).outcome, KeyOutcome.absent);
    expect((await ios().create(binding)).outcome, KeyOutcome.absent);
    expect((await ios().delete(binding)).outcome, KeyOutcome.absent);
  });

  test('iOS provider invalidations retire the provider session', () async {
    const provider = MethodChannel('test-ios-provider');
    final platform = NativeProviderPlatform(macOS: true, channel: provider);
    var invalidations = 0;
    final stop = platform.onInvalidation(() => invalidations++);
    // MobileLifecycle.providerInvalidations: background/lock, termination.
    for (final reason in ['inactive', 'close']) {
      await messenger.handlePlatformMessage(
        provider.name,
        provider.codec.encodeMethodCall(MethodCall('invalidate', reason)),
        (_) {},
      );
    }
    expect(invalidations, 2);
    stop();
  });

  test('iOS device lock arrives as the locked signal', () async {
    const lifecycle = MethodChannel('test-ios-lifecycle');
    final signals = <DeviceSignal>[];
    final stop = NativeDeviceSignalPlatform(
      operatingSystem: 'ios',
      channel: lifecycle,
    ).listen(signals.add);
    await messenger.handlePlatformMessage(
      lifecycle.name,
      lifecycle.codec.encodeMethodCall(const MethodCall('signal', 'locked')),
      (_) {},
    );
    expect(signals, [DeviceSignal.locked]);
    stop();
  });

  test('an iPhone approves and never installs a desktop CLI', () {
    final iphone = DeviceCapabilities.derive(
      operatingSystem: 'ios',
      providerTransport: true,
      biometricSigner: true,
      reviewNotifications: true,
    );
    expect(iphone.canApprove, isTrue);
    expect(iphone.biometric, isTrue);
    expect(iphone.canExecute, isFalse);
    expect(iphone.cliInstall, isFalse);
    expect(isMobileSystem('ios'), isTrue);
  });
}
