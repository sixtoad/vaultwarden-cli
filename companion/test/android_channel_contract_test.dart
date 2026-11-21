import 'dart:io';

import 'package:companion_slice/platform/approval_client.dart';
import 'package:companion_slice/platform/approval_key.dart';
import 'package:companion_slice/platform/notifications.dart';
import 'package:companion_slice/platform/provider.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

/// The Android approval client's channel contract (#60 phase 1,
/// docs/mobile-clients.md). The Kotlin side cannot run in a Dart test, so
/// these tests (a) read the constants and argument key sets straight out of
/// the Kotlin sources, so drift between the two languages fails here, and
/// (b) drive the real Dart channel clients against a fake Android native
/// side that applies the same closed schemas as the Kotlin handlers.
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  const kotlin = 'android/app/src/main/kotlin/dev/vaultwarden/companionslice';
  String source(String file) => File('$kotlin/$file').readAsStringSync();
  String constant(String file, String name) =>
      RegExp('const val $name = "([^"]*)"').firstMatch(source(file))!.group(1)!;

  group('Kotlin sources agree with the Dart clients', () {
    test('channel names', () {
      expect(
        constant('ApprovalKeyChannel.kt', 'NAME'),
        'dev.vaultwarden.companionSlice/approvalKey',
      );
      expect(
        constant('ProviderChannel.kt', 'NAME'),
        'dev.vaultwarden.companionSlice/provider',
      );
      expect(
        constant('ReviewNotifications.kt', 'NAME'),
        'dev.vaultwarden.companionSlice/notifications',
      );
      expect(
        constant('MainActivity.kt', 'LIFECYCLE_CHANNEL'),
        'dev.vaultwarden.companionSlice/lifecycle',
      );
    });

    test('availability reply is an Android verification Dart accepts', () {
      final reply = constant('ApprovalKeyChannel.kt', 'AVAILABLE');
      expect(
        parseUserVerification('android', reply),
        UserVerification.biometric,
      );
      // Android never claims a device-credential key (ApprovalKeySpec).
      expect(
        source('ApprovalKeyChannel.kt'),
        isNot(contains('"deviceCredential"')),
      );
    });

    test('sign arguments are exactly the keys Dart sends', () {
      expect(
        source('ApprovalKeyChannel.kt'),
        contains('setOf("session", "token", "purpose", "transcript")'),
      );
      expect(
        source('ApprovalKeyChannel.kt'),
        contains('keys + setOf("providerIdentity", "approvalClient")'),
      );
    });

    test('purposes and outcomes use the Dart enum names', () {
      expect(
        source('ApprovalTranscript.kt'),
        contains('enum class ApprovalPurpose { approve, enroll }'),
      );
      final outcomes = RegExp(r'enum class KeyOutcome \{ ([^}]*) \}')
          .firstMatch(source('KeyAttributePolicy.kt'))!
          .group(1)!
          .split(', ');
      expect(outcomes, KeyOutcome.values.map((o) => o.name).toList());
    });

    test('the key alias derivation matches the macOS tag', () {
      final swift = File('macos/Runner/ProductionApprovalContract.swift')
          .readAsStringSync();
      final prefix = RegExp(r'static let tagPrefix = "([^"]*)"')
          .firstMatch(swift)!
          .group(1)!;
      expect(constant('ApprovalTranscript.kt', 'ALIAS_PREFIX'), prefix);
    });

    test('notification copy is the macOS generic copy', () {
      final swift = File('macos/Runner/ReviewNotificationContract.swift')
          .readAsStringSync();
      String swiftConstant(String name) =>
          RegExp('static let $name = "([^"]*)"').firstMatch(swift)!.group(1)!;
      expect(
        constant('ReviewNotificationContract.kt', 'TITLE'),
        swiftConstant('title'),
      );
      expect(
        constant('ReviewNotificationContract.kt', 'BODY'),
        swiftConstant('body'),
      );
    });

    test('lifecycle reasons are the documented ones', () {
      final triggers = RegExp(
        r'(STOP|SCREEN_OFF|DESTROY)\("(\w+)", (null|"(\w+)")\)',
      ).allMatches(source('SignerGate.kt'));
      final reasons = {for (final m in triggers) m.group(1): m.group(2)};
      final signals = {for (final m in triggers) m.group(1): m.group(4)};
      expect(reasons, {
        'STOP': 'inactive',
        'SCREEN_OFF': 'inactive',
        'DESTROY': 'close',
      });
      expect(signals['SCREEN_OFF'], DeviceSignal.locked.name);
    });
  });

  group('Dart clients against a fake Android native side', () {
    const keyChannel = MethodChannel('test-android-approval-key');
    final binding = KeyBinding('1f' * 32, '2e' * 32);
    final publicKey = Uint8List.fromList([4, ...List.filled(64, 7)]);
    final der = Uint8List.fromList([
      0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, //
    ]);
    late List<MethodCall> calls;

    /// The Kotlin handler's admission rules (`ApprovalKeyChannel.binding`,
    /// `SignerGate`), returning `KeyReply.encode()` shapes.
    Object? android(MethodCall call, String outcome) {
      calls.add(call);
      Map<String, Object> reply(String o, [Uint8List? key, Uint8List? sig]) => {
        'outcome': o,
        'publicKey': key ?? Uint8List(0),
        'signature': sig ?? Uint8List(0),
      };
      final args = call.arguments;
      switch (call.method) {
        case 'availability':
          return 'biometric';
        case 'read' || 'create' || 'delete':
          if (args is! Map ||
              args.keys.toSet().difference({
                'providerIdentity',
                'approvalClient',
              }).isNotEmpty ||
              args.length != 2) {
            throw PlatformException(code: 'invalid_request');
          }
          return reply(
            call.method == 'read' ? 'present' : '${call.method}d',
            publicKey,
          );
        case 'sign':
          if (args is! Map ||
              args.keys.toSet().length != 6 ||
              !{
                'providerIdentity',
                'approvalClient',
                'session',
                'token',
                'purpose',
                'transcript',
              }.containsAll(args.keys) ||
              !RegExp(r'^[0-9a-f]{32}$').hasMatch(args['session'] as String) ||
              args['transcript'] is! Uint8List) {
            throw PlatformException(code: 'invalid_request');
          }
          return outcome == 'signed'
              ? reply('signed', publicKey, der)
              : reply(outcome);
        case 'cancel':
          return null;
      }
      throw MissingPluginException();
    }

    setUp(() => calls = []);
    tearDown(() => messenger.setMockMethodCallHandler(keyChannel, null));

    test(
      'a signed reply carries DER and the SEC1 key; nothing else signs',
      () async {
        for (final outcome in [
          'signed',
          'cancelled',
          'invalidated',
          'refused',
          'unavailable',
          'unsafe',
        ]) {
          messenger.setMockMethodCallHandler(
            keyChannel,
            (c) async => android(c, outcome),
          );
          final platform = NativeApprovalKeyPlatform(
            channel: keyChannel,
            operatingSystem: 'android',
          );
          final result = await platform.sign(
            binding,
            KeyPurpose.approve,
            Uint8List(10),
            1,
          );
          expect(result.outcome.name, outcome);
          expect(
            result.signature.isNotEmpty,
            outcome == 'signed',
            reason: outcome,
          );
          final sign = calls.single;
          expect((sign.arguments as Map)['purpose'], 'approve');
          expect((sign.arguments as Map)['token'], 1);
          calls.clear();
        }
      },
    );

    test('a cancelled prompt returning a signature is refused', () async {
      // A native bug that returned a signature with `cancelled` never approves.
      messenger.setMockMethodCallHandler(
        keyChannel,
        (c) async => {
          'outcome': 'cancelled',
          'publicKey': publicKey,
          'signature': der,
        },
      );
      final platform = NativeApprovalKeyPlatform(
        channel: keyChannel,
        operatingSystem: 'android',
      );
      final result = await platform.sign(
        binding,
        KeyPurpose.approve,
        Uint8List(10),
        1,
      );
      expect(result.outcome, KeyOutcome.failed);
      expect(result.signature, isEmpty);
    });

    test('a native argument refusal is failed, never signed', () async {
      messenger.setMockMethodCallHandler(
        keyChannel,
        (c) async => throw PlatformException(code: 'invalid_request'),
      );
      final platform = NativeApprovalKeyPlatform(
        channel: keyChannel,
        operatingSystem: 'android',
      );
      expect(
        (await platform.sign(
          binding,
          KeyPurpose.enroll,
          Uint8List(1),
          2,
        )).outcome,
        KeyOutcome.failed,
      );
    });

    test('key management and availability round-trip', () async {
      messenger.setMockMethodCallHandler(
        keyChannel,
        (c) async => android(c, 'signed'),
      );
      final platform = NativeApprovalKeyPlatform(
        channel: keyChannel,
        operatingSystem: 'android',
      );
      expect(await platform.verification(), UserVerification.biometric);
      expect((await platform.read(binding)).outcome, KeyOutcome.present);
      expect((await platform.create(binding)).outcome, KeyOutcome.created);
      expect((await platform.delete(binding)).outcome, KeyOutcome.deleted);
    });

    test(
      'Android lifecycle signals reach Dart; unknown ones are ignored',
      () async {
        const channel = MethodChannel('test-android-lifecycle');
        final platform = NativeDeviceSignalPlatform(
          operatingSystem: 'android',
          channel: channel,
        );
        final seen = <DeviceSignal>[];
        final stop = platform.listen(seen.add);
        Future<void> send(String signal) => messenger.handlePlatformMessage(
          channel.name,
          const StandardMethodCodec().encodeMethodCall(
            MethodCall('signal', signal),
          ),
          (_) {},
        );
        await send('locked');
        await send('screenOff');
        expect(seen, [DeviceSignal.locked]);
        stop();
      },
    );

    test('provider invalidation and notification opens arrive', () async {
      const provider = MethodChannel('test-android-provider');
      var invalidated = 0;
      final stop = NativeProviderPlatform(
        macOS: true,
        channel: provider,
      ).onInvalidation(() => invalidated++);
      await messenger.handlePlatformMessage(
        provider.name,
        const StandardMethodCodec().encodeMethodCall(
          const MethodCall('invalidate', 'inactive'),
        ),
        (_) {},
      );
      expect(invalidated, 1);
      stop();

      const notifications = MethodChannel('test-android-notifications');
      messenger.setMockMethodCallHandler(
        notifications,
        (c) async => <String>['A' * 22],
      );
      final opened = <String>[];
      final launched = await NativeReviewNotificationPlatform(
        macOS: true,
        channel: notifications,
      ).listen(opened.add);
      expect(launched, ['A' * 22]);
      for (final token in [
        'B' * 22,
        'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
      ]) {
        await messenger.handlePlatformMessage(
          notifications.name,
          const StandardMethodCodec().encodeMethodCall(
            MethodCall('open', token),
          ),
          (_) {},
        );
      }
      // A request id (43 chars) is never a token.
      expect(opened, ['B' * 22]);
      messenger.setMockMethodCallHandler(notifications, null);
    });
  });
}
