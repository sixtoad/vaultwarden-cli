import 'package:companion_slice/platform/approval_key.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test(
    'native key replies are a closed schema and never a bare signature',
    () async {
      Map<String, Object> reply(String outcome, int key, int signature) => {
        'outcome': outcome,
        'publicKey': Uint8List.fromList([4, ...List.filled(key - 1, 1)]),
        'signature': Uint8List(signature),
      };
      expect(parseKeyReply(reply('signed', 65, 70)).outcome, KeyOutcome.signed);
      for (final bad in <Object?>[
        null,
        'signed',
        reply('signed', 65, 4), // too short to be DER
        reply('signed', 65, 73), // longer than any P-256 DER signature
        reply('signed', 33, 70), // compressed or truncated point
        reply('cancelled', 65, 70), // a signature with a non-signed outcome
        {...reply('signed', 65, 70), 'extra': true},
      ]) {
        expect(parseKeyReply(bad).outcome, KeyOutcome.failed, reason: '$bad');
      }
      expect(parseKeyReply(reply('bogus', 65, 0)).outcome, KeyOutcome.failed);
      final other = NativeApprovalKeyPlatform(macOS: false);
      expect(await other.touchIdAvailable(), isFalse);
      const binding = KeyBinding('a', 'b');
      expect((await other.read(binding)).outcome, KeyOutcome.unavailable);
      expect(
        (await other.sign(
          binding,
          KeyPurpose.approve,
          Uint8List(1),
          1,
        )).outcome,
        KeyOutcome.unavailable,
      );
    },
  );

  testWidgets(
    'signatures and cancels carry a per-client session nonce, so a hot restart never reuses the native counter',
    (tester) async {
      const name = 'test/approvalKey';
      final calls = <MethodCall>[];
      tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
        const MethodChannel(name),
        (call) async {
          calls.add(call);
          return call.method == 'cancel'
              ? null
              : {
                  'outcome': 'cancelled',
                  'publicKey': Uint8List(0),
                  'signature': Uint8List(0),
                };
        },
      );
      const binding = KeyBinding('p', 'c');
      final first = NativeApprovalKeyPlatform(
        macOS: true,
        channel: const MethodChannel(name),
      );
      final restarted = NativeApprovalKeyPlatform(
        macOS: true,
        channel: const MethodChannel(name),
      );
      await first.sign(binding, KeyPurpose.approve, Uint8List(1), 1);
      await first.cancel(1);
      await restarted.sign(binding, KeyPurpose.enroll, Uint8List(1), 1);
      final sessions = [
        for (final call in calls) (call.arguments as Map)['session'],
      ];
      for (final session in sessions) {
        expect(session, matches(RegExp(r'^[0-9a-f]{32}$')));
      }
      expect(sessions[0], sessions[1], reason: 'cancel names its own session');
      expect(
        sessions[0],
        isNot(sessions[2]),
        reason: 'a new client is a new session',
      );
      expect(calls[1].arguments, {'session': sessions[0], 'token': 1});
      expect(
        KeyOutcome.values.map((o) => o.name),
        isNot(contains('missingKey')),
      );
    },
  );
}
