import 'dart:typed_data';

import 'package:companion_slice/platform/approval_key.dart';
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
}
