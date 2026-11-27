import 'dart:typed_data';

import 'package:companion_slice/platform/approval_key.dart';
import 'package:companion_slice/src/rust/api/biometric.dart' as bio;
import 'package:companion_slice/src/rust/frb_generated.dart';
import 'package:flutter_test/flutter_test.dart';

import 'p256_test_key.dart';
import 'provider_support.dart';
import 'touch_id_support.dart';

/// The bound key, but over other bytes: well-formed DER that does not verify.
class OtherBytesKeys extends FakeKeys {
  @override
  List<int> signedMessage(Uint8List transcript) => [...transcript, 0];
}

/// Another key than the provider's: its key id is not the review's.
class OtherKey extends FakeKeys {
  final other = TestP256Key(BigInt.from(11));
  @override
  Future<KeyReply> sign(
    KeyBinding b,
    KeyPurpose purpose,
    Uint8List transcript,
    int token,
  ) async {
    signed.add((purpose, transcript));
    return KeyReply(KeyOutcome.signed, other.publicKey, other.sign(transcript));
  }
}

/// docs/implementation/shared-approval-checks-spec.md S-3: the Rust core
/// verifies the signer's reply before any proof leaves the device, on every
/// platform (before, only the iOS and Android channels verified, natively).
void main() {
  setUpAll(() async => RustLib.init());
  setUp(resetProvider);

  for (final (name, keys) in [
    ('a signature that does not verify over the transcript', OtherBytesKeys()),
    ('a signature by a key other than the enrolled one', OtherKey()),
  ]) {
    test('$name is never sent and keeps the review', () async {
      final native = FixtureProviderPlatform()..approvalBinding = binding;
      final (provider, touchId) = await reviewed(native, keys);
      await touchId.approve();
      expect(keys.signed, hasLength(1), reason: 'the key did sign');
      expect(decisions(native), isEmpty, reason: 'nothing was sent');
      expect(touchId.message, touchId.notSent);
      expect(provider.state.canDecide, isTrue, reason: 'the review is kept');
      expect(
        bio.providerBiometricState().result,
        bio.BiometricDecisionResult.none,
      );
      touchId.dispose();
      provider.dispose();
    });
  }
}
