import 'dart:convert';
import 'dart:typed_data';

import 'package:companion_slice/platform/approval_key.dart';
import 'package:companion_slice/provider/touch_id.dart';
import 'package:companion_slice/src/rust/api/biometric.dart' as bio;
import 'package:companion_slice/src/rust/frb_generated.dart';
import 'package:flutter_test/flutter_test.dart';

import 'provider_support.dart';
import 'touch_id_support.dart';

/// SHA-256("vaultwarden-access.approval-v2"): the Windows Hello RP id hash
/// (desktop-approval-spec D-8), pinned in Rust by both sides.
const rpIdHash =
    '9304ca3fa326db0b0f074d7157175dbe763381d50b99f366757ee493d2dcbc45';

Uint8List authenticatorData(int flags) => Uint8List.fromList([
  for (var i = 0; i < 64; i += 2)
    int.parse(rpIdHash.substring(i, i + 2), radix: 16),
  flags,
  0,
  0,
  0,
  1,
]);

/// A Windows Hello key: signatures come with WebAuthn authenticator data.
class HelloKeys extends FakeKeys {
  Uint8List data = authenticatorData(0x05);
  @override
  Future<KeyReply> sign(
    KeyBinding b,
    KeyPurpose purpose,
    Uint8List transcript,
    int token,
  ) async {
    final reply = await super.sign(b, purpose, transcript, token);
    return reply.outcome == KeyOutcome.signed
        ? KeyReply(reply.outcome, reply.publicKey, reply.signature, data)
        : reply;
  }
}

void main() {
  setUpAll(() async => RustLib.init());
  setUp(resetProvider);

  test('a Windows Hello approval sends its authenticator data and says Windows Hello', () async {
    final native = FixtureProviderPlatform()..approvalBinding = binding;
    final keys = HelloKeys();
    final (provider, macWording) = await reviewed(native, keys);
    macWording.dispose();
    final touchId = TouchIdController(
      provider,
      keys,
      operatingSystem: 'windows',
    );
    await touchId.refreshLocal();
    await provider.review(providerId);
    await touchId.approve();
    final proof = decisions(native).single['proof'] as Map<String, dynamic>;
    expect(proof['key_id'], goldenKeyId);
    expect(
      proof['authenticator_data'],
      base64Url.encode(keys.data).replaceAll('=', ''),
    );
    expect(touchId.message, 'Approved once with Windows Hello.');
    touchId.dispose();
    provider.dispose();
  });

  test('data without user verification is never sent', () async {
    final native = FixtureProviderPlatform()..approvalBinding = binding;
    final keys = HelloKeys()..data = authenticatorData(0x01);
    final (provider, touchId) = await reviewed(native, keys);
    await touchId.approve();
    expect(decisions(native), isEmpty);
    expect(
      bio.providerBiometricState().result,
      isNot(bio.BiometricDecisionResult.inFlight),
    );
    touchId.dispose();
    provider.dispose();
  });
}
