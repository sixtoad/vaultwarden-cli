import 'dart:convert';
import 'dart:typed_data';

import 'package:companion_slice/platform/approval_key.dart';
import 'package:companion_slice/provider/page.dart';
import 'package:companion_slice/provider/touch_id.dart';
import 'package:flutter/material.dart';

import 'installation_settings_test.dart' show FakeInstallation;

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

  Widget page(FixtureProviderPlatform native, FakeKeys keys, String os) =>
      MaterialApp(
        home: ProviderPage(
          platform: native,
          syntheticBuilder: (_) => const SizedBox(),
          approvalKeys: keys,
          operatingSystem: os,
          installation: FakeInstallation(),
        ),
      );

  testWidgets('Windows names Windows Hello on the authorization step', (
    tester,
  ) async {
    final native = FixtureProviderPlatform()..approvalBinding = binding;
    await tester.pumpWidget(page(native, HelloKeys(), 'windows'));
    await tester.pumpAndSettle();
    await tester.ensureVisible(requestRow(providerId));
    await tester.tap(requestRow(providerId));
    await tester.pumpAndSettle();
    expect(
      find.textContaining('Windows Hello or password next'),
      findsOneWidget,
    );
    await startAuthorization(tester);
    expect(find.text('Approve once with Windows Hello'), findsOneWidget);
    expect(find.textContaining('Touch ID'), findsNothing);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('Linux settings offer no approval key and never say Touch ID', (
    tester,
  ) async {
    final keys = FakeKeys()..available = false;
    await tester.pumpWidget(page(FixtureProviderPlatform(), keys, 'linux'));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('destination-settings')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('linux-password-approval')), findsOneWidget);
    expect(find.byKey(const Key('touch-id-keys')), findsNothing);
    await tester.pumpWidget(const SizedBox.shrink());
  });
}
