import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:companion_slice/platform/approval_key.dart';
import 'package:companion_slice/platform/provider.dart';
import 'package:companion_slice/provider/controller.dart';
import 'package:companion_slice/provider/touch_id.dart';

import 'provider_support.dart';

/// SHA-256 of the canonical JSON of `tests/fixtures/companion/review.json`'s
/// review (sorted keys, no whitespace, literal UTF-8), as the provider binds it.
const reviewDigest =
    '57c88fac8b5d729c58efb7c2bf45432098d28bfb3d585d69bb66b56413a7f654';
final golden = jsonDecode(
  File('../tests/fixtures/approval-v2-golden.json').readAsStringSync(),
) as Map<String, dynamic>;
Uint8List b64(String text) =>
    base64Url.decode(text.padRight((text.length + 3) & ~3, '='));
final publicKey = b64(golden['public_key'] as String);
final goldenKeyId = golden['approval']['key_id'] as String;

class FakeKeys implements ApprovalKeyPlatform {
  bool available = true, present = true;

  /// What `read` reports for a present key (`invalidated` after a
  /// fingerprint change).
  KeyOutcome presentOutcome = KeyOutcome.present;
  KeyOutcome signOutcome = KeyOutcome.signed;
  int availabilityChecks = 0, reads = 0;

  /// When set, `sign` waits for it (the system prompt is open meanwhile).
  Completer<void>? prompt;
  void Function()? onPrompt;
  final cancelled = <int>[];
  Uint8List signature = b64(golden['approval']['signature'] as String);
  final signed = <(KeyPurpose, Uint8List)>[];
  final created = <KeyBinding>[], deleted = <KeyBinding>[];
  @override
  Future<bool> touchIdAvailable() async {
    availabilityChecks++;
    return available;
  }

  @override
  Future<KeyReply> read(KeyBinding b) async => ++reads > 0 && present
      ? KeyReply(presentOutcome, publicKey)
      : KeyReply(KeyOutcome.absent);
  @override
  Future<KeyReply> create(KeyBinding b) async {
    created.add(b);
    present = true;
    presentOutcome = KeyOutcome.present;
    return KeyReply(KeyOutcome.created, publicKey);
  }

  @override
  Future<KeyReply> delete(KeyBinding b) async {
    deleted.add(b);
    present = false;
    return KeyReply(KeyOutcome.deleted);
  }

  @override
  Future<KeyReply> sign(
    KeyBinding b,
    KeyPurpose purpose,
    Uint8List transcript,
    int token,
  ) async {
    signed.add((purpose, transcript));
    onPrompt?.call();
    if (prompt != null) await prompt!.future;
    if (presentOutcome == KeyOutcome.invalidated) {
      return KeyReply(KeyOutcome.invalidated);
    }
    return signOutcome == KeyOutcome.signed
        ? KeyReply(KeyOutcome.signed, publicKey, signature)
        : KeyReply(signOutcome);
  }

  @override
  Future<void> cancel(int token) async => cancelled.add(token);
}

Map<String, dynamic>? binding(
  Map<String, dynamic> reply, {
  bool allowed = true,
  String? keyId,
}) => {
  'version': 2,
  'domain': 'dev.vaultwarden.provider.approval.v2',
  'action': 'approve',
  'provider_identity': 'a' * 64,
  'approval_client': 'b' * 64,
  'key_id': allowed ? (keyId ?? goldenKeyId) : null,
  'biometric_allowed': allowed,
  'request_id': providerId,
  'record_digest': '3d' * 32,
  'policy_digest': reply['review']['policy_digest'],
  'arguments_digest': reply['review']['arguments_digest'],
  'expires_at_unix_seconds': reply['review']['expires_at_unix_seconds'],
  'generation': reply['generation'],
  'ticket': reply['ticket'],
  'ticket_deadline_unix_ms': 1,
  'review_digest': reviewDigest,
};

Future<(ProviderController, TouchIdController)> reviewed(
  FixtureProviderPlatform native,
  FakeKeys keys,
) async {
  final provider = ProviderController(native);
  await provider.initialize();
  final touchId = TouchIdController(provider, keys);
  await touchId.refreshLocal();
  await provider.review(providerId);
  return (provider, touchId);
}

List<Map<String, dynamic>> decisions(FixtureProviderPlatform n) =>
    n.commands.where((c) => c['command'] == 'decision').toList();

String prefix(Uint8List transcript) =>
    utf8.decode(transcript.sublist(4, 4 + transcript[3]));

/// Provider fixture with the golden enrollment identities and key commands.
class KeyFixture extends FixtureProviderPlatform {
  KeyFixture(this.enroll, String provider, String client) {
    saved = ProviderConfiguration(
      configured: true,
      endpoint: 'https://fixture.example/v1/companion',
      pin: provider,
      fingerprint: client,
    );
  }
  final Map<String, dynamic> enroll;
  bool loseRevoke = false;
  String? keyId;

  Map<String, dynamic> get target => {
    'kind': 'approval_client',
    'id': saved.fingerprint,
  };

  @override
  Future<Uint8List> send(Uint8List body) async {
    final command = jsonDecode(utf8.decode(body)) as Map<String, dynamic>;
    switch (command['command']) {
      case 'biometric_prepare':
        commands.add(command);
        final enrolling = command['operation'] == 'enroll';
        return encoded({
          'version': 2,
          'operation': command['operation'],
          'target': target,
          'action_id': enrolling ? enroll['action_id'] : 'R' * 43,
          'ticket': enrolling ? enroll['ticket'] : '7' * 64,
          'generation': 4,
          'valid_for_seconds': 55,
          'provider_identity': saved.pin,
          'biometric_key_id': keyId,
        });
      case 'biometric_enroll':
        commands.add(command);
        keyId = goldenKeyId;
        return encoded({
          'version': 2,
          'operation': 'enroll',
          'target': target,
          'action_id': command['action_id'],
          'biometric_key_id': keyId,
        });
      case 'biometric_revoke':
        commands.add(command);
        if (loseRevoke) throw StateError('Synthetic lost response');
        final revoked = keyId;
        keyId = null;
        return encoded({
          'version': 2,
          'operation': 'revoke',
          'target': target,
          'action_id': command['action_id'],
          'revoked_key_id': revoked,
        });
    }
    return super.send(body);
  }
}
