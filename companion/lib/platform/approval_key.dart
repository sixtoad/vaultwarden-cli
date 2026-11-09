import 'dart:io';

import 'package:flutter/services.dart';

/// Outcomes of the production approval key channel. Anything unknown is
/// `failed`; no outcome grants authority: Rust and the provider verify.
enum KeyOutcome {
  present,
  absent,
  created,
  deleted,
  signed,
  cancelled,
  unavailable,
  missingKey,
  refused,
  failed,
  unsafe,
}

enum KeyPurpose { approve, enroll }

class KeyReply {
  KeyReply(this.outcome, [Uint8List? publicKey, Uint8List? signature])
    : publicKey = publicKey ?? Uint8List(0),
      signature = signature ?? Uint8List(0);
  final KeyOutcome outcome;
  final Uint8List publicKey, signature;
}

/// The pinned identities a production key is bound to: the provider TLS
/// leaf SHA-256 and this device's client leaf SHA-256 (64 lowercase hex).
class KeyBinding {
  const KeyBinding(this.providerIdentity, this.approvalClient);
  final String providerIdentity, approvalClient;
  Map<String, Object> get arguments => {
    'providerIdentity': providerIdentity,
    'approvalClient': approvalClient,
  };
}

/// The macOS Secure Enclave approval key (one per provider and client). The
/// synthetic demonstration key lives on a different channel and tag.
abstract interface class ApprovalKeyPlatform {
  Future<bool> touchIdAvailable();
  Future<KeyReply> read(KeyBinding binding);
  Future<KeyReply> create(KeyBinding binding);
  Future<KeyReply> delete(KeyBinding binding);
  Future<KeyReply> sign(
    KeyBinding binding,
    KeyPurpose purpose,
    Uint8List transcript,
    int token,
  );
  Future<void> cancel(int token);
}

class NativeApprovalKeyPlatform implements ApprovalKeyPlatform {
  NativeApprovalKeyPlatform({bool? macOS, MethodChannel? channel})
    : _macOS = macOS ?? Platform.isMacOS,
      _channel =
          channel ??
          const MethodChannel('dev.vaultwarden.companionSlice/approvalKey');
  final bool _macOS;
  final MethodChannel _channel;

  @override
  Future<bool> touchIdAvailable() async {
    if (!_macOS) return false;
    try {
      return await _channel.invokeMethod<Object?>('availability') == 'touchID';
    } on PlatformException {
      return false;
    } on MissingPluginException {
      return false;
    }
  }

  @override
  Future<KeyReply> read(KeyBinding binding) => _call('read', binding.arguments);
  @override
  Future<KeyReply> create(KeyBinding binding) =>
      _call('create', binding.arguments);
  @override
  Future<KeyReply> delete(KeyBinding binding) =>
      _call('delete', binding.arguments);
  @override
  Future<KeyReply> sign(
    KeyBinding binding,
    KeyPurpose purpose,
    Uint8List transcript,
    int token,
  ) => _call('sign', {
    ...binding.arguments,
    'token': token,
    'purpose': purpose.name,
    'transcript': transcript,
  });

  @override
  Future<void> cancel(int token) async {
    if (!_macOS) return;
    try {
      await _channel.invokeMethod<void>('cancel', token);
    } on PlatformException {
      /* The pending signature still owns its slot. */
    } on MissingPluginException {
      /* No platform worker. */
    }
  }

  Future<KeyReply> _call(String method, Map<String, Object> arguments) async {
    if (!_macOS) return KeyReply(KeyOutcome.unavailable);
    try {
      return parseKeyReply(
        await _channel.invokeMethod<Object?>(method, arguments),
      );
    } on PlatformException {
      return KeyReply(KeyOutcome.failed);
    } on MissingPluginException {
      return KeyReply(KeyOutcome.unavailable);
    }
  }
}

/// Closed reply schema. A malformed reply is `failed`, never a signature.
KeyReply parseKeyReply(Object? reply) {
  if (reply is! Map ||
      reply.length != 3 ||
      reply['publicKey'] is! Uint8List ||
      reply['signature'] is! Uint8List) {
    return KeyReply(KeyOutcome.failed);
  }
  final outcome =
      KeyOutcome.values.where((o) => o.name == reply['outcome']).firstOrNull ??
      KeyOutcome.failed;
  final key = reply['publicKey'] as Uint8List;
  final signature = reply['signature'] as Uint8List;
  if ((key.isNotEmpty && (key.length != 65 || key.first != 4)) ||
      signature.length > 72 ||
      (outcome == KeyOutcome.signed &&
          (signature.length < 8 || key.length != 65)) ||
      (outcome != KeyOutcome.signed && signature.isNotEmpty)) {
    return KeyReply(KeyOutcome.failed);
  }
  return KeyReply(outcome, key, signature);
}
