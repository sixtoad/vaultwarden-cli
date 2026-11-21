import 'dart:io';
import 'dart:math';

import 'package:flutter/services.dart';

import 'approval_client.dart';

/// Outcomes of the production approval key channel. Anything unknown is
/// `failed`; no outcome grants authority: Rust and the provider verify.
enum KeyOutcome {
  present,
  absent,
  created,
  deleted,
  signed,

  /// The key exists, but a fingerprint change invalidated it.
  invalidated,
  cancelled,
  unavailable,
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

/// The hardware-backed approval key (one per provider and client): the
/// macOS Secure Enclave, the iOS Secure Enclave or an Android StrongBox/TEE
/// Keystore key. Every signature needs its own user verification. The
/// synthetic demonstration key lives on a different channel and tag. The
/// contract each platform meets is `docs/mobile-clients.md`.
abstract interface class ApprovalKeyPlatform {
  /// A request-bound, user-verified signer is available now (Touch ID on
  /// macOS; Face ID or Touch ID on iOS; Class 3 biometrics on Android; never
  /// the passcode alone). The historical name is kept for every
  /// implementation.
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

class NativeApprovalKeyPlatform
    implements ApprovalKeyPlatform, UserVerificationPlatform {
  /// [macOS] overrides whether the native channel exists here (default: an
  /// approval-client system; `true` alone means the macOS contract, as it
  /// always did); [operatingSystem] selects which `availability` replies
  /// are accepted (default: this system).
  NativeApprovalKeyPlatform({
    bool? macOS,
    MethodChannel? channel,
    String? operatingSystem,
  }) : _system =
           operatingSystem ??
           (macOS == true ? 'macos' : Platform.operatingSystem),
       _macOS =
           macOS ??
           isApprovalClientSystem(operatingSystem ?? Platform.operatingSystem),
       _channel =
           channel ??
           const MethodChannel('dev.vaultwarden.companionSlice/approvalKey'),
       _session = _nonce();
  final bool _macOS;
  final String _system;
  final MethodChannel _channel;

  /// Signature numbers are per session: the native side restarts its
  /// counter for a new session (a Dart hot restart keeps the native signer
  /// but restarts the Dart counter, which would otherwise be refused).
  final String _session;

  static String _nonce() {
    final random = Random.secure();
    return List.generate(
      16,
      (_) => random.nextInt(256).toRadixString(16).padLeft(2, '0'),
    ).join();
  }

  @override
  Future<bool> touchIdAvailable() async =>
      await verification() != UserVerification.unavailable;

  @override
  Future<UserVerification> verification() async {
    if (!_macOS) return UserVerification.unavailable;
    try {
      return parseUserVerification(
        _system,
        await _channel.invokeMethod<Object?>('availability'),
      );
    } on PlatformException {
      return UserVerification.unavailable;
    } on MissingPluginException {
      return UserVerification.unavailable;
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
    'session': _session,
    'token': token,
    'purpose': purpose.name,
    'transcript': transcript,
  });

  @override
  Future<void> cancel(int token) async {
    if (!_macOS) return;
    try {
      await _channel.invokeMethod<void>('cancel', {
        'session': _session,
        'token': token,
      });
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
