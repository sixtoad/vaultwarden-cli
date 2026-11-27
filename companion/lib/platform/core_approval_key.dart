import 'dart:io';
import 'dart:math';

import 'package:flutter/services.dart';

import '../src/rust/api/desktop_key.dart' as core;
import 'approval_client.dart';
import 'approval_key.dart';

/// The generated bridge calls; tests replace them.
class CoreKeyApi {
  const CoreKeyApi();
  Future<String> availability() => core.desktopKeyAvailability();
  Future<core.DesktopKeyReply> call(
    String method,
    KeyBinding binding, {
    String session = '',
    int token = 0,
    String purpose = '',
    Uint8List? transcript,
  }) => switch (method) {
    'read' => core.desktopKeyRead(
      providerIdentity: binding.providerIdentity,
      approvalClient: binding.approvalClient,
    ),
    'create' => core.desktopKeyCreate(
      providerIdentity: binding.providerIdentity,
      approvalClient: binding.approvalClient,
    ),
    'delete' => core.desktopKeyDelete(
      providerIdentity: binding.providerIdentity,
      approvalClient: binding.approvalClient,
    ),
    _ => core.desktopKeySign(
      providerIdentity: binding.providerIdentity,
      approvalClient: binding.approvalClient,
      session: session,
      token: token,
      purpose: purpose,
      transcript: transcript ?? Uint8List(0),
    ),
  };
  void cancel(String session, int token) =>
      core.desktopKeyCancel(session: session, token: token);
}

/// The Windows Hello approval key (docs/implementation/desktop-approval-spec.md
/// D-6) through the Rust core. Linux, and anything but Windows, is
/// `unavailable`: it approves with the provider password (D-9).
class CoreApprovalKeyPlatform
    implements ApprovalKeyPlatform, UserVerificationPlatform {
  CoreApprovalKeyPlatform({
    String? operatingSystem,
    this.api = const CoreKeyApi(),
  }) : _windows = (operatingSystem ?? Platform.operatingSystem) == 'windows',
       _session = _nonce();
  final CoreKeyApi api;
  final bool _windows;
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
    if (!_windows) return UserVerification.unavailable;
    try {
      return parseUserVerification('windows', await api.availability());
    } catch (_) {
      return UserVerification.unavailable;
    }
  }

  Future<KeyReply> _call(
    String method,
    KeyBinding binding, {
    String session = '',
    int token = 0,
    String purpose = '',
    Uint8List? transcript,
  }) async {
    if (!_windows) return KeyReply(KeyOutcome.unavailable);
    try {
      return parseCoreKeyReply(
        await api.call(
          method,
          binding,
          session: session,
          token: token,
          purpose: purpose,
          transcript: transcript,
        ),
      );
    } catch (_) {
      return KeyReply(KeyOutcome.failed);
    }
  }

  @override
  Future<KeyReply> read(KeyBinding binding) => _call('read', binding);
  @override
  Future<KeyReply> create(KeyBinding binding) => _call('create', binding);
  @override
  Future<KeyReply> delete(KeyBinding binding) => _call('delete', binding);
  @override
  Future<KeyReply> sign(
    KeyBinding binding,
    KeyPurpose purpose,
    Uint8List transcript,
    int token,
  ) => _call(
    'sign',
    binding,
    session: _session,
    token: token,
    purpose: purpose.name,
    transcript: transcript,
  );

  @override
  Future<void> cancel(int token) async {
    if (!_windows) return;
    try {
      api.cancel(_session, token);
    } catch (_) {
      /* The open signature still owns its slot. */
    }
  }
}

/// The key reply schema of `parseKeyReply` plus the authenticator data:
/// exactly 37 bytes with `signed`, empty otherwise. A malformed reply is
/// `failed`, never a signature.
KeyReply parseCoreKeyReply(core.DesktopKeyReply reply) {
  final data = reply.authenticatorData;
  final parsed = parseKeyReply({
    'outcome': reply.outcome,
    'publicKey': reply.publicKey,
    'signature': reply.signature,
  });
  final signed = parsed.outcome == KeyOutcome.signed;
  if (signed ? data.length != 37 : data.isNotEmpty) {
    return KeyReply(KeyOutcome.failed);
  }
  return KeyReply(parsed.outcome, parsed.publicKey, parsed.signature, data);
}
