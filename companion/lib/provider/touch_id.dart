import 'dart:async';

import 'package:flutter/foundation.dart';

import '../platform/approval_key.dart';
import '../src/rust/api/biometric.dart' as bio;
import '../src/rust/api/provider.dart' as core;
import 'controller.dart';

/// Production Touch ID approval and own-device key enrollment (issue 49).
/// Rust builds and checks every transcript, the Secure Enclave signs only
/// after Touch ID, and the provider verifies. Any refusal, cancellation or
/// error ends the attempt with nothing sent; password approval stays.
class TouchIdController extends ChangeNotifier {
  TouchIdController(this.provider, this.platform);
  final ProviderController provider;
  final ApprovalKeyPlatform platform;
  bool available = false, working = false;
  KeyOutcome local = KeyOutcome.absent;
  String message = '';
  int _token = 0;
  int? _active;
  bool _disposed = false;

  /// A Touch ID prompt is open (the window may be inactive meanwhile).
  bool get prompting => _active != null;

  KeyBinding? get binding {
    final c = provider.configuration;
    return c.configured ? KeyBinding(c.pin, c.fingerprint) : null;
  }

  bio.ProviderBiometricState? get review {
    try {
      return bio.providerBiometricState();
    } catch (_) {
      return null;
    }
  }

  /// Whether the Touch ID approve action may start for the current review.
  bool get canApprove {
    final state = review;
    return available &&
        !working &&
        !provider.busy &&
        provider.state.canDecide &&
        state != null &&
        state.canPrepare &&
        state.biometricAllowed;
  }

  /// Why Touch ID cannot approve the current review (empty when it can).
  String get unavailableReason {
    if (!available) {
      return 'Touch ID is unavailable on this Mac. Approve with your password.';
    }
    final state = review;
    if (state == null) return 'Touch ID approval is unavailable.';
    if (state.support == bio.BiometricSupport.unsupported) {
      return 'This provider does not support Touch ID approval. Restart the app after upgrading it.';
    }
    if (state.refusal == bio.BiometricRefusal.bindingUnavailable ||
        !state.bindingAvailable) {
      return 'The provider offered no Touch ID binding for this review. Approve with your password.';
    }
    if (!state.biometricAllowed) {
      return state.keyId.isEmpty
          ? 'No Touch ID key is enrolled for this Mac. Enroll it in Settings, or approve with your password.'
          : 'The provider policy requires a password for this request.';
    }
    if (!state.canPrepare) return 'Obtain a fresh review before approving.';
    return '';
  }

  void _publish() {
    if (!_disposed) notifyListeners();
  }

  Future<void> refreshLocal() async {
    available = await platform.touchIdAvailable();
    final b = binding;
    local = b == null ? KeyOutcome.absent : (await platform.read(b)).outcome;
    _publish();
  }

  /// Fetch a fresh review, require it to be exactly what was displayed,
  /// then sign its transcript after Touch ID and send one proof.
  Future<void> approve() async {
    if (!canApprove) return;
    final id = provider.state.reviewId, shown = provider.state.reviewText;
    final b = binding!;
    working = true;
    message = '';
    _publish();
    try {
      await provider.review(id);
      if (provider.state.reviewId != id ||
          provider.state.reviewText != shown ||
          !provider.state.canDecide) {
        message = 'The request changed or is no longer pending. Nothing was approved. Check the refreshed review.';
        return;
      }
      final state = review;
      if (state == null || !state.canPrepare || !state.biometricAllowed) {
        message = unavailableReason;
        return;
      }
      final bio.BiometricSigningRequest request;
      try {
        request = bio.providerBiometricPrepare();
      } catch (_) {
        message = 'This review cannot be signed. Nothing was sent.';
        return;
      }
      final token = ++_token;
      _active = token;
      final reply = await platform.sign(
        b,
        KeyPurpose.approve,
        request.transcript,
        token,
      );
      _active = null;
      if (reply.outcome != KeyOutcome.signed) {
        message = _signFailure(reply.outcome);
        return;
      }
      await provider.perform(
        core.ProviderCommand.approve,
        begin: () => bio.providerBiometricBegin(
          handle: request.handle,
          keyId: request.keyId,
          signature: reply.signature,
        ),
      );
      message = resultText(review?.result ?? bio.BiometricDecisionResult.none);
      if (provider.recoveryId.isNotEmpty) await provider.refresh();
    } finally {
      _active = null;
      working = false;
      _publish();
    }
  }

  Future<void> cancel() async {
    final token = _active;
    if (token != null) await platform.cancel(token);
  }

  /// Enroll this Mac's key: management ticket, Secure Enclave key (reused
  /// when one exists for this provider and client), proof of possession
  /// after Touch ID, then the fresh password. Never deletes a key.
  Future<void> enroll(String password) async {
    final b = binding;
    if (b == null || working || !available) return;
    working = true;
    message = '';
    _publish();
    try {
      await provider.performKey(
        () => bio.biometricKeyBegin(
          command: bio.BiometricKeyCommand.prepareEnroll,
        ),
      );
      if (!provider.keys.canEnroll) {
        message =
            'The provider did not issue an enrollment ticket. ${provider.keys.message}';
        return;
      }
      var key = await platform.read(b);
      if (key.outcome == KeyOutcome.absent) key = await platform.create(b);
      if (key.outcome != KeyOutcome.present &&
          key.outcome != KeyOutcome.created) {
        message =
            'This Mac could not provide a Secure Enclave key (${key.outcome.name}). Nothing was enrolled.';
        return;
      }
      local = KeyOutcome.present;
      final bio.BiometricEnrollRequest request;
      try {
        request = bio.biometricKeyEnrollTranscript(publicKey: key.publicKey);
      } catch (_) {
        message =
            'The enrollment ticket expired or the key was refused. Try again.';
        return;
      }
      final token = ++_token;
      _active = token;
      final proof = await platform.sign(
        b,
        KeyPurpose.enroll,
        request.transcript,
        token,
      );
      _active = null;
      if (proof.outcome != KeyOutcome.signed) {
        message = _signFailure(proof.outcome);
        return;
      }
      await provider.performKey(
        () => bio.biometricKeyBeginEnroll(
          password: password,
          publicKey: key.publicKey,
          signature: proof.signature,
        ),
      );
      message = provider.keys.message;
    } finally {
      _active = null;
      working = false;
      await refreshLocal();
    }
  }

  /// Revoke this Mac's key on the provider; the local key is deleted only
  /// after the provider confirmed the revocation.
  Future<void> revoke(String password) async {
    final b = binding;
    if (b == null || working) return;
    working = true;
    message = '';
    _publish();
    try {
      await provider.performKey(
        () => bio.biometricKeyBegin(
          command: bio.BiometricKeyCommand.prepareRevoke,
        ),
      );
      if (!provider.keys.canRevoke) {
        message =
            'The provider did not issue a revocation ticket. ${provider.keys.message}';
        return;
      }
      await provider.performKey(
        () => bio.biometricKeyBeginRevoke(password: password),
      );
      message = provider.keys.message;
      if (provider.keys.outcome == bio.BiometricKeyOutcome.revoked) {
        await platform.delete(b);
      }
    } finally {
      working = false;
      await refreshLocal();
    }
  }

  Future<void> readKey() async {
    await provider.performKey(
      () => bio.biometricKeyBegin(command: bio.BiometricKeyCommand.read),
    );
    await refreshLocal();
  }

  static String _signFailure(KeyOutcome outcome) => switch (outcome) {
    KeyOutcome.cancelled => 'Touch ID was cancelled. Nothing was sent. Try again or approve with your password.',
    KeyOutcome.unavailable => 'Touch ID is unavailable or locked out. Nothing was sent. Approve with your password.',
    KeyOutcome.absent || KeyOutcome.missingKey => 'This Mac has no approval key for this provider. Nothing was sent. Enroll it in Settings, or approve with your password.',
    KeyOutcome.refused => 'This Mac\'s key does not match the enrolled key or the request binding. Nothing was sent.',
    _ =>
      'Touch ID signing failed. Nothing was sent. Approve with your password.',
  };

  static String resultText(bio.BiometricDecisionResult result) =>
      switch (result) {
        bio.BiometricDecisionResult.approved => 'Approved once with Touch ID.',
        bio.BiometricDecisionResult.stale => 'The review expired or changed before the provider received the approval. Nothing was approved; obtain a fresh review.',
        bio.BiometricDecisionResult.passwordRequired => 'The provider refused the Touch ID proof (key replaced, retired or password required). Approve with your password.',
        bio.BiometricDecisionResult.rateLimited =>
          'Too many attempts. Wait a minute before trying again.',
        bio.BiometricDecisionResult.rejected =>
          'The provider rejected the decision. The request is final.',
        bio.BiometricDecisionResult.outcomeUnknown => 'The provider response was lost. Only the request status is checked now; nothing is resent.',
        _ => '',
      };

  @override
  void dispose() {
    _disposed = true;
    final token = _active;
    if (token != null) unawaited(platform.cancel(token));
    super.dispose();
  }
}
