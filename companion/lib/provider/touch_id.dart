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
  bool _disposed = false, _exempt = false;

  /// Called when an approval or enrollment ends, so the page applies the
  /// window's current lifecycle state (it ignored `inactive`/`resumed`
  /// while the system prompt was up).
  VoidCallback? onExemptionEnded;

  /// A Touch ID prompt is open (the window may be inactive meanwhile).
  bool get prompting => _active != null;

  /// An approval or enrollment with a system prompt is running.
  bool get lifecycleExempt => _exempt;

  static const notSent =
      'Touch ID signed, but the review changed or the approval could not start. Nothing was sent; try again.';

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

  String _origin(String id) =>
      provider.management.originId == id ? provider.management.originText : '';

  void _start() {
    working = true;
    _exempt = true;
    message = '';
    provider.holdPolling();
    _publish();
  }

  void _end() {
    _active = null;
    provider.releasePolling();
    working = false;
    _exempt = false;
    _publish();
    if (!_disposed) onExemptionEnded?.call();
  }

  Future<void> refreshLocal() async {
    available = await platform.touchIdAvailable();
    final b = binding;
    local = b == null ? KeyOutcome.absent : (await platform.read(b)).outcome;
    _publish();
  }

  /// Fetch a fresh review, require it to be exactly what was displayed,
  /// then sign its transcript after Touch ID and send one proof. Polling is
  /// held meanwhile; any path that does not send says so.
  Future<void> approve() async {
    if (!canApprove) return;
    final id = provider.state.reviewId, shown = provider.state.reviewText;
    final origin = _origin(id);
    final b = binding!;
    // Selecting another request (or any invalidation) cancels the prompt.
    void watch() {
      if (provider.state.reviewId != id) unawaited(cancel());
    }

    _start();
    provider.addListener(watch);
    var recover = false;
    try {
      available = await platform.touchIdAvailable();
      if (!available) {
        message = unavailableReason;
        return;
      }
      await provider.review(id);
      if (provider.state.reviewId != id ||
          provider.state.reviewText != shown ||
          _origin(id) != origin ||
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
      if (provider.state.reviewId != id || !provider.state.canDecide) {
        message = notSent;
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
      if (!provider.lastPerformSent) {
        message = notSent;
        return;
      }
      final text = resultText(
        review?.result ?? bio.BiometricDecisionResult.none,
      );
      message = text.isNotEmpty ? text : 'The provider answer was not a Touch ID result. Check the request status before trying again.';
      recover = provider.recoveryId.isNotEmpty;
    } finally {
      provider.removeListener(watch);
      _end();
    }
    if (recover) await provider.refresh();
  }

  int? _cancelled;

  /// Cancel the open prompt (once per prompt).
  Future<void> cancel() async {
    final token = _active;
    if (token == null || token == _cancelled) return;
    _cancelled = token;
    await platform.cancel(token);
  }

  /// The local key could not be read (`unsafe`: not a Secure Enclave key
  /// with an access control; `failed`: the Keychain read failed). Enrolling
  /// then replaces it only after an explicit confirmation.
  bool get localUnreadable =>
      local == KeyOutcome.unsafe || local == KeyOutcome.failed;

  static const unknownKeyId =
      'This Mac\'s key could not be checked against the provider\'s current key. Nothing was sent; try again.';

  /// Enroll this Mac's key: management ticket, Secure Enclave key, proof of
  /// possession after Touch ID, then the fresh password. A local key is
  /// reused only when the provider holds it as current and it is usable;
  /// then nothing needs enrolling. Any other local key for this provider
  /// and client (retired, revoked, never enrolled, or invalidated by a
  /// fingerprint change) can never approve again and is replaced. A local
  /// key whose id cannot be computed is never deleted (the attempt ends),
  /// and an unreadable one is deleted only with [replaceUnreadable], which
  /// the key panel sets after the user confirmed the replacement.
  Future<void> enroll(String password, {bool replaceUnreadable = false}) async {
    final b = binding;
    if (b == null || working || !available) return;
    _start();
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
      local = key.outcome;
      final unreadable =
          key.outcome == KeyOutcome.unsafe || key.outcome == KeyOutcome.failed;
      if (unreadable && !replaceUnreadable) {
        message =
            'This Mac\'s approval key could not be read (${key.outcome.name}). Nothing was sent. Replace it to enroll: the unreadable key is deleted and a new one is created after you confirm. Until then, approve with your password.';
        return;
      }
      if (key.outcome == KeyOutcome.present ||
          key.outcome == KeyOutcome.invalidated ||
          unreadable) {
        if (key.outcome == KeyOutcome.present &&
            provider.keys.keyId.isNotEmpty) {
          // Never delete on an unknown id: the key may be the current one.
          final id = _keyId(key.publicKey);
          if (id.isEmpty) {
            message = unknownKeyId;
            return;
          }
          if (id == provider.keys.keyId) {
            message = 'This Mac\'s key is already the provider\'s current Touch ID key. Nothing was sent.';
            return;
          }
        }
        if ((await platform.delete(b)).outcome != KeyOutcome.deleted) {
          message = 'This Mac\'s old approval key could not be removed. Nothing was enrolled.';
          return;
        }
        key = await platform.create(b);
      } else if (key.outcome == KeyOutcome.absent) {
        key = await platform.create(b);
      }
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
      _end();
      await refreshLocal();
    }
  }

  /// The provider's key id for `publicKey` (SHA-256 of the SEC1 point, as
  /// Rust computes it for the current ticket); empty when unavailable.
  static String _keyId(Uint8List publicKey) {
    try {
      return bio.biometricKeyEnrollTranscript(publicKey: publicKey).keyId;
    } catch (_) {
      return '';
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
    KeyOutcome.invalidated => 'A fingerprint change invalidated this Mac\'s Touch ID key. Nothing was sent. Enroll again in Settings (a new key replaces it), or approve with your password.',
    KeyOutcome.absent => 'This Mac has no approval key for this provider. Nothing was sent. Enroll it in Settings, or approve with your password.',
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
