import 'dart:async';
import 'dart:io' show Platform;

import 'package:flutter/foundation.dart';

import '../platform/approval_client.dart';
import '../platform/approval_key.dart';
import '../src/rust/api/biometric.dart' as bio;
import '../src/rust/api/provider.dart' as core;
import 'approval_attempts.dart';
import 'controller.dart';

/// Production Touch ID approval and own-device key enrollment (issue 49).
/// Rust builds and checks every transcript, the Secure Enclave signs only
/// after Touch ID, and the provider verifies. Any refusal, cancellation or
/// error ends the attempt with nothing sent; password approval stays.
class TouchIdController extends ChangeNotifier {
  TouchIdController(this.provider, this.platform, {String? operatingSystem})
    : operatingSystem = operatingSystem ?? Platform.operatingSystem {
    provider.addListener(_observeReview);
  }
  final ProviderController provider;
  final ApprovalKeyPlatform platform;

  /// This device's system: selects the prompt wording (#60).
  final String operatingSystem;

  /// The verification the key last reported available (Face ID, ...).
  UserVerification _verification = UserVerification.unavailable;

  /// How messages name the verification and this device; macOS keeps
  /// "Touch ID" and "this Mac".
  VerificationWording get wording =>
      VerificationWording.of(operatingSystem, _verification);
  bool available = false, working = false;
  KeyOutcome local = KeyOutcome.absent;
  String message = '';
  int _token = 0;
  int? _active;
  bool _disposed = false, _exempt = false;

  /// The open request-bound authorization (#60 lifecycle rule).
  final attempts = ApprovalAttempts();

  /// The request the approval [message] is about ('' for key management),
  /// and how the user can recognise it (its operation and a short id).
  String _messageRequest = '', _messageLabel = '';

  /// The approval message was already shown with another request's review;
  /// the next review load clears it.
  bool _earlierShown = false;
  String _observedReview = '';

  /// The approval message as shown with the review of [requestId]. An
  /// approval's outcome is never presented as another request's: on any
  /// other review it names the request it is about.
  String messageFor(String requestId) =>
      message.isEmpty || _messageRequest.isEmpty || _messageRequest == requestId
      ? message
      : 'Earlier request ($_messageLabel): $message';

  /// What the user sees of request [id] at a glance: its operation and the
  /// start of its id as the request list shows it.
  static String requestLabel(String id, String operation) {
    final short = id.length > 8 ? '${id.substring(0, 8)}…' : id;
    return operation.isEmpty ? short : '$operation, $short';
  }

  /// An earlier request's approval message is shown with the first other
  /// review loaded after it, and cleared by the next review load.
  void _observeReview() {
    final id = provider.state.reviewId;
    if (id == _observedReview) return;
    _observedReview = id;
    if (id.isEmpty ||
        working ||
        message.isEmpty ||
        _messageRequest.isEmpty ||
        id == _messageRequest) {
      return;
    }
    if (!_earlierShown) {
      _earlierShown = true;
      return;
    }
    message = '';
    _messageRequest = '';
    _earlierShown = false;
    _publish();
  }

  /// Retire the open authorization (background, lock, interruption,
  /// navigation, selection) and cancel its prompt. A signature that still
  /// arrives afterwards sends nothing.
  Future<void> retire() async {
    attempts.retire();
    await cancel();
  }

  /// Called when an approval or enrollment ends, so the page applies the
  /// window's current lifecycle state (it ignored `inactive`/`resumed`
  /// while the system prompt was up).
  VoidCallback? onExemptionEnded;

  /// A Touch ID prompt is open (the window may be inactive meanwhile).
  bool get prompting => _active != null;

  /// An approval or enrollment with a system prompt is running.
  bool get lifecycleExempt => _exempt;

  String get notSent =>
      '${wording.method} signed, but the review changed or the approval could not start. Nothing was sent; try again.';

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
    final w = wording;
    if (!available) {
      return '${w.startMethod} is unavailable on ${w.device}. Approve with your password.';
    }
    final state = review;
    if (state == null) return '${w.startMethod} approval is unavailable.';
    if (state.support == bio.BiometricSupport.unsupported) {
      return 'This provider does not support ${w.method} approval. Restart the app after upgrading it.';
    }
    if (state.refusal == bio.BiometricRefusal.bindingUnavailable ||
        !state.bindingAvailable) {
      return 'The provider offered no ${w.method} binding for this review. Approve with your password.';
    }
    if (!state.biometricAllowed) {
      return state.keyId.isEmpty
          ? 'No ${w.method} key is enrolled for ${w.device}. Enroll it in Settings, or approve with your password.'
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
    // Ending while another request's review is shown displays the message
    // there once; the next review load clears it.
    _observedReview = provider.state.reviewId;
    _earlierShown =
        _messageRequest.isNotEmpty &&
        _observedReview.isNotEmpty &&
        _observedReview != _messageRequest;
    _publish();
    if (!_disposed) onExemptionEnded?.call();
  }

  /// Whether the key can sign now; remembers which verification it uses.
  Future<bool> _checkAvailable() async {
    final keys = platform;
    if (keys is! UserVerificationPlatform) return keys.touchIdAvailable();
    final verification = await (keys as UserVerificationPlatform)
        .verification();
    if (verification == UserVerification.unavailable) return false;
    _verification = verification;
    return true;
  }

  Future<void> refreshLocal() async {
    available = await _checkAvailable();
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
    // Selecting another request (or any invalidation) retires the attempt
    // and cancels the prompt.
    void watch() {
      if (provider.state.reviewId != id) unawaited(retire());
    }

    final attempt = attempts.begin(id);
    _start();
    _messageRequest = id;
    _messageLabel = requestLabel(id, provider.state.review?.operation ?? '');
    var recover = false;
    try {
      available = await _checkAvailable();
      if (!available) {
        message = unavailableReason;
        return;
      }
      await provider.review(id);
      if (!attempts.admits(attempt, provider.state.reviewId) ||
          provider.state.reviewId != id ||
          provider.state.reviewText != shown ||
          _origin(id) != origin ||
          !provider.state.canDecide) {
        message = 'The request changed or is no longer pending. Nothing was approved. Check the refreshed review.';
        return;
      }
      // From the fresh review on, any change of the shown review retires the
      // attempt (the fetch above passes through an empty review).
      provider.addListener(watch);
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
      if (!attempts.admits(attempt, provider.state.reviewId) ||
          !provider.state.canDecide) {
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
      message = text.isNotEmpty
          ? text
          : 'The provider answer was not a ${wording.method} result. Check the request status before trying again.';
      recover = provider.recoveryId.isNotEmpty;
    } finally {
      provider.removeListener(watch);
      attempts.end(attempt);
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
    _messageRequest = '';
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
    _messageRequest = '';
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

  String _signFailure(KeyOutcome outcome) {
    final w = wording;
    return switch (outcome) {
      KeyOutcome.cancelled =>
        '${w.startMethod} was cancelled. Nothing was sent. Try again or approve with your password.',
      KeyOutcome.unavailable =>
        '${w.startMethod} is unavailable or locked out. Nothing was sent. Approve with your password.',
      KeyOutcome.invalidated =>
        'A ${w.change} change invalidated ${w.device}\'s ${w.method} key. Nothing was sent. Enroll again in Settings (a new key replaces it), or approve with your password.',
      KeyOutcome.absent =>
        '${w.startDevice} has no approval key for this provider. Nothing was sent. Enroll it in Settings, or approve with your password.',
      KeyOutcome.refused =>
        '${w.startDevice}\'s key does not match the enrolled key or the request binding. Nothing was sent.',
      _ =>
        '${w.startMethod} signing failed. Nothing was sent. Approve with your password.',
    };
  }

  String resultText(bio.BiometricDecisionResult result) => switch (result) {
    bio.BiometricDecisionResult.approved =>
      'Approved once with ${wording.method}.',
    bio.BiometricDecisionResult.stale => 'The review expired or changed before the provider received the approval. Nothing was approved; obtain a fresh review.',
    bio.BiometricDecisionResult.passwordRequired =>
      'The provider refused the ${wording.method} proof (key replaced, retired or password required). Approve with your password.',
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
    provider.removeListener(_observeReview);
    final token = _active;
    if (token != null) unawaited(platform.cancel(token));
    super.dispose();
  }
}
