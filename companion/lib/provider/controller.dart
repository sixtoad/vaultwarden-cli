import 'dart:async';

import 'package:flutter/foundation.dart';

import '../platform/provider.dart';
import '../src/rust/api/provider.dart' as core;
import 'pilot_bundle.dart';

/// Rust owns admission, review and reply validation. Dart schedules only reads;
/// decision/unlock are exclusively explicit calls from the foreground UI.
class ProviderController extends ChangeNotifier {
  ProviderController(this.platform) : state = core.providerSnapshot();
  final ProviderPlatform platform;
  core.ProviderSnapshot state;
  ProviderConfiguration configuration = const ProviderConfiguration(
    configured: false,
  );
  bool settingUp = false, suspended = false, _disposed = false;
  bool _routeCurrent = true, _ready = false, _loaded = false;
  bool _activityCurrent = false;
  bool _reconciling = false, _operation = false;
  String _settlementId = '';
  String diagnostic = '';
  int _context = 0, _backoff = 5;
  Timer? _poll, _expiry;
  void Function()? _unsubscribe;
  VoidCallback? clearPasswords;
  bool get eligible => !_disposed && !suspended && _routeCurrent;
  bool get busy => state.busy || settingUp || _reconciling || _operation;
  String get recoveryId =>
      _settlementId.isNotEmpty ? _settlementId : state.uncertainId;
  bool get canSetup =>
      platform.available && eligible && _ready && !busy && recoveryId.isEmpty;
  bool get canSetupPilot =>
      disposablePilotEnabled &&
      platform is PilotProviderPlatform &&
      canSetup &&
      state.statusProgress != core.ProviderStatusProgress.committed;
  int get refreshDelaySeconds => _backoff;
  bool get connected =>
      eligible && _ready && configuration.configured && state.authorityKnown;
  void setActivityCurrent(bool current) {
    _activityCurrent = current;
  }

  void _publish() {
    if (!_disposed) notifyListeners();
  }

  Future<void> initialize() async {
    if (!platform.available) return;
    _unsubscribe = platform.onInvalidation(suspend);
    _expiry = Timer.periodic(const Duration(milliseconds: 250), (_) {
      final previous = state.reviewId;
      state = core.providerSnapshot();
      if (previous != state.reviewId) clearPasswords?.call();
      _publish();
    });
    await refresh();
  }

  bool _sameProvider(ProviderConfiguration value) =>
      value.configured == configuration.configured &&
      value.endpoint == configuration.endpoint &&
      value.pin == configuration.pin &&
      value.fingerprint == configuration.fingerprint;

  Future<void> _reconcile() async {
    if (_reconciling || settingUp || _operation || _disposed) return;
    final context = _context;
    _reconciling = true;
    _publish();
    try {
      final loaded = await platform.configuration();
      if (_disposed || context != _context) return;
      final same = _loaded && _sameProvider(loaded);
      if (recoveryId.isNotEmpty &&
          (!same ||
              (loaded.uncertainId.isNotEmpty &&
                  loaded.uncertainId != recoveryId))) {
        throw StateError('Original provider recovery required');
      }
      // Atomic marker removal may have succeeded before a later permissions
      // update threw. Only matching configured native metadata can prove that
      // settlement is already durable; it cannot resolve Rust uncertainty.
      if (same &&
          loaded.configured &&
          loaded.uncertainId.isEmpty &&
          _settlementId.isNotEmpty &&
          state.uncertainId.isEmpty) {
        _settlementId = '';
      }
      if (!same) {
        state = core.providerConfigure(uncertainId: loaded.uncertainId);
      } else if (loaded.uncertainId.isNotEmpty && recoveryId.isEmpty) {
        state = core.providerConfigure(uncertainId: loaded.uncertainId);
      }
      configuration = loaded;
      _loaded = true;
      _ready = true;
      diagnostic = '';
    } catch (_) {
      _ready = false;
      invalidate();
      diagnostic = 'Saved provider setup is unavailable. Check the dedicated client identity.';
    } finally {
      _reconciling = false;
      _publish();
    }
  }

  void invalidate() {
    _context++;
    clearPasswords?.call();
    state = core.providerInvalidate();
    _publish();
  }

  void suspend() {
    suspended = true;
    _poll?.cancel();
    invalidate();
    _ready = false;
  }

  void resume() {
    suspended = false;
    unawaited(refresh());
  }

  void setRouteCurrent(bool current) {
    _routeCurrent = current;
    if (!current) {
      _poll?.cancel();
      invalidate();
      _ready = false;
    } else if (eligible) {
      unawaited(refresh());
    }
  }

  Future<void> setup(String endpoint, String pin, String passphrase) async {
    if (!canSetup) return;
    invalidate();
    _ready = false;
    settingUp = true;
    _poll?.cancel();
    diagnostic = '';
    _publish();
    try {
      await platform.setup(endpoint, pin, passphrase);
    } catch (_) {
      diagnostic = 'Setup cancelled or unavailable. Check HTTPS, CA, leaf pin and dedicated PKCS#12.';
    } finally {
      settingUp = false;
      clearPasswords?.call();
      _publish();
    }
    // Native import/save may succeed while its dialogs make the app inactive.
    // Always reload persisted metadata; never keep the old label with new TLS.
    await _reconcile();
    if (eligible) await refresh();
  }

  Future<void> setupPilot(String input) async {
    clearPasswords?.call();
    if (!canSetupPilot) return; // mutation: pilot recovery admission
    PilotBundle bundle;
    try {
      bundle = PilotBundle.parse(input);
    } catch (_) {
      diagnostic = 'Invalid disposable pilot bundle.';
      _publish();
      return;
    }
    invalidate();
    final context = _context;
    _ready = false;
    settingUp = true;
    _poll?.cancel();
    diagnostic = '';
    _publish();
    var imported = false;
    try {
      final installed = await (platform as PilotProviderPlatform).setupPilot(
        bundle,
      );
      if (!eligible || context != _context) return;
      if (!installed.configured ||
          installed.uncertainId.isNotEmpty ||
          installed.endpoint != bundle.endpoint ||
          installed.pin != bundle.pin ||
          installed.fingerprint != bundle.fingerprint) {
        throw StateError('Disposable identity mismatch');
      }
      configuration = installed;
      state = core.providerConfigure(uncertainId: '');
      _loaded = true;
      _ready = true;
      imported = true;
    } catch (_) {
      diagnostic = 'Disposable setup failed. No unlock was sent. Check the bundle and dedicated identity.';
    } finally {
      settingUp = false;
      clearPasswords?.call();
      _publish();
    }
    // No refresh/retry after a failed or invalidated import. A later explicit
    // reload may reconcile persisted metadata, but never retains the password.
    if (!imported || !eligible || context != _context) {
      return; // mutation: pilot import success
    }
    await unlock(bundle.unlockPassword);
  }

  Future<bool> perform(
    core.ProviderCommand command, {
    String id = '',
    String password = '',
  }) async {
    if (!eligible ||
        !_ready ||
        !platform.available ||
        !configuration.configured ||
        busy ||
        (recoveryId.isNotEmpty &&
            (command != core.ProviderCommand.status || id != recoveryId))) {
      return false;
    }
    core.ProviderWork work;
    try {
      work = core.providerBegin(
        command: command,
        requestId: id,
        password: password,
      );
    } catch (_) {
      diagnostic =
          'A fresh review, valid password and idle provider are required.';
      clearPasswords?.call();
      _publish();
      return false;
    }
    if ([
      core.ProviderCommand.review,
      core.ProviderCommand.approve,
      core.ProviderCommand.deny,
      core.ProviderCommand.unlock,
    ].contains(command)) {
      clearPasswords?.call();
    }
    diagnostic = '';
    _operation = true;
    state = core.providerSnapshot();
    final pendingId = recoveryId;
    _publish();
    Uint8List response;
    try {
      response = await platform.send(work.body);
    } catch (_) {
      response = Uint8List(0);
    } finally {
      work.body.fillRange(0, work.body.length, 0);
    }
    // Always finish, even after widget disposal/invalidation. Rust distinguishes
    // stale reads from decisions that may already have committed.
    final previousReview = state.reviewId;
    state = core.providerFinish(token: work.token, response: response);
    if (previousReview != state.reviewId) clearPasswords?.call();
    final accepted = state.outcome == core.ProviderOutcome.accepted;
    final rejectedDecision =
        [
          core.ProviderCommand.approve,
          core.ProviderCommand.deny,
        ].contains(command) &&
        state.outcome == core.ProviderOutcome.rejected;
    if ([
          core.ProviderCommand.status,
          core.ProviderCommand.approve,
          core.ProviderCommand.deny,
        ].contains(command) &&
        pendingId.isNotEmpty &&
        state.uncertainId.isEmpty &&
        (accepted || rejectedDecision) &&
        state.statusProgress != core.ProviderStatusProgress.pending) {
      _settlementId = pendingId;
      try {
        await platform.settle(pendingId);
        _settlementId = '';
      } catch (_) {
        _ready = false;
        diagnostic = 'Status received, but recovery storage could not be cleared. Refresh the original request status to retry settlement.';
      }
    }
    _operation = false;
    _publish();
    return accepted && _settlementId.isEmpty;
  }

  Future<void> refresh() async {
    _poll?.cancel();
    if (!eligible || busy) {
      _schedule();
      return;
    }
    if (!_ready) await _reconcile();
    if (!eligible || busy || !_ready || !configuration.configured) {
      _schedule();
      return;
    }
    bool success;
    if (recoveryId.isNotEmpty ||
        state.statusProgress == core.ProviderStatusProgress.committed) {
      success = await perform(
        core.ProviderCommand.status,
        id: recoveryId.isNotEmpty ? recoveryId : state.statusId,
      );
      // A committed status ends delivery uncertainty only after durable marker
      // settlement. Activity may then read history under fresh authority, while
      // statusProgress still schedules the original execution on the next poll.
      if (success && eligible && _activityCurrent && recoveryId.isEmpty) {
        success = await perform(core.ProviderCommand.session);
        if (success && eligible && !state.locked) {
          success = await perform(core.ProviderCommand.history);
        }
      }
    } else {
      success = await perform(core.ProviderCommand.session);
      if (success && eligible && !state.locked) {
        success = await perform(core.ProviderCommand.list);
        if (success && eligible && _activityCurrent && !state.locked) {
          success = await perform(core.ProviderCommand.history);
        }
      }
    }
    _backoff = success ? 5 : (_backoff * 2).clamp(5, 30);
    _schedule();
  }

  void _schedule() {
    _poll?.cancel();
    if (eligible && platform.available) {
      _poll = Timer(Duration(seconds: _backoff), refresh);
    }
  }

  Future<void> review(String id) async {
    invalidate();
    await perform(core.ProviderCommand.review, id: id);
  }

  Future<void> decide(bool approve, String password) async {
    await perform(
      approve ? core.ProviderCommand.approve : core.ProviderCommand.deny,
      password: password,
    );
    if (recoveryId.isNotEmpty) await refresh();
    _schedule();
  }

  Future<void> unlock(String password) async {
    await perform(core.ProviderCommand.unlock, password: password);
    await refresh();
  }

  @override
  void dispose() {
    _disposed = true;
    _context++;
    clearPasswords?.call();
    clearPasswords = null;
    _poll?.cancel();
    _expiry?.cancel();
    _unsubscribe?.call();
    core.providerInvalidate();
    super.dispose();
  }
}
