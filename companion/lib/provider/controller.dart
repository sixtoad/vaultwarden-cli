import 'dart:async';

import 'package:flutter/foundation.dart';

import '../platform/provider.dart';
import '../src/rust/api/provider.dart' as core;

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
  String diagnostic = '';
  int _context = 0, _backoff = 5;
  Timer? _poll, _expiry;
  void Function()? _unsubscribe;
  VoidCallback? clearPasswords;
  bool get busy => state.busy || settingUp;
  bool get canSetup => platform.available && !busy && state.uncertainId.isEmpty;

  void _publish() {
    if (!_disposed) notifyListeners();
  }

  Future<void> initialize() async {
    if (!platform.available) return;
    final context = ++_context;
    _unsubscribe = platform.onInvalidation(invalidate);
    _expiry = Timer.periodic(const Duration(milliseconds: 250), (_) {
      final previous = state.reviewId;
      state = core.providerSnapshot();
      if (previous != state.reviewId) clearPasswords?.call();
      _publish();
    });
    try {
      final loaded = await platform.configuration();
      if (_disposed || context != _context) return;
      configuration = loaded;
      if (loaded.configured && !state.busy && state.uncertainId.isEmpty) {
        state = core.providerConfigure(uncertainId: loaded.uncertainId);
      }
      _publish();
      if (loaded.configured) await refresh();
    } catch (_) {
      diagnostic = 'Saved provider setup is unavailable. Check the dedicated client identity.';
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
  }

  void resume() {
    suspended = false;
    unawaited(refresh());
  }

  Future<void> setup(String endpoint, String pin, String passphrase) async {
    if (!canSetup) return;
    invalidate();
    final context = _context;
    settingUp = true;
    _poll?.cancel();
    diagnostic = '';
    _publish();
    try {
      final loaded = await platform.setup(endpoint, pin, passphrase);
      if (_disposed || context != _context) return;
      configuration = loaded;
      state = core.providerConfigure(uncertainId: loaded.uncertainId);
    } catch (_) {
      diagnostic = 'Setup cancelled or unavailable. Check HTTPS, CA, leaf pin and dedicated PKCS#12.';
    } finally {
      settingUp = false;
      clearPasswords?.call();
      _publish();
    }
    if (!_disposed && configuration.configured) await refresh();
  }

  Future<bool> perform(
    core.ProviderCommand command, {
    String id = '',
    String password = '',
  }) async {
    if (_disposed ||
        !platform.available ||
        !configuration.configured ||
        busy ||
        suspended) {
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
    state = core.providerSnapshot();
    final pendingId = state.uncertainId;
    _publish();
    Uint8List response;
    bool connected = true;
    try {
      response = await platform.send(work.body);
    } catch (_) {
      response = Uint8List(0);
      connected = false;
    } finally {
      work.body.fillRange(0, work.body.length, 0);
    }
    // Always finish, even after widget disposal/invalidation. Rust distinguishes
    // stale reads from decisions that may already have committed.
    final previousReview = state.reviewId;
    state = core.providerFinish(token: work.token, response: response);
    if (previousReview != state.reviewId) clearPasswords?.call();
    if (pendingId.isNotEmpty && state.uncertainId.isEmpty) {
      try {
        await platform.settle(pendingId);
      } catch (_) {
        diagnostic = 'Status received, but recovery storage could not be cleared. Reconnect before further decisions.';
        configuration = const ProviderConfiguration(configured: false);
      }
    }
    _publish();
    return connected;
  }

  Future<void> refresh() async {
    _poll?.cancel();
    if (_disposed || suspended || busy || !configuration.configured) {
      _schedule();
      return;
    }
    bool success;
    if (state.uncertainId.isNotEmpty) {
      success = await perform(
        core.ProviderCommand.status,
        id: state.uncertainId,
      );
    } else {
      success = await perform(core.ProviderCommand.session);
      if (success && !_disposed && !suspended) {
        success = await perform(core.ProviderCommand.list);
      }
    }
    _backoff = success ? 5 : (_backoff * 2).clamp(5, 30);
    _schedule();
  }

  void _schedule() {
    if (!_disposed && !suspended && configuration.configured) {
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
    if (state.uncertainId.isNotEmpty) await refresh();
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
