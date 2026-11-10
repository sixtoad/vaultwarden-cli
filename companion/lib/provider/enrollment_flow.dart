import 'dart:async';

import 'package:flutter/foundation.dart';

import '../src/rust/api/enrollment.dart' as enroll;
import 'controller.dart';

enum EnrollmentMode { none, add, join }

typedef _Work = ({int token, Uint8List body});

/// Guided enrollment journeys (#59 phase 2). Rust owns the protocol, the
/// invitation secret and every reply's validation; this class only schedules
/// exchanges through [ProviderController.exchange] and keeps UI state.
///
/// The joining session survives navigation and app inactivity (its code may
/// be on screen while the human talks to the provider owner); only Cancel,
/// Start over, a provider change or closing the app forget it. The owner's
/// shown invitation and session list are retired with every other authority.
class EnrollmentFlow extends ChangeNotifier {
  EnrollmentFlow(this.provider, {this.tick = const Duration(seconds: 1)})
    : joiner = enroll.enrollmentJoinerSnapshot(),
      admin = enroll.enrollmentAdminSnapshot() {
    provider.addListener(_providerChanged);
    _identity = _currentIdentity();
    if (joiner.phase != enroll.JoinerPhase.idle) mode = EnrollmentMode.join;
  }
  final ProviderController provider;
  final Duration tick;
  enroll.JoinerSnapshot joiner;
  enroll.EnrollmentAdminSnapshot admin;
  EnrollmentMode mode = EnrollmentMode.none;
  String message = '';
  String selected = '';
  Timer? _timer;
  int _ticks = 0;
  bool _disposed = false, _sending = false;
  String _identity = '';

  bool get sending => _sending;
  bool get ready => provider.canEnroll && !_sending;
  bool get joinerLive => const [
    enroll.JoinerPhase.joining,
    enroll.JoinerPhase.compare,
    enroll.JoinerPhase.waiting,
  ].contains(joiner.phase);

  String _currentIdentity() => provider.configuration.configured
      ? '${provider.configuration.endpoint}|${provider.configuration.pin}|${provider.configuration.fingerprint}'
      : '';

  void _providerChanged() {
    final identity = _currentIdentity();
    if (identity != _identity && provider.configuration.configured) {
      // Another provider or client certificate: the session is not for it.
      if (_identity.isNotEmpty) joiner = enroll.enrollmentJoinerReset();
      _identity = identity;
    }
    admin = enroll.enrollmentAdminSnapshot();
    if (admin.issued == null && admin.sessions.isEmpty) selected = '';
    _publish();
  }

  void _publish() {
    if (!_disposed) notifyListeners();
  }

  Future<void> open(EnrollmentMode next) async {
    mode = next;
    message = '';
    _schedule();
    _publish();
    if (next == EnrollmentMode.add) await list();
  }

  void close() {
    if (mode == EnrollmentMode.add) {
      admin = enroll.enrollmentAdminDismissInvitation();
    }
    mode = joinerLive ? EnrollmentMode.join : EnrollmentMode.none;
    if (mode == EnrollmentMode.none) _timer?.cancel();
    selected = '';
    message = '';
    _publish();
  }

  void _schedule() {
    _timer?.cancel();
    if (_disposed || mode == EnrollmentMode.none) return;
    _timer = Timer.periodic(tick, (_) => unawaited(_onTick()));
  }

  Future<void> _onTick() async {
    if (_disposed) return;
    _ticks++;
    joiner = enroll.enrollmentJoinerSnapshot();
    _publish();
    if (_ticks % 3 == 0) await poll();
  }

  /// One background exchange: re-send the confirmation until a final state,
  /// or watch for the owner's cancel, expiry or a mismatch typed at the
  /// provider; on the owner side, refresh live sessions.
  Future<void> poll() async {
    if (_disposed || _sending) return;
    if (mode == EnrollmentMode.join) {
      if (joiner.phase == enroll.JoinerPhase.waiting) {
        await _joinerSend(enroll.JoinerCommand.confirm, quiet: true);
      } else if (joiner.phase == enroll.JoinerPhase.compare) {
        await _joinerSend(enroll.JoinerCommand.status, quiet: true);
      }
    } else if (mode == EnrollmentMode.add &&
        admin.state == enroll.AdminState.ready &&
        admin.sessions.any(_live)) {
      await list(quiet: true);
    }
  }

  static bool _live(enroll.AdminSessionView s) =>
      s.state == enroll.AdminSessionState.awaitingJoin ||
      s.state == enroll.AdminSessionState.awaitingApprovals;

  Future<Uint8List?> _send(Uint8List body) async {
    _sending = true;
    _publish();
    try {
      return await provider.exchange(body);
    } finally {
      _sending = false;
    }
  }

  // Joining endpoint ---------------------------------------------------------

  Future<void> join(String invitation) async {
    if (!ready) return;
    message = '';
    final _Work work;
    try {
      final w = enroll.enrollmentJoin(
        invitation: invitation,
        deviceFingerprint: provider.configuration.fingerprint,
        providerPin: provider.configuration.pin,
      );
      work = (token: w.token, body: w.body);
    } catch (error) {
      message = _plain(error);
      _publish();
      return;
    }
    await _finishJoiner(work);
  }

  Future<void> retry() => _joinerSend(enroll.JoinerCommand.retry);
  Future<void> confirm() => _joinerSend(enroll.JoinerCommand.confirm);
  Future<void> decline() => _joinerSend(enroll.JoinerCommand.decline);

  Future<void> cancelJoin() async {
    if (joiner.phase == enroll.JoinerPhase.joining) {
      // Not joined yet: nothing to authenticate a cancel with. Forget it.
      reset();
      return;
    }
    await _joinerSend(enroll.JoinerCommand.cancel);
  }

  void reset() {
    joiner = enroll.enrollmentJoinerReset();
    message = '';
    _publish();
  }

  Future<void> _joinerSend(
    enroll.JoinerCommand command, {
    bool quiet = false,
  }) async {
    if (!ready) return;
    final _Work work;
    try {
      final w = enroll.enrollmentJoinerBegin(command: command);
      work = (token: w.token, body: w.body);
    } catch (error) {
      if (!quiet) message = _plain(error);
      _publish();
      return;
    }
    await _finishJoiner(work);
  }

  Future<void> _finishJoiner(_Work work) async {
    joiner = enroll.enrollmentJoinerSnapshot();
    final response = await _send(work.body);
    joiner = enroll.enrollmentJoinerFinish(
      token: work.token,
      response: response ?? Uint8List(0),
    );
    if (response == null) message = 'The provider is busy. Try again.';
    if (mode == EnrollmentMode.none && joinerLive) mode = EnrollmentMode.join;
    _schedule();
    _publish();
  }

  // Provider owner -------------------------------------------------------------

  Future<void> list({bool quiet = false}) =>
      _admin(enroll.AdminCommand.list, quiet: quiet);

  Future<void> invite({
    required enroll.EnrolleeRole role,
    required String label,
    int uid = 0,
    int gid = 0,
  }) async {
    await _admin(
      enroll.AdminCommand.invite,
      role: role,
      label: label,
      uid: uid,
      gid: gid,
    );
    if (admin.outcome == enroll.AdminOutcome.invited) await list(quiet: true);
  }

  Future<void> approve(String id, String code, String password) => _admin(
    enroll.AdminCommand.approve,
    id: id,
    code: code,
    password: password,
  );

  Future<void> cancelInvitation(String id) =>
      _admin(enroll.AdminCommand.cancel, id: id);

  void dismissInvitation() {
    admin = enroll.enrollmentAdminDismissInvitation();
    _publish();
  }

  void select(String id) {
    selected = id;
    message = '';
    _publish();
  }

  Future<void> _admin(
    enroll.AdminCommand command, {
    enroll.EnrolleeRole role = enroll.EnrolleeRole.companion,
    String label = '',
    int uid = 0,
    int gid = 0,
    String id = '',
    String code = '',
    String password = '',
    bool quiet = false,
  }) async {
    if (!ready) return;
    if (!quiet) message = '';
    final _Work work;
    try {
      final w = enroll.enrollmentAdminBegin(
        request: enroll.EnrollmentAdminRequest(
          command: command,
          role: role,
          label: label,
          agentUid: uid,
          agentGid: gid,
          id: id,
          code: code,
          password: password,
        ),
      );
      work = (token: w.token, body: w.body);
    } catch (error) {
      message = _plain(error);
      _publish();
      return;
    }
    admin = enroll.enrollmentAdminSnapshot();
    _publish();
    final response = await _send(work.body);
    admin = enroll.enrollmentAdminFinish(
      token: work.token,
      response: response ?? Uint8List(0),
    );
    if (command == enroll.AdminCommand.approve &&
        admin.outcome != enroll.AdminOutcome.authenticationFailed) {
      selected = '';
    }
    _publish();
  }

  static String _plain(Object error) {
    final text = error.toString();
    // frb wraps Rust's closed messages; never surface anything else.
    final match = RegExp(r'[A-Z][^\n]{0,160}[.)]').firstMatch(text);
    return match?.group(0) ?? 'Not possible right now.';
  }

  @override
  void dispose() {
    _disposed = true;
    _timer?.cancel();
    provider.removeListener(_providerChanged);
    super.dispose();
  }
}
