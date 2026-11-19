import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import '../src/rust/api/enrollment.dart' as enroll;
import 'controller.dart';

enum EnrollmentMode { none, add, join }

typedef _Work = ({int token, Uint8List body});

/// Largest OS user/group ID an agent invitation accepts (`u32::MAX` and 0
/// are refused by the provider).
const maxAgentId = 4294967294;

/// Guided enrollment journeys (#59 phase 2). Rust owns the protocol, the
/// invitation secret and every reply's validation; this class only schedules
/// exchanges through [ProviderController.exchange] and keeps UI state.
///
/// The joining session survives navigation and app inactivity (its code may
/// be on screen while the human talks to the provider owner); only Cancel,
/// Start over, a provider change (detected in Rust) or closing the app end
/// it. The owner's shown invitation and session list are retired with every
/// other authority.
class EnrollmentFlow extends ChangeNotifier {
  EnrollmentFlow(this.provider, {this.tick = const Duration(seconds: 1)})
    : joiner = enroll.enrollmentJoinerSnapshot(),
      admin = enroll.enrollmentAdminSnapshot() {
    provider.addListener(_providerChanged);
    if (joiner.phase != enroll.JoinerPhase.idle) mode = EnrollmentMode.join;
  }
  final ProviderController provider;
  final Duration tick;
  enroll.JoinerSnapshot joiner;
  enroll.EnrollmentAdminSnapshot admin;
  EnrollmentMode mode = EnrollmentMode.none;
  String message = '';
  String selected = '';

  /// The shown invitation's code, read once from Rust per invitation.
  String invitationCode = '';
  bool _copied = false;
  Timer? _timer;
  int _ticks = 0;
  bool _disposed = false, _sending = false;

  bool get sending => _sending;
  bool get ready => provider.canEnroll && !_sending;
  bool get joinerLive => const [
    enroll.JoinerPhase.joining,
    enroll.JoinerPhase.compare,
    enroll.JoinerPhase.waiting,
  ].contains(joiner.phase);

  void _providerChanged() {
    admin = enroll.enrollmentAdminSnapshot();
    // Retired with every other authority (navigation, sleep, provider
    // change): forget the shown invitation, here and on the clipboard.
    if (admin.issued == null && invitationCode.isNotEmpty) _forgetInvitation();
    if (admin.sessions.isEmpty) selected = '';
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
    if (mode == EnrollmentMode.add) dismissInvitation();
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

  /// One background exchange: re-send the confirmation (or an
  /// unacknowledged cancel) until a final state, or watch for the owner's
  /// cancel, expiry or a mismatch typed at the provider; on the owner side,
  /// learn this client's authority again and refresh live sessions.
  Future<void> poll() async {
    if (_disposed || _sending || !provider.canEnroll) return;
    if (mode == EnrollmentMode.join) {
      if (joiner.phase == enroll.JoinerPhase.waiting) {
        await _joinerSend(enroll.JoinerCommand.confirm, quiet: true);
      } else if (joiner.phase == enroll.JoinerPhase.compare) {
        await _joinerSend(enroll.JoinerCommand.status, quiet: true);
      }
    } else if (mode == EnrollmentMode.add &&
        (admin.state == enroll.AdminState.unknown ||
            (admin.state == enroll.AdminState.ready &&
                admin.sessions.any(_live)))) {
      await list(quiet: true);
    }
  }

  static bool _live(enroll.AdminSessionView s) =>
      s.state == enroll.AdminSessionState.awaitingJoin ||
      s.state == enroll.AdminSessionState.awaitingApprovals;

  /// False (with a message) when another provider exchange is running.
  bool _admit(bool quiet) {
    if (ready) return true;
    if (!quiet) {
      message = 'The provider is busy or not connected. Try again.';
      _publish();
    }
    return false;
  }

  Future<Uint8List> _send(Uint8List body) async {
    _sending = true;
    _publish();
    try {
      final response = await provider.exchange(body);
      if (response == null) {
        message = 'The provider is busy or not connected. Try again.';
      }
      return response ?? Uint8List(0);
    } finally {
      _sending = false;
      _publish();
    }
  }

  // Joining endpoint ---------------------------------------------------------

  Future<void> join(String invitation) async {
    if (!_admit(false)) return;
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
    if (!_admit(quiet)) return;
    final _Work work;
    try {
      final w = enroll.enrollmentJoinerBegin(
        command: command,
        deviceFingerprint: provider.configuration.fingerprint,
        providerPin: provider.configuration.pin,
      );
      work = (token: w.token, body: w.body);
    } catch (error) {
      joiner = enroll.enrollmentJoinerSnapshot();
      if (!quiet) message = _plain(error);
      _publish();
      return;
    }
    if (!quiet) message = '';
    await _finishJoiner(work);
  }

  Future<void> _finishJoiner(_Work work) async {
    joiner = enroll.enrollmentJoinerSnapshot();
    final response = await _send(work.body);
    joiner = enroll.enrollmentJoinerFinish(
      token: work.token,
      response: response,
    );
    response.fillRange(0, response.length, 0);
    if (mode == EnrollmentMode.none && joinerLive) mode = EnrollmentMode.join;
    _schedule();
    _publish();
  }

  // Provider owner -------------------------------------------------------------

  Future<void> list({bool quiet = false}) async {
    await _admin(enroll.AdminCommand.list, quiet: quiet);
  }

  Future<void> invite({
    required enroll.EnrolleeRole role,
    required String label,
    int? uid,
    int? gid,
  }) async {
    final agent = role == enroll.EnrolleeRole.agent;
    bool valid(int? id) => id != null && id >= 1 && id <= maxAgentId;
    if (agent && (!valid(uid) || !valid(gid))) {
      message =
          'Enter the agent account\'s numeric user and group IDs (1 to $maxAgentId).';
      _publish();
      return;
    }
    await _admin(
      enroll.AdminCommand.invite,
      role: role,
      label: label,
      uid: agent ? uid! : 0,
      gid: agent ? gid! : 0,
    );
    if (admin.outcome == enroll.AdminOutcome.invited) {
      _forgetInvitation();
      invitationCode = enroll.enrollmentAdminInvitationCode();
      await list(quiet: true);
    }
  }

  /// True when the approval reached the provider (whatever it answered);
  /// false when nothing was sent, so the typed code can be kept.
  Future<bool> approve(String id, String code, String password) async {
    final sent = await _admin(
      enroll.AdminCommand.approve,
      id: id,
      code: code,
      password: password,
    );
    if (!sent) return false;
    switch (admin.outcome) {
      // Retry with the same selection after a throttle or a wrong password.
      case enroll.AdminOutcome.authenticationFailed:
      case enroll.AdminOutcome.rateLimited:
        break;
      case enroll.AdminOutcome.unavailable:
        // The outcome is unknown: read it back.
        selected = '';
        await list(quiet: true);
      default:
        selected = '';
    }
    _publish();
    return true;
  }

  Future<void> cancelInvitation(String id) async {
    await _admin(enroll.AdminCommand.cancel, id: id);
    if (admin.outcome == enroll.AdminOutcome.unavailable) {
      await list(quiet: true);
    }
  }

  /// The invitation was copied: it must leave the clipboard with it.
  void copiedInvitation() => _copied = true;

  void dismissInvitation() {
    admin = enroll.enrollmentAdminDismissInvitation();
    _forgetInvitation();
    _publish();
  }

  void _forgetInvitation() {
    final code = invitationCode;
    invitationCode = '';
    if (!_copied || code.isEmpty) return;
    _copied = false;
    unawaited(_clearClipboard(code));
  }

  static Future<void> _clearClipboard(String code) async {
    try {
      final current = await Clipboard.getData(Clipboard.kTextPlain);
      if (current?.text == code) {
        await Clipboard.setData(const ClipboardData(text: ''));
      }
    } catch (_) {
      // No clipboard on this platform: nothing was placed there either.
    }
  }

  void select(String id) {
    selected = id;
    message = '';
    _publish();
  }

  Future<bool> _admin(
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
    if (!_admit(quiet)) return false;
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
      return false;
    }
    admin = enroll.enrollmentAdminSnapshot();
    _publish();
    final response = await _send(work.body);
    admin = enroll.enrollmentAdminFinish(token: work.token, response: response);
    response.fillRange(0, response.length, 0);
    _publish();
    return true;
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
    _forgetInvitation();
    provider.removeListener(_providerChanged);
    super.dispose();
  }
}
