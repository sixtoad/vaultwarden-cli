import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:flutter/material.dart';

import '../design/components.dart';
import '../platform/notifications.dart';

/// Review-request notifications (#61). Announces each newly pending request
/// once, while the window is not foreground, with the native side's fixed
/// generic text. The notification carries only a random token; the token maps
/// to the request id here, in memory. Opening it is never an approval: the
/// page loads a fresh review of that request from the provider.
class ReviewNotifier extends ChangeNotifier {
  ReviewNotifier(this.platform, {Random? random})
    : _random = random ?? Random.secure();
  final ReviewNotificationPlatform platform;
  final Random _random;

  /// Bound on remembered tokens and announced ids for one process.
  static const remembered = 256;
  bool enabled = false, busy = false, _disposed = false;
  NotificationPermission permission = NotificationPermission.unavailable;
  String message = '';

  /// The first inbox read after launch or a provider change is a baseline:
  /// requests already pending then are not announced (no burst).
  bool _baselined = false;

  /// Ids already announced or seen on screen: the only dedupe. An id whose
  /// post failed is removed again, so the next read retries it while the
  /// request is still pending.
  final Set<String> _announced = {};
  final Map<String, String> _tokens = {};

  /// Tokens whose notification may still be delivered, by request id.
  final Map<String, String> _delivered = {};
  bool _watching = false;

  bool get available =>
      platform.available && permission != NotificationPermission.unavailable;

  /// Notifications are posted only when on in Settings and permitted.
  bool get active =>
      available && enabled && permission == NotificationPermission.authorized;

  /// What the Settings switch shows: on only while notifications can post.
  bool get switchedOn => active;

  void _publish() {
    if (!_disposed) notifyListeners();
  }

  /// Reads the saved setting and the current permission. Never prompts.
  Future<void> load() async {
    try {
      permission = await platform.permission();
      enabled = await platform.enabled();
    } catch (_) {
      permission = NotificationPermission.unavailable;
      enabled = false;
    }
    if (enabled && permission == NotificationPermission.denied) {
      message = deniedText;
    }
    _publish();
  }

  /// Permission can change in System Settings while the app is away.
  Future<void> refreshPermission() async {
    if (!platform.available) return;
    try {
      permission = await platform.permission();
    } catch (_) {
      permission = NotificationPermission.unavailable;
    }
    if (enabled && permission == NotificationPermission.denied) {
      message = deniedText;
    }
    _publish();
  }

  static const deniedText =
      'Notifications are turned off for this app in System Settings → Notifications. Requests still appear here.';

  /// The Settings toggle: the only place the permission prompt is shown.
  Future<void> setEnabled(bool value) async {
    if (busy || !platform.available) return;
    busy = true;
    _publish();
    try {
      if (!value) {
        await platform.setEnabled(false);
        enabled = false;
        message = 'Review notifications are off.';
        return;
      }
      if (permission == NotificationPermission.notDetermined) {
        // The explicit toggle is the one path that arms the native prompt.
        await platform.armPermissionRequest();
        permission = await platform.requestPermission();
      } else {
        permission = await platform.permission();
      }
      enabled = permission == NotificationPermission.authorized;
      await platform.setEnabled(enabled);
      message = enabled
          ? 'Review notifications are on. They say only that a request needs your review.'
          : deniedText;
    } catch (_) {
      enabled = false;
      message = 'Notification setup failed. Requests still appear here.';
    } finally {
      busy = false;
      _publish();
    }
  }

  /// Every successful inbox read. A request seen while foreground is on
  /// screen already; one first seen while away is announced once.
  void observe(List<String> ids, {required bool foreground}) {
    final pending = ids.toSet();
    // Decided or expired: its delivered notification goes too. The token
    // stays resolvable, so a click racing the removal opens the final state.
    _withdraw([
      for (final entry in _delivered.entries)
        if (!pending.contains(entry.key)) entry.value,
    ]);
    _delivered.removeWhere((id, _) => !pending.contains(id));
    final fresh = ids.where((id) => !_announced.contains(id)).toList();
    final baseline = !_baselined;
    _baselined = true;
    if (foreground || !active || baseline) {
      _announced.addAll(fresh);
      _trim(pending);
      return;
    }
    for (final id in fresh) {
      _announced.add(id);
      final token = _token();
      _tokens[token] = id;
      _delivered[id] = token;
      unawaited(
        platform.post(token).catchError((Object _) {
          // Not shown: forget it so the next read announces it again.
          _announced.remove(id);
          _tokens.remove(token);
          if (_delivered[id] == token) _delivered.remove(id);
        }),
      );
    }
    _trim(pending);
  }

  void _withdraw(List<String> tokens) {
    if (tokens.isEmpty) return;
    unawaited(platform.withdraw(tokens).catchError((Object _) {}));
  }

  /// The background watch started or stopped: hold the native activity that
  /// keeps its timer out of App Nap only while it runs.
  void setWatching(bool value) {
    if (_watching == value || (value && !platform.available)) return;
    _watching = value;
    unawaited(platform.setWatching(value).catchError((Object _) {}));
  }

  /// The request a notification token stands for, if this process sent it.
  String? resolve(String token) => _tokens[token];

  /// A different provider: forget everything learned from the old one.
  void reset() {
    _withdraw(_delivered.values.toList());
    _delivered.clear();
    _baselined = false;
    _announced.clear();
    _tokens.clear();
  }

  String _token() {
    final bytes = List<int>.generate(16, (_) => _random.nextInt(256));
    return base64Url.encode(bytes).replaceAll('=', '');
  }

  /// Bounds memory. Ids still pending are never forgotten (that would
  /// announce them again); only ones that left the list are dropped, oldest
  /// first.
  void _trim(Set<String> pending) {
    while (_tokens.length > remembered) {
      _tokens.remove(_tokens.keys.first);
    }
    if (_announced.length <= remembered) return;
    final stale = _announced.where((id) => !pending.contains(id)).toList();
    for (final id in stale.take(_announced.length - remembered)) {
      _announced.remove(id);
    }
  }

  @override
  void dispose() {
    _disposed = true;
    super.dispose();
  }
}

/// Settings: turning notifications on is the explicit action that asks for
/// the operating system's permission.
class ReviewNotificationSettings extends StatelessWidget {
  const ReviewNotificationSettings({super.key, required this.notifier});
  final ReviewNotifier notifier;

  @override
  Widget build(BuildContext context) {
    final available = notifier.available;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const StatusLabel(
          'Review notifications',
          icon: Icons.notifications_none,
        ),
        SwitchListTile(
          key: const Key('review-notifications'),
          contentPadding: EdgeInsets.zero,
          value: notifier.switchedOn,
          onChanged: available && !notifier.busy
              ? (value) => unawaited(notifier.setEnabled(value))
              : null,
          title: const Text('Notify me when a request needs review'),
          subtitle: Text(
            available
                ? 'The notification says only "A request needs your review." Opening it loads a fresh review; it never approves. Notifications are sent while this window is open but not in front.'
                : 'Notifications are not available on this platform yet.',
          ),
        ),
        if (notifier.message.isNotEmpty)
          Text(
            notifier.message,
            key: const Key('review-notifications-message'),
          ),
      ],
    );
  }
}
