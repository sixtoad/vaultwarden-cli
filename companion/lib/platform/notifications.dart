import 'dart:io';

import 'package:flutter/services.dart';

/// Operating-system permission for review notifications.
enum NotificationPermission { notDetermined, denied, authorized, unavailable }

/// Review-request notifications (#61). The native side owns the only text a
/// notification shows; Flutter passes nothing but an opaque token.
abstract interface class ReviewNotificationPlatform {
  bool get available;
  Future<NotificationPermission> permission();

  /// Shows the system permission prompt. Call only from an explicit user
  /// action (the Settings toggle), never at launch, and only right after
  /// [armPermissionRequest]: the native side refuses an unarmed request.
  Future<NotificationPermission> requestPermission();

  /// One-shot: allows the next [requestPermission]. Only the Settings toggle
  /// calls it.
  Future<void> armPermissionRequest();
  Future<bool> enabled();
  Future<void> setEnabled(bool value);
  Future<void> post(String token);

  /// Removes delivered notifications whose request is no longer pending.
  Future<void> withdraw(List<String> tokens);

  /// Holds (or releases) a system activity so the background watch's timer
  /// is not throttled by App Nap while the window is hidden.
  Future<void> setWatching(bool value);

  /// Registers the click handler; returns the tokens whose clicks arrived
  /// before Flutter was listening (oldest first).
  Future<List<String>> listen(void Function(String token) onOpen);
}

class UnavailableNotificationPlatform implements ReviewNotificationPlatform {
  const UnavailableNotificationPlatform();
  @override
  bool get available => false;
  @override
  Future<NotificationPermission> permission() async =>
      NotificationPermission.unavailable;
  @override
  Future<NotificationPermission> requestPermission() async =>
      NotificationPermission.unavailable;
  @override
  Future<void> armPermissionRequest() async {}
  @override
  Future<bool> enabled() async => false;
  @override
  Future<void> setEnabled(bool value) async {}
  @override
  Future<void> post(String token) async {}
  @override
  Future<void> withdraw(List<String> tokens) async {}
  @override
  Future<void> setWatching(bool value) async {}
  @override
  Future<List<String>> listen(void Function(String token) onOpen) async => [];
}

class NativeReviewNotificationPlatform implements ReviewNotificationPlatform {
  NativeReviewNotificationPlatform({bool? macOS, MethodChannel? channel})
    : available = macOS ?? Platform.isMacOS,
      _channel =
          channel ??
          const MethodChannel('dev.vaultwarden.companionSlice/notifications');
  @override
  final bool available;
  final MethodChannel _channel;
  static final tokenPattern = RegExp(r'^[A-Za-z0-9_-]{22}$');

  NotificationPermission _parse(Object? value) => switch (value) {
    'notDetermined' => NotificationPermission.notDetermined,
    'denied' => NotificationPermission.denied,
    'authorized' => NotificationPermission.authorized,
    _ => NotificationPermission.unavailable,
  };

  @override
  Future<NotificationPermission> permission() async {
    if (!available) return NotificationPermission.unavailable;
    return _parse(await _channel.invokeMethod<Object?>('status'));
  }

  @override
  Future<NotificationPermission> requestPermission() async {
    if (!available) return NotificationPermission.unavailable;
    return _parse(await _channel.invokeMethod<Object?>('requestAuthorization'));
  }

  @override
  Future<void> armPermissionRequest() async {
    if (!available) return;
    await _channel.invokeMethod<void>('armAuthorization');
  }

  @override
  Future<bool> enabled() async {
    if (!available) return false;
    return await _channel.invokeMethod<Object?>('enabled') == true;
  }

  @override
  Future<void> setEnabled(bool value) async {
    if (!available) return;
    await _channel.invokeMethod<void>('setEnabled', value);
  }

  @override
  Future<void> post(String token) async {
    if (!available) return;
    if (!tokenPattern.hasMatch(token)) throw const FormatException('token');
    await _channel.invokeMethod<void>('post', {'token': token});
  }

  @override
  Future<void> withdraw(List<String> tokens) async {
    if (!available || tokens.isEmpty) return;
    if (!tokens.every(tokenPattern.hasMatch)) {
      throw const FormatException('token');
    }
    await _channel.invokeMethod<void>('withdraw', {'tokens': tokens});
  }

  @override
  Future<void> setWatching(bool value) async {
    if (!available) return;
    await _channel.invokeMethod<void>('watching', value);
  }

  @override
  Future<List<String>> listen(void Function(String token) onOpen) async {
    if (!available) return [];
    _channel.setMethodCallHandler((call) async {
      final token = call.arguments;
      if (call.method == 'open' &&
          token is String &&
          tokenPattern.hasMatch(token)) {
        onOpen(token);
      }
    });
    final launched = await _channel.invokeMethod<Object?>('listen');
    return [
      if (launched is List)
        for (final token in launched)
          if (token is String && tokenPattern.hasMatch(token)) token,
    ];
  }
}
