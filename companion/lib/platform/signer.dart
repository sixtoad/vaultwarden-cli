import 'dart:io';

import 'package:flutter/services.dart';

import '../src/rust/api.dart';

enum AuthenticationAvailability { touchId, unavailable }

abstract interface class ApprovalPlatform {
  Future<AuthenticationAvailability> availability();
  Future<Completion> perform(Work work);
  Future<void> cancel(int token);
  void Function() onInvalidation(void Function(Invalidation) callback);
}

class NativeApprovalPlatform implements ApprovalPlatform {
  NativeApprovalPlatform({bool? macOS, MethodChannel? channel})
    : _macOS = macOS ?? Platform.isMacOS,
      _channel =
          channel ??
          const MethodChannel('dev.vaultwarden.companionSlice/signer');
  final bool _macOS;
  final MethodChannel _channel;
  static final Map<String, Object> _handlerOwners = {};

  @override
  Future<AuthenticationAvailability> availability() async {
    if (!_macOS) return AuthenticationAvailability.unavailable;
    try {
      return await _channel.invokeMethod<Object?>('availability') == 'touchID'
          ? AuthenticationAvailability.touchId
          : AuthenticationAvailability.unavailable;
    } on PlatformException {
      return AuthenticationAvailability.unavailable;
    } on MissingPluginException {
      return AuthenticationAvailability.unavailable;
    }
  }

  @override
  Future<Completion> perform(Work work) async {
    if (!_macOS) return _empty(Outcome.unavailable);
    // Do not synthesize a completion on a timeout. Only a returned method call
    // can release the Rust admission slot; cancellation keeps awaiting it.
    try {
      final reply = await _channel.invokeMethod<Object?>('perform', {
        'token': work.token,
        'epoch': work.epoch,
        'operation': work.operation.name,
        'fixture': work.fixture,
        'expiresUnixMs': work.expiresUnixMs.toInt(),
        'nonce': work.nonce,
        'keyId': work.keyId,
      });
      if (reply is! Map) return _empty(Outcome.failed);
      final returnedSignature = reply['signature'];
      if (work.operation == Operation.noInteraction &&
          returnedSignature is Uint8List &&
          returnedSignature.isNotEmpty) {
        return _empty(Outcome.unsafe);
      }
      if (reply.length != 3 ||
          reply['publicKey'] is! Uint8List ||
          reply['signature'] is! Uint8List) {
        return _empty(Outcome.failed);
      }
      final key = reply['publicKey']! as Uint8List;
      final signature = reply['signature']! as Uint8List;
      if (key.length > 65 || signature.length > 72) {
        return _empty(Outcome.rejected);
      }
      final outcome =
          Outcome.values.where((o) => o.name == reply['outcome']).firstOrNull ??
          Outcome.failed;
      return Completion(outcome: outcome, publicKey: key, signature: signature);
    } on PlatformException {
      return _empty(Outcome.failed);
    } on MissingPluginException {
      return _empty(Outcome.unavailable);
    }
  }

  @override
  Future<void> cancel(int token) async {
    if (!_macOS) return;
    try {
      await _channel.invokeMethod<void>('cancel', token);
    } on PlatformException {
      /* The pending operation still owns admission. */
    } on MissingPluginException {
      /* No platform worker exists. */
    }
  }

  @override
  void Function() onInvalidation(void Function(Invalidation) callback) {
    if (!_macOS) return () {};
    final owner = Object();
    _handlerOwners[_channel.name] = owner;
    var subscribed = true;
    _channel.setMethodCallHandler((call) async {
      if (subscribed &&
          identical(_handlerOwners[_channel.name], owner) &&
          call.method == 'invalidate') {
        callback(
          call.arguments == 'sleep' ? Invalidation.sleep : Invalidation.close,
        );
      }
    });
    return () {
      subscribed = false;
      // An older widget must not unregister a replacement's channel handler.
      if (identical(_handlerOwners[_channel.name], owner)) {
        _handlerOwners.remove(_channel.name);
        _channel.setMethodCallHandler(null);
      }
    };
  }

  Completion _empty(Outcome outcome) => Completion(
    outcome: outcome,
    publicKey: Uint8List(0),
    signature: Uint8List(0),
  );
}
