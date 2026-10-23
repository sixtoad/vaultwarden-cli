import 'dart:io';

import 'package:flutter/services.dart';

import '../provider/pilot_bundle.dart';

class ProviderConfiguration {
  const ProviderConfiguration({
    required this.configured,
    this.endpoint = '',
    this.pin = '',
    this.fingerprint = '',
    this.uncertainId = '',
  });
  final bool configured;
  final String endpoint, pin, fingerprint, uncertainId;
}

abstract interface class ProviderPlatform {
  bool get available;
  Future<ProviderConfiguration> configuration();
  Future<ProviderConfiguration> setup(
    String endpoint,
    String pin,
    String passphrase,
  );
  Future<Uint8List> send(Uint8List body);
  Future<void> settle(String id);
  void Function() onInvalidation(void Function() callback);
}

abstract interface class PilotProviderPlatform {
  Future<ProviderConfiguration> setupPilot(PilotBundle bundle);
}

class NativeProviderPlatform
    implements ProviderPlatform, PilotProviderPlatform {
  NativeProviderPlatform({bool? macOS, MethodChannel? channel})
    : available = macOS ?? Platform.isMacOS,
      _channel =
          channel ??
          const MethodChannel('dev.vaultwarden.companionSlice/provider');
  @override
  final bool available;
  final MethodChannel _channel;
  static final Map<String, Object> _owners = {};

  @override
  Future<ProviderConfiguration> setupPilot(PilotBundle bundle) async {
    if (!disposablePilotEnabled || !available) {
      throw UnsupportedError('Disposable pilot setup unavailable');
    }
    return _parse(
      await _channel.invokeMethod<Object?>(
        'setupDisposablePilotV1',
        bundle.nativeArguments,
      ),
    );
  }

  ProviderConfiguration _parse(Object? value) {
    if (value is Map && value.length == 1 && value['configured'] == false) {
      return const ProviderConfiguration(configured: false);
    }
    if (value is! Map ||
        value.length != 5 ||
        value['configured'] != true ||
        ![
          'endpoint',
          'pin',
          'fingerprint',
          'uncertainId',
        ].every((key) => value[key] is String)) {
      throw const FormatException('Invalid provider configuration');
    }
    final endpoint = value['endpoint'] as String;
    final pin = value['pin'] as String;
    final fingerprint = value['fingerprint'] as String;
    final id = value['uncertainId'] as String;
    if (endpoint.length > 2048 ||
        !RegExp(r'^[a-f0-9]{64}$').hasMatch(pin) ||
        !RegExp(r'^[a-f0-9]{64}$').hasMatch(fingerprint) ||
        (id.isNotEmpty && !RegExp(r'^[A-Za-z0-9_-]{43}$').hasMatch(id))) {
      throw const FormatException('Invalid provider configuration');
    }
    return ProviderConfiguration(
      configured: true,
      endpoint: endpoint,
      pin: pin,
      fingerprint: fingerprint,
      uncertainId: id,
    );
  }

  @override
  Future<ProviderConfiguration> configuration() async {
    if (!available) return const ProviderConfiguration(configured: false);
    return _parse(await _channel.invokeMethod<Object?>('configuration'));
  }

  @override
  Future<ProviderConfiguration> setup(
    String endpoint,
    String pin,
    String passphrase,
  ) async {
    if (!available) throw UnsupportedError('Provider transport unavailable');
    return _parse(
      await _channel.invokeMethod<Object?>('setup', {
        'endpoint': endpoint,
        'pin': pin,
        'passphrase': passphrase,
      }),
    );
  }

  @override
  Future<Uint8List> send(Uint8List body) async {
    if (!available) throw UnsupportedError('Provider transport unavailable');
    if (body.length > 16384) throw const FormatException('Request too large');
    final reply = await _channel.invokeMethod<Object?>('send', body);
    if (reply is! Uint8List || reply.length > 1048576) {
      throw const FormatException('Invalid provider response');
    }
    return reply;
  }

  @override
  Future<void> settle(String id) async {
    if (!available) throw UnsupportedError('Provider transport unavailable');
    await _channel.invokeMethod<void>('settle', id);
  }

  @override
  void Function() onInvalidation(void Function() callback) {
    if (!available) return () {};
    final owner = Object();
    _owners[_channel.name] = owner;
    _channel.setMethodCallHandler((call) async {
      if (identical(_owners[_channel.name], owner) &&
          call.method == 'invalidate') {
        callback();
      }
    });
    return () {
      if (identical(_owners[_channel.name], owner)) {
        _owners.remove(_channel.name);
        _channel.setMethodCallHandler(null);
      }
    };
  }
}
