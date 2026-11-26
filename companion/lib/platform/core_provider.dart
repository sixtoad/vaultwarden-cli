import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';

import '../src/rust/api/desktop_provider.dart' as core;
import 'provider.dart';

/// Systems whose provider transport is the Rust core instead of a native
/// channel (docs/implementation/desktop-approval-spec.md, D-1/D-2).
const coreTransportSystems = {'linux', 'windows'};

bool isCoreTransportSystem(String operatingSystem) =>
    coreTransportSystems.contains(operatingSystem);

/// A transport whose setup reads the CA and the PKCS#12 by absolute path
/// (D-4); Dart never holds their bytes.
abstract interface class PathSetupPlatform {
  Future<ProviderConfiguration> setupFromFiles(
    String endpoint,
    String pin,
    String caPath,
    String identityPath,
    String passphrase,
  );
}

/// The generated bridge calls; tests replace them.
class CoreProviderApi {
  const CoreProviderApi();
  Future<core.DesktopProviderConfiguration> configuration() =>
      core.desktopProviderConfiguration();
  Future<core.DesktopProviderConfiguration> setup(
    String endpoint,
    String pin,
    String caPath,
    String identityPath,
    String passphrase,
  ) => core.desktopProviderSetup(
    endpoint: endpoint,
    pin: pin,
    caPath: caPath,
    identityPath: identityPath,
    passphrase: passphrase,
  );
  Future<Uint8List> send(Uint8List body, bool foreground) =>
      core.desktopProviderSend(body: body, foreground: foreground);
  Future<void> settle(String id) => core.desktopProviderSettle(id: id);
  void invalidate() => core.desktopProviderInvalidate();
}

/// The `ProviderPlatform` contract (docs/mobile-clients.md section 1) over
/// the Rust core on Windows and Linux. The closed reply schemas and size
/// limits are the native channel's.
class CoreProviderPlatform implements ProviderPlatform, PathSetupPlatform {
  CoreProviderPlatform({
    String? operatingSystem,
    this.api = const CoreProviderApi(),
    AppLifecycleState? Function()? lifecycle,
  }) : available = isCoreTransportSystem(
         operatingSystem ?? Platform.operatingSystem,
       ),
       _lifecycle = lifecycle ?? (() => WidgetsBinding.instance.lifecycleState);
  final CoreProviderApi api;
  final AppLifecycleState? Function() _lifecycle;
  @override
  final bool available;

  /// No lifecycle event yet counts as the foreground, as the page treats it.
  bool get _foreground {
    final state = _lifecycle();
    return state == null || state == AppLifecycleState.resumed;
  }

  static Map<String, Object> _wire(core.DesktopProviderConfiguration c) =>
      c.configured
      ? {
          'configured': true,
          'endpoint': c.endpoint,
          'pin': c.pin,
          'fingerprint': c.fingerprint,
          'uncertainId': c.uncertainId,
          'managementRecovery': c.managementRecovery,
        }
      : {'configured': false};

  @override
  Future<ProviderConfiguration> configuration() async {
    if (!available) return const ProviderConfiguration(configured: false);
    return parseProviderConfiguration(_wire(await api.configuration()));
  }

  /// The native file dialogs of macOS do not exist here: use
  /// [setupFromFiles].
  @override
  Future<ProviderConfiguration> setup(
    String endpoint,
    String pin,
    String passphrase,
  ) async => throw UnsupportedError('Select the CA and PKCS#12 by path');

  @override
  Future<ProviderConfiguration> setupFromFiles(
    String endpoint,
    String pin,
    String caPath,
    String identityPath,
    String passphrase,
  ) async {
    if (!available) throw UnsupportedError('Provider transport unavailable');
    return parseProviderConfiguration(
      _wire(await api.setup(endpoint, pin, caPath, identityPath, passphrase)),
    );
  }

  @override
  Future<Uint8List> send(Uint8List body) async {
    if (!available) throw UnsupportedError('Provider transport unavailable');
    if (body.length > 16384) throw const FormatException('Request too large');
    final reply = await api.send(body, _foreground);
    if (reply.length > 1048576) {
      throw const FormatException('Invalid provider response');
    }
    return reply;
  }

  @override
  Future<void> settle(String id) async {
    if (!available) throw UnsupportedError('Provider transport unavailable');
    await api.settle(id);
  }

  /// Leaving the foreground discards any prepared administrative ticket in
  /// Rust; hiding, pausing or detaching also retires the provider session
  /// (`inactive` alone does not: the Windows Hello prompt deactivates the
  /// window, and the page defers it during a prompt, spec D-5).
  @override
  void Function() onInvalidation(void Function() callback) {
    if (!available) return () {};
    final listener = AppLifecycleListener(
      onStateChange: (state) {
        if (state != AppLifecycleState.resumed) api.invalidate();
        if (const {
          AppLifecycleState.hidden,
          AppLifecycleState.paused,
          AppLifecycleState.detached,
        }.contains(state)) {
          callback();
        }
      },
    );
    return listener.dispose;
  }
}
