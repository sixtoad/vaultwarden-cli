// CI-only AOT entrypoint. The normal application has no fixture input/focus hooks.
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:companion_slice/platform/core_loader.dart';
import 'package:companion_slice/platform/provider.dart';
import 'package:companion_slice/provider/controller.dart';
import 'package:companion_slice/provider/pilot_bundle.dart';

import 'provider_tls_smoke.dart' as probe;

// Match ProviderPage's lifecycle forwarding: losing focus during an async
// setup must invalidate the controller operation before it can unlock.
class PilotLifecycle with WidgetsBindingObserver {
  PilotLifecycle(this.controller);
  final ProviderController controller;
  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      controller.resume();
    } else {
      controller.suspend();
    }
  }
}

Future<void> waitForFocus(bool foreground) async {
  final deadline = DateTime.now().add(const Duration(seconds: 5));
  while (DateTime.now().isBefore(deadline)) {
    final state = WidgetsBinding.instance.lifecycleState;
    // On desktop, resumed means the app's view has input focus. Observe the
    // real Flutter/AppKit transition; never inject a synthetic lifecycle event.
    if (foreground
        ? state == AppLifecycleState.resumed
        : [
            AppLifecycleState.inactive,
            AppLifecycleState.hidden,
            AppLifecycleState.paused,
          ].contains(state)) {
      return;
    }
    await Future<void>.delayed(const Duration(milliseconds: 25));
  }
  probe.check(false, probe.ProbeCheck.negativeClosed);
}

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  try {
    probe.check(
      kReleaseMode && Platform.isMacOS && disposablePilotEnabled,
      probe.ProbeCheck.releaseMac,
    );
    final scenario = Platform.environment['COMPANION_PILOT_CASE'];
    probe.check(
      Platform.environment['CI'] == 'true' &&
          ['foreground', 'inactive'].contains(scenario),
      probe.ProbeCheck.ciEnvironment,
    );
    await initializePackagedCore();
    runApp(
      const MaterialApp(
        home: Scaffold(body: Text('Disposable pilot channel CI fixture')),
      ),
    );
    await WidgetsBinding.instance.endOfFrame;
    stdout.writeln('COMPANION_PILOT_READY');
    await stdout.flush();
    // The external fixture establishes real AppKit focus before sending bytes.
    // No clipboard reads or credentials in arguments/environment/artifacts.
    final bytes = <int>[];
    await for (final chunk in stdin) {
      probe.check(
        bytes.length + chunk.length <= PilotBundle.maximumLength,
        probe.ProbeCheck.negativeClosed,
      );
      bytes.addAll(chunk);
    }
    final input = utf8.decode(bytes);
    bytes.fillRange(0, bytes.length, 0);
    await waitForFocus(scenario == 'foreground');
    final bundle = PilotBundle.parse(input);
    final native = NativeProviderPlatform();
    await probe.progress(probe.ProbePhase.configuration);
    final before = await native.configuration();
    if (scenario == 'inactive') {
      probe.check(before.configured, probe.ProbeCheck.configuredLoopback);
      var rejected = false;
      try {
        // Exercise the native admission guard directly, not Dart's lifecycle gate.
        await native.setupPilot(bundle);
      } on PlatformException catch (error) {
        rejected = error.code == 'provider_unavailable';
      }
      probe.check(rejected, probe.ProbeCheck.negativeClosed);
      final after = await native.configuration();
      probe.check(
        after.configured == before.configured &&
            after.endpoint == before.endpoint &&
            after.pin == before.pin &&
            after.fingerprint == before.fingerprint &&
            after.uncertainId == before.uncertainId,
        probe.ProbeCheck.settledNativeMarker,
      );
    } else {
      probe.check(!before.configured, probe.ProbeCheck.negativeClosed);
      final controller = ProviderController(native);
      final lifecycle = PilotLifecycle(controller);
      WidgetsBinding.instance.addObserver(lifecycle);
      try {
        await controller.initialize();
        await probe.progress(probe.ProbePhase.controller);
        await controller.setupPilot(input);
        probe.check(
          !controller.state.locked && controller.diagnostic.isEmpty,
          probe.ProbeCheck.sessionUnlocked,
        );
      } finally {
        WidgetsBinding.instance.removeObserver(lifecycle);
        controller.dispose();
      }
      // Read persisted metadata through a fresh platform object after setup.
      final saved = await NativeProviderPlatform().configuration();
      probe.check(
        saved.configured &&
            saved.endpoint == bundle.endpoint &&
            saved.pin == bundle.pin &&
            saved.fingerprint == bundle.fingerprint &&
            saved.uncertainId.isEmpty,
        probe.ProbeCheck.fingerprint,
      );
    }
    await probe.succeed();
  } catch (_) {
    stderr.writeln(
      'COMPANION_PROVIDER_TLS_FAILED:${probe.phase.name}:${probe.failedCheck.name}',
    );
    await stderr.flush();
    exit(1);
  }
}
