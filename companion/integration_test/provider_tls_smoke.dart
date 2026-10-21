// CI-only AOT entrypoint. The ordinary lib/main.dart has no fixture hooks.
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:companion_slice/platform/core_loader.dart';
import 'package:companion_slice/platform/provider.dart';
import 'package:companion_slice/src/rust/api/provider.dart' as core;

const id = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

// Closed diagnostic vocabulary: never print exceptions, configuration or bodies.
enum ProbePhase {
  startup,
  initializeCore,
  configuration,
  configureCore,
  begin,
  nativeSend,
  finish,
  settle,
}

enum ProbeCheck {
  none,
  releaseMac,
  ciEnvironment,
  configuredLoopback,
  fingerprint,
  recoveryMarker,
  pendingCoreMarker,
  pendingNativeMarker,
  terminalCoreMarker,
  approvedStatus,
  settledNativeMarker,
  negativeClosed,
  sessionUnlocked,
  reviewDecidable,
  completeArguments,
  decisionStatus,
}

var phase = ProbePhase.startup;
var failedCheck = ProbeCheck.none;
void check(bool value, ProbeCheck label) {
  if (!value) failedCheck = label;
  if (!value) throw StateError('Packaged provider assertion');
}

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  try {
    check(kReleaseMode && Platform.isMacOS, ProbeCheck.releaseMac);
    final scenario = Platform.environment['COMPANION_PROVIDER_CASE'];
    check(
      scenario != null && Platform.environment['CI'] == 'true',
      ProbeCheck.ciEnvironment,
    );
    phase = ProbePhase.initializeCore;
    await initializePackagedCore();
    runApp(
      const MaterialApp(
        home: Scaffold(body: Text('Packaged provider TLS fixture')),
      ),
    );
    final native = NativeProviderPlatform();
    Future<ProviderConfiguration> configuration() async {
      phase = ProbePhase.configuration;
      return native.configuration();
    }

    Future<void> settle() async {
      phase = ProbePhase.settle;
      await native.settle(id);
    }

    final config = await configuration();
    check(
      config.configured && Uri.parse(config.endpoint).host == '127.0.0.1',
      ProbeCheck.configuredLoopback,
    );
    check(
      config.fingerprint ==
          Platform.environment['COMPANION_EXPECT_CLIENT_SHA256'],
      ProbeCheck.fingerprint,
    );
    phase = ProbePhase.configureCore;
    core.providerConfigure(uncertainId: config.uncertainId);

    Future<void> send(
      core.ProviderCommand command, {
      String requestId = '',
      String password = '',
    }) async {
      phase = ProbePhase.begin;
      final work = core.providerBegin(
        command: command,
        requestId: requestId,
        password: password,
      );
      Uint8List reply;
      try {
        phase = ProbePhase.nativeSend;
        reply = await native.send(work.body);
      } catch (_) {
        // Enum name only, never the error or request body.
        stderr.writeln(
          'COMPANION_PROVIDER_TLS_NATIVE_REJECTED:${command.name}',
        );
        reply = Uint8List(0);
      } finally {
        work.body.fillRange(0, work.body.length, 0);
      }
      phase = ProbePhase.finish;
      core.providerFinish(token: work.token, response: reply);
    }

    if (scenario == 'recover' || scenario == 'recover-pending') {
      check(config.uncertainId == id, ProbeCheck.recoveryMarker);
      await send(core.ProviderCommand.status, requestId: id);
      if (scenario == 'recover-pending') {
        check(
          core.providerSnapshot().uncertainId == id,
          ProbeCheck.pendingCoreMarker,
        );
        check(
          (await configuration()).uncertainId == id,
          ProbeCheck.pendingNativeMarker,
        );
      } else {
        check(
          core.providerSnapshot().uncertainId.isEmpty,
          ProbeCheck.terminalCoreMarker,
        );
        check(
          core.providerSnapshot().statusText.contains('approved'),
          ProbeCheck.approvedStatus,
        );
        await settle();
        check(
          (await configuration()).uncertainId.isEmpty,
          ProbeCheck.settledNativeMarker,
        );
      }
    } else {
      await send(core.ProviderCommand.session);
      if (scenario == 'negative') {
        check(
          core.providerSnapshot().locked && !core.providerSnapshot().canDecide,
          ProbeCheck.negativeClosed,
        );
      } else {
        check(!core.providerSnapshot().locked, ProbeCheck.sessionUnlocked);
        await send(core.ProviderCommand.review, requestId: id);
        check(core.providerSnapshot().canDecide, ProbeCheck.reviewDecidable);
        check(
          core.providerSnapshot().reviewText.contains(
            'Arguments (1 separate values)',
          ),
          ProbeCheck.completeArguments,
        );
        await send(
          scenario == 'deny'
              ? core.ProviderCommand.deny
              : core.ProviderCommand.approve,
          requestId: id,
          password: scenario == 'deny' ? '' : 'synthetic-only',
        );
        if (scenario == 'drop') {
          check(
            core.providerSnapshot().uncertainId == id,
            ProbeCheck.pendingCoreMarker,
          );
          check(
            (await configuration()).uncertainId == id,
            ProbeCheck.pendingNativeMarker,
          );
          // Exit before status recovery: the next app process must restore it.
        } else {
          check(
            core.providerSnapshot().uncertainId.isEmpty,
            ProbeCheck.terminalCoreMarker,
          );
          check(
            core.providerSnapshot().statusText.contains(
              scenario == 'wrong-password'
                  ? 'rejected'
                  : scenario == 'deny'
                  ? 'denied'
                  : 'approved',
            ),
            ProbeCheck.decisionStatus,
          );
          await settle();
          check(
            (await configuration()).uncertainId.isEmpty,
            ProbeCheck.settledNativeMarker,
          );
        }
      }
    }
    stdout.writeln('COMPANION_PROVIDER_TLS_OK');
    await stdout.flush();
    await stderr.flush();
    exit(0);
  } catch (_) {
    stderr.writeln(
      'COMPANION_PROVIDER_TLS_FAILED:${phase.name}:${failedCheck.name}',
    );
    await stderr.flush();
    exit(1);
  }
}
