// CI-only AOT entrypoint. The ordinary lib/main.dart has no fixture hooks.
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:companion_slice/platform/core_loader.dart';
import 'package:companion_slice/platform/provider.dart';
import 'package:companion_slice/provider/controller.dart';
import 'package:companion_slice/src/rust/api/provider.dart' as core;
import 'package:companion_slice/src/rust/api/management.dart' as management;

const id = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

// Closed diagnostic vocabulary: never print exceptions, configuration or bodies.
enum ProbePhase {
  startup,
  initializeCore,
  configuration,
  configurationNative,
  configurationDecode,
  configurationUnreadable,
  configurationInvalid,
  configurationIdentity,
  configureCore,
  begin,
  nativeSend,
  finish,
  settle,
  shutdown,
  controller,
  foreground,
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
  inbox,
  terminalStatus,
  foregroundWindow,
  managementInventory,
  managementDetail,
  managementPrepared,
  managementOutcome,
  history,
}

var phase = ProbePhase.startup;
var failedCheck = ProbeCheck.none;
Future<void> progress(ProbePhase next, {bool complete = false}) async {
  phase = next;
  stderr.writeln(
    'COMPANION_PROVIDER_TLS_PROGRESS:${next.name}:${complete ? 'complete' : 'enter'}',
  );
  // Flush before crossing the boundary so a killed process retains its last
  // reached operation. Only enum labels, never configuration or error contents.
  await stderr.flush();
}

void check(bool value, ProbeCheck label) {
  if (!value) failedCheck = label;
  if (!value) throw StateError('Packaged provider assertion');
}

Future<void> succeed() async {
  await progress(ProbePhase.shutdown);
  stdout.writeln('COMPANION_PROVIDER_TLS_OK');
  await stdout.flush();
  await progress(ProbePhase.shutdown, complete: true);
  exit(0);
}

Future<void> main() async {
  await progress(ProbePhase.startup);
  WidgetsFlutterBinding.ensureInitialized();
  await progress(ProbePhase.startup, complete: true);
  try {
    check(kReleaseMode && Platform.isMacOS, ProbeCheck.releaseMac);
    final scenario = Platform.environment['COMPANION_PROVIDER_CASE'];
    check(
      scenario != null && Platform.environment['CI'] == 'true',
      ProbeCheck.ciEnvironment,
    );
    await progress(ProbePhase.initializeCore);
    await initializePackagedCore();
    await progress(ProbePhase.initializeCore, complete: true);
    runApp(
      const MaterialApp(
        home: Scaffold(body: Text('Packaged provider TLS fixture')),
      ),
    );
    final native = NativeProviderPlatform();
    Future<ProviderConfiguration> configuration() async {
      await progress(ProbePhase.configuration);
      try {
        final value = await native.configuration();
        await progress(ProbePhase.configuration, complete: true);
        return value;
      } on PlatformException catch (error) {
        phase = switch (error.code) {
          'provider_configuration_unreadable' =>
            ProbePhase.configurationUnreadable,
          'provider_configuration_invalid' => ProbePhase.configurationInvalid,
          'provider_identity_unavailable' => ProbePhase.configurationIdentity,
          _ => ProbePhase.configurationNative,
        };
        rethrow;
      } on MissingPluginException {
        phase = ProbePhase.configurationNative;
        rethrow;
      } on FormatException {
        phase = ProbePhase.configurationDecode;
        rethrow;
      }
    }

    Future<void> settle() async {
      await progress(ProbePhase.settle);
      await native.settle(id);
      await progress(ProbePhase.settle, complete: true);
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
    if (scenario!.startsWith('management-')) {
      // Real UI lifecycle only: the external CI harness activates this existing
      // app. Native prepare/revoke still require its actual MainFlutterWindow.
      await progress(ProbePhase.foreground);
      await WidgetsBinding.instance.endOfFrame;
      stdout.writeln('COMPANION_PROVIDER_TLS_FOREGROUND_READY');
      await stdout.flush();
      final deadline = DateTime.now().add(const Duration(seconds: 15));
      while (WidgetsBinding.instance.lifecycleState !=
              AppLifecycleState.resumed &&
          DateTime.now().isBefore(deadline)) {
        await Future<void>.delayed(const Duration(milliseconds: 50));
      }
      check(
        WidgetsBinding.instance.lifecycleState == AppLifecycleState.resumed,
        ProbeCheck.foregroundWindow,
      );
      await progress(ProbePhase.foreground, complete: true);
      management.managementConfigure(recovery: config.managementRecovery);
      final self = scenario == 'management-self-revoke';
      final targetKind = self
          ? management.IdentityKind.approvalClient
          : management.IdentityKind.requesterAgent;
      final targetId = self ? config.fingerprint : id;
      Future<void> manage(management.ManagementCommand command) async {
        await progress(ProbePhase.begin);
        final work = management.managementBegin(
          command: command,
          kind: targetKind,
          id: targetId,
          password: command == management.ManagementCommand.revoke
              ? 'synthetic-management-only'
              : '',
        );
        await progress(ProbePhase.begin, complete: true);
        Uint8List reply;
        try {
          await progress(ProbePhase.nativeSend);
          reply = await native.send(work.body);
        } catch (_) {
          stderr.writeln(
            'COMPANION_PROVIDER_TLS_NATIVE_REJECTED:identity_${command.name}',
          );
          reply = Uint8List(0);
        } finally {
          work.body.fillRange(0, work.body.length, 0);
        }
        await progress(ProbePhase.nativeSend, complete: true);
        await progress(ProbePhase.finish);
        management.managementFinish(token: work.token, response: reply);
        await progress(ProbePhase.finish, complete: true);
      }

      final recovering = scenario.startsWith('management-recover');
      if (recovering) {
        check(config.managementRecovery.isNotEmpty, ProbeCheck.recoveryMarker);
        check(
          management.managementSnapshot().recovery.isNotEmpty &&
              !management.managementSnapshot().canRevoke,
          ProbeCheck.pendingCoreMarker,
        );
        await manage(management.ManagementCommand.status);
      } else {
        check(
          config.managementRecovery.isEmpty,
          ProbeCheck.settledNativeMarker,
        );
        await manage(management.ManagementCommand.list);
        final inventory = management.managementSnapshot();
        check(
          inventory.outcome == management.ManagementOutcome.accepted &&
              inventory.identities.length == 2 &&
              inventory.identities.first.thisClient &&
              inventory.identities.first.id == config.fingerprint &&
              inventory.identities.first.roles.contains(
                management.IdentityRole.admin,
              ) &&
              inventory.identities.last.kind ==
                  management.IdentityKind.requesterAgent &&
              inventory.identities.last.id == id &&
              inventory.providerFingerprint == 'e' * 64 &&
              inventory.executionConfigured &&
              inventory.executionAvailable,
          ProbeCheck.managementInventory,
        );
        await manage(management.ManagementCommand.detail);
        check(
          management.managementSnapshot().detail?.id == targetId &&
              management.managementSnapshot().detail?.kind == targetKind &&
              !management.managementSnapshot().canRevoke,
          ProbeCheck.managementDetail,
        );
        await manage(management.ManagementCommand.prepare);
        check(
          management.managementSnapshot().canRevoke,
          ProbeCheck.managementPrepared,
        );
        await manage(management.ManagementCommand.revoke);
      }
      final result = management.managementSnapshot();
      if (scenario == 'management-drop' ||
          scenario == 'management-recover-pending') {
        check(
          result.recovery.isNotEmpty && !result.canRevoke,
          ProbeCheck.pendingCoreMarker,
        );
        check(
          (await configuration()).managementRecovery.isNotEmpty,
          ProbeCheck.pendingNativeMarker,
        );
        if (recovering) {
          check(
            result.revocation == 'pending' && result.cleanup == 'unknown',
            ProbeCheck.managementOutcome,
          );
        }
        // Exit without settling: a new AOT process must read the durable marker
        // and send only the exact action status, never prepare/revoke again.
      } else {
        check(
          result.recovery.isEmpty && !result.canRevoke,
          ProbeCheck.terminalCoreMarker,
        );
        check(
          result.outcome == management.ManagementOutcome.accepted &&
              result.revocation == 'recorded' &&
              result.cleanup == 'complete',
          ProbeCheck.managementOutcome,
        );
        await progress(ProbePhase.settle);
        await native.settle(result.actionId);
        await progress(ProbePhase.settle, complete: true);
        check(
          (await configuration()).managementRecovery.isEmpty,
          ProbeCheck.settledNativeMarker,
        );
      }
      await succeed();
      return;
    }
    if (scenario.startsWith('controller-')) {
      await progress(ProbePhase.controller);
      final controller = ProviderController(native);
      try {
        await controller.initialize();
        check(
          controller.configuration.configured,
          ProbeCheck.configuredLoopback,
        );
        if (scenario.startsWith('controller-history')) {
          controller.setActivityCurrent(true);
          await controller.refresh();
          if (scenario == 'controller-history') {
            check(
              controller.state.historyState ==
                      core.ProviderHistoryState.available &&
                  controller.state.history.length == 2 &&
                  controller.state.history.first.requestId == id &&
                  controller.state.history.first.outcome ==
                      core.ProviderHistoryOutcome.succeeded &&
                  controller.state.history.last.atUnixSeconds == null &&
                  controller.state.history.last.requestId == 'B' * 43 &&
                  controller.state.statusId.isEmpty &&
                  controller.state.uncertainId.isEmpty &&
                  !controller.state.canDecide,
              ProbeCheck.history,
            );
            controller.setActivityCurrent(false);
            await controller.review(controller.state.history.first.requestId);
            check(
              controller.state.reviewId == id && controller.state.canDecide,
              ProbeCheck.reviewDecidable,
            );
          } else {
            check(
              controller.state.historyState ==
                      core.ProviderHistoryState.unavailable &&
                  controller.state.history.isEmpty &&
                  !controller.state.canDecide,
              ProbeCheck.history,
            );
          }
          check(
            (await configuration()).uncertainId.isEmpty,
            ProbeCheck.settledNativeMarker,
          );
        } else if (scenario == 'controller-unlock') {
          check(controller.state.locked, ProbeCheck.negativeClosed);
          await controller.unlock('synthetic-only');
          check(!controller.state.locked, ProbeCheck.sessionUnlocked);
          check(
            controller.state.requests.length == 1 &&
                controller.state.requests.single == id,
            ProbeCheck.inbox,
          );
          await controller.review(id);
          check(controller.state.canDecide, ProbeCheck.reviewDecidable);
          await controller.decide(true, 'synthetic-only');
          check(
            controller.state.statusProgress ==
                core.ProviderStatusProgress.committed,
            ProbeCheck.approvedStatus,
          );
          await controller.refresh();
          check(
            controller.state.statusProgress ==
                core.ProviderStatusProgress.committed,
            ProbeCheck.approvedStatus,
          );
          await controller.refresh();
          check(
            controller.state.statusProgress ==
                    core.ProviderStatusProgress.terminal &&
                controller.state.statusId == id,
            ProbeCheck.terminalStatus,
          );
        } else {
          check(config.uncertainId == id, ProbeCheck.recoveryMarker);
          if (scenario == 'controller-recover-pending') {
            check(controller.recoveryId == id, ProbeCheck.pendingCoreMarker);
            check(
              (await configuration()).uncertainId == id,
              ProbeCheck.pendingNativeMarker,
            );
          } else {
            check(controller.recoveryId.isEmpty, ProbeCheck.terminalCoreMarker);
            check(
              controller.state.statusProgress ==
                  core.ProviderStatusProgress.committed,
              ProbeCheck.approvedStatus,
            );
            check(
              (await configuration()).uncertainId.isEmpty,
              ProbeCheck.settledNativeMarker,
            );
          }
        }
      } finally {
        controller.dispose();
      }
      await progress(ProbePhase.controller, complete: true);
      await succeed();
      return;
    }
    await progress(ProbePhase.configureCore);
    core.providerConfigure(uncertainId: config.uncertainId);
    await progress(ProbePhase.configureCore, complete: true);

    Future<void> send(
      core.ProviderCommand command, {
      String requestId = '',
      String password = '',
    }) async {
      await progress(ProbePhase.begin);
      final work = core.providerBegin(
        command: command,
        requestId: requestId,
        password: password,
      );
      await progress(ProbePhase.begin, complete: true);
      Uint8List reply;
      try {
        await progress(ProbePhase.nativeSend);
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
      await progress(ProbePhase.nativeSend, complete: true);
      await progress(ProbePhase.finish);
      core.providerFinish(token: work.token, response: reply);
      await progress(ProbePhase.finish, complete: true);
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
              ) &&
              core.providerSnapshot().review?.arguments.length == 1 &&
              core.providerSnapshot().review?.id == '"$id"',
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
    await succeed();
  } catch (_) {
    stderr.writeln(
      'COMPANION_PROVIDER_TLS_FAILED:${phase.name}:${failedCheck.name}',
    );
    await stderr.flush();
    exit(1);
  }
}
