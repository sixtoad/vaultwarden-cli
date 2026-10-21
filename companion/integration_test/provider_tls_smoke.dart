// CI-only AOT entrypoint. The ordinary lib/main.dart has no fixture hooks.
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:companion_slice/platform/core_loader.dart';
import 'package:companion_slice/platform/provider.dart';
import 'package:companion_slice/src/rust/api/provider.dart' as core;

const id = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
void check(bool value) {
  if (!value) throw StateError('Packaged provider assertion');
}

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  try {
    check(kReleaseMode && Platform.isMacOS);
    final scenario = Platform.environment['COMPANION_PROVIDER_CASE'];
    check(scenario != null && Platform.environment['CI'] == 'true');
    await initializePackagedCore();
    runApp(
      const MaterialApp(
        home: Scaffold(body: Text('Packaged provider TLS fixture')),
      ),
    );
    final native = NativeProviderPlatform();
    final config = await native.configuration();
    check(config.configured && Uri.parse(config.endpoint).host == '127.0.0.1');
    check(
      config.fingerprint ==
          Platform.environment['COMPANION_EXPECT_CLIENT_SHA256'],
    );
    core.providerConfigure(uncertainId: config.uncertainId);

    Future<void> send(
      core.ProviderCommand command, {
      String requestId = '',
      String password = '',
    }) async {
      final work = core.providerBegin(
        command: command,
        requestId: requestId,
        password: password,
      );
      Uint8List reply;
      try {
        reply = await native.send(work.body);
      } catch (_) {
        reply = Uint8List(0);
      } finally {
        work.body.fillRange(0, work.body.length, 0);
      }
      core.providerFinish(token: work.token, response: reply);
    }

    if (scenario == 'recover' || scenario == 'recover-pending') {
      check(config.uncertainId == id);
      await send(core.ProviderCommand.status, requestId: id);
      if (scenario == 'recover-pending') {
        check(core.providerSnapshot().uncertainId == id);
        check((await native.configuration()).uncertainId == id);
      } else {
        check(core.providerSnapshot().uncertainId.isEmpty);
        check(core.providerSnapshot().statusText.contains('approved'));
        await native.settle(id);
        check((await native.configuration()).uncertainId.isEmpty);
      }
    } else {
      await send(core.ProviderCommand.session);
      if (scenario == 'negative') {
        check(
          core.providerSnapshot().locked && !core.providerSnapshot().canDecide,
        );
      } else {
        check(!core.providerSnapshot().locked);
        await send(core.ProviderCommand.review, requestId: id);
        check(core.providerSnapshot().canDecide);
        check(
          core.providerSnapshot().reviewText.contains(
            'Arguments (1 separate values)',
          ),
        );
        await send(
          scenario == 'deny'
              ? core.ProviderCommand.deny
              : core.ProviderCommand.approve,
          requestId: id,
          password: scenario == 'deny' ? '' : 'synthetic-only',
        );
        if (scenario == 'drop') {
          check(core.providerSnapshot().uncertainId == id);
          check((await native.configuration()).uncertainId == id);
          // Exit before status recovery: the next app process must restore it.
        } else {
          check(core.providerSnapshot().uncertainId.isEmpty);
          check(
            core.providerSnapshot().statusText.contains(
              scenario == 'wrong-password'
                  ? 'rejected'
                  : scenario == 'deny'
                  ? 'denied'
                  : 'approved',
            ),
          );
          await native.settle(id);
          check((await native.configuration()).uncertainId.isEmpty);
        }
      }
    }
    stdout.writeln('COMPANION_PROVIDER_TLS_OK');
    await stdout.flush();
    exit(0);
  } catch (_) {
    stderr.writeln('COMPANION_PROVIDER_TLS_FAILED');
    await stderr.flush();
    exit(1);
  }
}
