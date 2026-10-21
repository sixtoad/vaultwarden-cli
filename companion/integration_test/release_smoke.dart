// Standalone release entrypoint: flutter test forces debug mode. These runtime
// checks remain active in AOT builds and never create/reopen a key or prompt.
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'package:companion_slice/main.dart';
import 'package:companion_slice/platform/core_loader.dart';
import 'package:companion_slice/platform/signer.dart';
import 'package:companion_slice/src/rust/api.dart' as core;
import 'package:companion_slice/platform/provider.dart';
import 'package:companion_slice/provider/page.dart';

import 'provider_checks.dart';

class SmokeFailure implements Exception {
  const SmokeFailure(this.check);
  final String check;
}

void require(bool condition, String check) {
  if (!condition) throw SmokeFailure(check);
}

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  try {
    require(kReleaseMode, 'release mode required');
    await initializePackagedCore();
    checkProviderBridge(require);
    final providerPlatform = NativeProviderPlatform();
    if (!Platform.isMacOS) {
      require(!providerPlatform.available, 'unsupported provider transport');
    } else {
      await providerPlatform.configuration();
    }
    final platform = NativeApprovalPlatform();
    final availability = await platform.availability();
    if (!Platform.isMacOS) {
      require(
        availability == AuthenticationAvailability.unavailable,
        'unsupported authentication',
      );
    } else {
      const channel = MethodChannel('dev.vaultwarden.companionSlice/signer');
      final raw = await channel.invokeMethod<Object?>('availability');
      require(
        raw == 'touchID' || raw == 'unavailable',
        'native availability contract',
      );
      var rejected = false;
      try {
        await channel.invokeMethod<Object?>('perform', <String, Object>{});
      } on PlatformException catch (error) {
        rejected = error.code == 'invalid_request';
      }
      require(rejected, 'native closed request contract');
    }
    require(!core.snapshot().hasKey, 'no startup key access');
    var rejected = false;
    try {
      core.begin(operation: core.Operation.sign);
    } catch (_) {
      rejected = true;
    }
    require(rejected, 'unreviewed signing must fail');
    require(
      core.selectFixture(id: 2).fixture.id == 2,
      'Rust fixture selection',
    );
    core.selectFixture(id: 1);
    runApp(CompanionApp(platform: platform));
    // Observe actual rendered release widgets without flutter_test/assert.
    await WidgetsBinding.instance.endOfFrame;
    await Future<void>.delayed(const Duration(milliseconds: 300));
    WidgetsBinding.instance.scheduleFrame();
    await WidgetsBinding.instance.endOfFrame;
    final text = <String>{};
    void inspect(Element element) {
      final widget = element.widget;
      if (widget is Text && widget.data != null) text.add(widget.data!);
      element.visitChildElements(inspect);
    }

    final root = WidgetsBinding.instance.rootElement;
    require(root != null, 'release widget tree');
    inspect(root!);
    require(text.contains('Rust core connected'), 'release core indicator');
    require(
      text.contains('Synthetic request one'),
      'release fixture rendering',
    );
    require(
      text.contains(
        availability == AuthenticationAvailability.touchId
            ? 'Touch ID available'
            : 'Biometric signing unavailable on this device',
      ),
      'release availability rendering',
    );
    require(
      core.snapshot().verified == 0 && !core.snapshot().busy,
      'no startup approval or worker',
    );
    runApp(
      MaterialApp(
        home: ProviderPage(
          platform: providerPlatform,
          syntheticBuilder: (_) => CompanionReview(platform: platform),
        ),
      ),
    );
    await WidgetsBinding.instance.endOfFrame;
    await Future<void>.delayed(const Duration(milliseconds: 300));
    WidgetsBinding.instance.scheduleFrame();
    await WidgetsBinding.instance.endOfFrame;
    text.clear();
    inspect(WidgetsBinding.instance.rootElement!);
    require(
      text.contains('Companion · provider approvals'),
      'release provider screen',
    );
    if (!Platform.isMacOS) {
      require(
        text.contains(
          'Provider transport unavailable on this platform. Provider approvals require macOS.',
        ),
        'release unsupported provider screen',
      );
    }
    if (Platform.isWindows) {
      // A Windows GUI runner has no reliable redirected console. The smoke-only
      // entrypoint receives a task-owned result path; the normal app ignores it.
      final path = Platform.environment['COMPANION_RELEASE_RESULT'];
      require(path != null, 'Windows smoke result path');
      await File(path!)
          .writeAsString('COMPANION_RELEASE_SMOKE_OK\n', flush: true);
    } else {
      // Inherited stdout also works inside the macOS app sandbox; do not weaken
      // entitlements or write an arbitrary external marker from that app.
      stdout.writeln('COMPANION_RELEASE_SMOKE_OK');
      await stdout.flush();
    }
    exit(0);
  } catch (error) {
    final check = error is SmokeFailure
        ? error.check
        : 'initialization or runtime failure';
    final message = 'COMPANION_RELEASE_SMOKE_FAILED: $check\n';
    if (Platform.isWindows) {
      final path = Platform.environment['COMPANION_RELEASE_RESULT'];
      if (path != null) {
        try {
          await File(path).writeAsString(message, flush: true);
        } catch (_) {
          /* Exit still fails. */
        }
      }
    } else {
      stderr.write(message);
      await stderr.flush();
    }
    exit(1);
  }
}
