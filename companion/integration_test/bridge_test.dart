import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:companion_slice/main.dart';
import 'package:companion_slice/platform/signer.dart';
import 'package:companion_slice/platform/core_loader.dart';
import 'package:companion_slice/src/rust/api.dart' as core;
import 'package:companion_slice/platform/approval_client.dart';
import 'package:companion_slice/platform/approval_key.dart';
import 'package:companion_slice/platform/core_approval_key.dart';
import 'package:companion_slice/platform/core_provider.dart';
import 'package:companion_slice/platform/provider.dart';

import 'provider_checks.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  testWidgets(
    'packaged Rust bridge loads and unsupported adapter cannot approve',
    (tester) async {
      await initializePackagedCore();
      checkProviderBridge(
        (condition, check) => expect(condition, true, reason: check),
      );
      final providerPlatform = NativeProviderPlatform();
      if (!Platform.isMacOS) {
        expect(providerPlatform.available, false);
        await expectLater(
          providerPlatform.send(Uint8List(0)),
          throwsUnsupportedError,
        );
      } else {
        // Reads only this development app's configuration; no identity import.
        await providerPlatform.configuration();
      }
      if (Platform.isMacOS) {
        const channel = MethodChannel('dev.vaultwarden.companionSlice/signer');
        expect(
          await channel.invokeMethod<String>('availability'),
          anyOf('touchID', 'unavailable'),
        );
        await expectLater(
          channel.invokeMethod<void>('perform', <String, Object>{}),
          throwsA(
            isA<PlatformException>().having(
              (error) => error.code,
              'code',
              'invalid_request',
            ),
          ),
        );
      } else {
        expect(
          await NativeApprovalPlatform().availability(),
          AuthenticationAvailability.unavailable,
        );
      }
      final platform = NativeApprovalPlatform(macOS: false);
      await tester.pumpWidget(CompanionApp(platform: platform));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('core-connected')), findsOneWidget);
      expect(find.text('Synthetic request one'), findsOneWidget);
      await tester.tap(find.text('Review request 2'));
      await tester.pump();
      expect(core.snapshot().fixture.id, 2);
      expect(find.text('Synthetic request two'), findsOneWidget);
      final button = tester.widget<FilledButton>(
        find.widgetWithText(FilledButton, 'Sign with Touch ID'),
      );
      expect(button.onPressed, isNull);
      final work = core.begin(operation: core.Operation.reopen);
      final reply = await platform.perform(work);
      final state = core.finish(
        token: work.token,
        epoch: work.epoch,
        completion: reply,
      );
      expect(state.outcome, core.Outcome.unavailable);
      expect(state.verified, 0);
      expect(state.hasKey, false);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets(
    'Windows and Linux reach the Rust-core transport and key through the packaged bridge',
    (tester) async {
      await initializePackagedCore();
      final os = Platform.operatingSystem;
      final transport = CoreProviderPlatform();
      expect(transport.available, isCoreTransportSystem(os));
      if (!transport.available) return;
      // Reads only this user's (fresh CI) configuration; nothing is written.
      await transport.configuration();
      await expectLater(
        transport.setupFromFiles('http://x', 'a' * 64, '/n', '/n', ''),
        throwsA(anything),
      );
      final keys = CoreApprovalKeyPlatform();
      final verification = await keys.verification();
      if (os == 'linux') {
        expect(verification, UserVerification.unavailable);
      } else {
        expect(
          verification,
          anyOf(UserVerification.windowsHello, UserVerification.unavailable),
        );
      }
      // A malformed binding is refused before any authenticator call.
      final refused = await keys.read(const KeyBinding('x', 'y'));
      expect(
        refused.outcome,
        os == 'linux' ? KeyOutcome.unavailable : KeyOutcome.failed,
      );
    },
  );
}
