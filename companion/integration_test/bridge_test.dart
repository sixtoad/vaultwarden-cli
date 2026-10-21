import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:companion_slice/main.dart';
import 'package:companion_slice/platform/signer.dart';
import 'package:companion_slice/platform/core_loader.dart';
import 'package:companion_slice/src/rust/api.dart' as core;

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  testWidgets(
    'packaged Rust bridge loads and unsupported adapter cannot approve',
    (tester) async {
      await initializePackagedCore();
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
}
