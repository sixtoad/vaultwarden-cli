import 'dart:async';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:companion_slice/main.dart';
import 'package:companion_slice/platform/signer.dart';
import 'package:companion_slice/src/rust/api.dart' as core;
import 'package:companion_slice/src/rust/frb_generated.dart';

class DelayedPlatform implements ApprovalPlatform {
  Completer<core.Completion>? pending;
  int cancels = 0;
  @override
  Future<AuthenticationAvailability> availability() async =>
      AuthenticationAvailability.touchId;
  @override
  Future<core.Completion> perform(core.Work work) {
    pending = Completer<core.Completion>();
    return pending!.future;
  }

  @override
  Future<void> cancel(int token) async {
    cancels++;
  }

  @override
  void onInvalidation(void Function(core.Invalidation) callback) {}
}

void main() {
  testWidgets(
    'selection cancels pending native work without reopening admission',
    (tester) async {
      await RustLib.init();
      tester.view.physicalSize = const Size(1000, 1200);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final platform = DelayedPlatform();
      await tester.pumpWidget(CompanionApp(platform: platform));
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.text('Create test key'));
      await tester.tap(find.text('Create test key'));
      await tester.pump();
      // Public SEC1 base point only; this mock is never hardware evidence.
      const hex =
          '046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'
          '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5';
      final publicKey = Uint8List.fromList([
        for (var i = 0; i < hex.length; i += 2)
          int.parse(hex.substring(i, i + 2), radix: 16),
      ]);
      platform.pending!.complete(
        core.Completion(
          outcome: core.Outcome.created,
          publicKey: publicKey,
          signature: Uint8List(0),
        ),
      );
      await tester.pumpAndSettle();
      expect(core.snapshot().hasKey, true);
      await tester.ensureVisible(find.text('Review request 1'));
      await tester.tap(find.text('Review request 1'));
      await tester.pump();
      await tester.tap(find.text('Sign with Touch ID'));
      await tester.pump();
      expect(core.snapshot().busy, true);
      await tester.tap(find.text('Review request 2'));
      await tester.pump();
      expect(platform.cancels, 1);
      expect(core.snapshot().busy, true);
      expect(
        tester
            .widget<FilledButton>(
              find.widgetWithText(FilledButton, 'Sign with Touch ID'),
            )
            .onPressed,
        isNull,
      );
      platform.pending!.complete(
        core.Completion(
          outcome: core.Outcome.verified,
          publicKey: Uint8List(0),
          signature: Uint8List.fromList([1]),
        ),
      );
      await tester.pumpAndSettle();
      expect(core.snapshot().busy, false);
      expect(core.snapshot().outcome, core.Outcome.cancelled);
      expect(core.snapshot().verified, 0);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );
}
