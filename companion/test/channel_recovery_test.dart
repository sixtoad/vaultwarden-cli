import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:companion_slice/main.dart';
import 'package:companion_slice/platform/signer.dart';
import 'package:companion_slice/src/rust/api.dart' as core;
import 'package:companion_slice/src/rust/frb_generated.dart';

void main() {
  testWidgets(
    'malformed completed replies release only their worker; disposal still finishes',
    (tester) async {
      await RustLib.init();
      tester.view.physicalSize = const Size(1000, 1400);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      const channel = MethodChannel('channel-recovery');
      var calls = 0;
      final delayed = Completer<Object?>();
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
            if (call.method == 'availability') return 'touchID';
            if (call.method == 'cancel') return null;
            calls++;
            return calls == 1 ? <Object?>[1, 'malformed'] : delayed.future;
          });
      await tester.pumpWidget(
        CompanionApp(
          platform: NativeApprovalPlatform(macOS: true, channel: channel),
        ),
      );
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.text('Create test key'));
      await tester.tap(find.text('Create test key'));
      await tester.pumpAndSettle();
      expect(core.snapshot().busy, false);
      expect(core.snapshot().outcome, core.Outcome.failed);
      await tester.tap(find.text('Reopen test key'));
      await tester.pump();
      expect(core.snapshot().busy, true);
      await tester.pumpWidget(const SizedBox.shrink());
      expect(core.snapshot().busy, true);
      delayed.complete('also malformed');
      await tester.pumpAndSettle();
      expect(core.snapshot().busy, false);
      expect(core.snapshot().verified, 0);
      expect(tester.takeException(), isNull);
      expect(calls, 2);
    },
  );
}
