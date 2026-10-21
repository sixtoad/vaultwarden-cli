import 'dart:async';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:companion_slice/main.dart';
import 'package:companion_slice/platform/signer.dart';
import 'package:companion_slice/src/rust/api.dart' as core;
import 'package:companion_slice/src/rust/frb_generated.dart';

class ControlledPlatform implements ApprovalPlatform {
  final requests = <Completer<AuthenticationAvailability>>[];
  void Function(core.Invalidation)? callback;
  int removals = 0;
  @override
  Future<AuthenticationAvailability> availability() {
    final request = Completer<AuthenticationAvailability>();
    requests.add(request);
    return request.future;
  }

  @override
  Future<core.Completion> perform(core.Work work) async => core.Completion(
    outcome: core.Outcome.unavailable,
    publicKey: Uint8List(0),
    signature: Uint8List(0),
  );

  @override
  Future<void> cancel(int token) async {}
  @override
  void Function() onInvalidation(void Function(core.Invalidation) callback) {
    this.callback = callback;
    // Keep the captured callback available to simulate already queued events.
    return () {
      removals++;
    };
  }
}

void main() {
  setUpAll(() async => RustLib.init());

  testWidgets(
    'availability recovers on refresh and resume; newest response wins',
    (tester) async {
      final platform = ControlledPlatform();
      await tester.pumpWidget(CompanionApp(platform: platform));
      platform.requests[0].complete(AuthenticationAvailability.unavailable);
      await tester.pump();
      expect(
        find.text('Biometric signing unavailable on this device'),
        findsOneWidget,
      );
      await tester.tap(find.text('Refresh availability'));
      platform.requests[1].complete(AuthenticationAvailability.touchId);
      await tester.pump();
      expect(find.text('Touch ID available'), findsOneWidget);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
      expect(platform.requests.length, 3);
      platform.requests[2].complete(AuthenticationAvailability.unavailable);
      await tester.pump();
      await tester.tap(find.text('Refresh availability'));
      await tester.tap(find.text('Refresh availability'));
      platform.requests[4].complete(AuthenticationAvailability.touchId);
      await tester.pump();
      platform.requests[3].complete(AuthenticationAvailability.unavailable);
      await tester.pump();
      expect(find.text('Touch ID available'), findsOneWidget);
      await tester.tap(find.text('Refresh availability'));
      await tester.pumpWidget(const SizedBox.shrink());
      platform.requests[5].complete(AuthenticationAvailability.touchId);
      await tester.pump();
      expect(tester.takeException(), isNull);
      expect(platform.removals, 1);
    },
  );

  testWidgets(
    'replaced and disposed listeners cannot invalidate the live core',
    (tester) async {
      final old = ControlledPlatform();
      final current = ControlledPlatform();
      await tester.pumpWidget(CompanionApp(platform: old));
      final stale = old.callback!;
      await tester.pumpWidget(CompanionApp(platform: current));
      expect(old.removals, 1);
      current.requests.single.complete(AuthenticationAvailability.unavailable);
      await tester.pump();
      old.requests.single.complete(AuthenticationAvailability.touchId);
      await tester.pump();
      expect(
        find.text('Biometric signing unavailable on this device'),
        findsOneWidget,
      );
      core.selectFixture(id: 2);
      stale(core.Invalidation.sleep);
      expect(core.snapshot().outcome, core.Outcome.ready);
      final disposed = current.callback!;
      await tester.pumpWidget(const SizedBox.shrink());
      final live = ControlledPlatform();
      await tester.pumpWidget(CompanionApp(platform: live));
      live.requests.single.complete(AuthenticationAvailability.unavailable);
      await tester.pump();
      core.selectFixture(id: 1);
      disposed(core.Invalidation.close);
      stale(core.Invalidation.sleep);
      expect(core.snapshot().outcome, core.Outcome.ready);
      live.callback!(core.Invalidation.sleep);
      expect(core.snapshot().outcome, core.Outcome.cancelled);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );
}
