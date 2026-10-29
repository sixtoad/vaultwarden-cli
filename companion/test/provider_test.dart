import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:companion_slice/platform/provider.dart';
import 'package:companion_slice/provider/controller.dart';
import 'package:companion_slice/provider/page.dart';
import 'package:companion_slice/src/rust/api/provider.dart' as core;
import 'package:companion_slice/src/rust/frb_generated.dart';

import 'provider_support.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async => RustLib.init());
  setUp(resetProvider);

  test(
    'generated history bridge preserves events and never supplies authority',
    () async {
      final native = FixtureProviderPlatform()
        ..historyReply = encoded(providerHistory());
      final controller = ProviderController(native);
      await controller.initialize();
      expect(native.commands.where((c) => c['command'] == 'history'), isEmpty);
      controller.setActivityCurrent(true);
      await controller.refresh();
      expect(
        controller.state.historyState,
        core.ProviderHistoryState.available,
      );
      expect(controller.state.history.single.requestId, providerId);
      expect(
        controller.state.history.single.outcome,
        core.ProviderHistoryOutcome.succeeded,
      );
      expect(
        controller.state.history.single.atUnixSeconds,
        BigInt.from(1700000000),
      );
      expect(controller.state.canDecide, false);
      expect(controller.state.statusId, isEmpty);
      expect(native.settlementAttempts, isEmpty);
      expect(native.commands.last, {
        'version': 1,
        'command': 'history',
        'limit': 50,
      });
      await controller.perform(
        core.ProviderCommand.approve,
        password: 'synthetic',
      );
      expect(native.commands.where((c) => c['command'] == 'decision'), isEmpty);
      controller.dispose();
    },
  );

  test('history clears on navigation, suspension, failed metadata and provider change', () async {
    for (final transition in [
      'navigation',
      'suspend',
      'metadata',
      'provider',
      'route',
    ]) {
      final native = FixtureProviderPlatform();
      final controller = ProviderController(native);
      await controller.initialize();
      controller.setActivityCurrent(true);
      await controller.refresh();
      expect(controller.state.history, isNotEmpty);
      if (transition == 'navigation') {
        controller.setActivityCurrent(false);
        controller.invalidate();
      } else if (transition == 'route') {
        controller.setRouteCurrent(false);
      } else {
        controller.suspend();
      }
      expect(controller.state.history, isEmpty);
      if (transition == 'metadata') {
        native.failConfiguration = true;
        controller.resume();
        await Future<void>.delayed(Duration.zero);
        expect(controller.connected, false);
        expect(controller.state.history, isEmpty);
      }
      if (transition == 'provider') {
        native.saved = ProviderConfiguration(
          configured: true,
          endpoint: 'https://new.example',
          pin: 'c' * 64,
          fingerprint: 'd' * 64,
        );
        native.historyReply = encoded({
          'version': 1,
          'history_version': 1,
          'events': [],
        });
        controller.resume();
        await Future<void>.delayed(Duration.zero);
        expect(controller.configuration.endpoint, 'https://new.example');
        expect(controller.state.history, isEmpty);
      }
      controller.dispose();
    }
  });

  test('late history after lifecycle retirement cannot restore display or authority', () async {
    for (final transition in ['navigation', 'background', 'route', 'dispose']) {
      final native = FixtureProviderPlatform()
        ..heldHistory = Completer<Uint8List>();
      final controller = ProviderController(native);
      await controller.initialize();
      final read = controller.perform(core.ProviderCommand.history);
      expect(controller.state.historyState, core.ProviderHistoryState.loading);
      switch (transition) {
        case 'navigation':
          controller.invalidate();
        case 'background':
          controller.suspend();
        case 'route':
          controller.setRouteCurrent(false);
        case 'dispose':
          controller.dispose();
      }
      native.heldHistory!.complete(encoded(providerHistory()));
      expect(await read, false);
      expect(controller.state.history, isEmpty);
      expect(controller.state.canDecide, false);
      expect(controller.state.outcome, core.ProviderOutcome.stale);
      if (transition != 'dispose') controller.dispose();
    }
  });

  test('old malformed and sensitive history responses are unavailable without permissive parsing', () async {
    final sensitive = providerHistory();
    (sensitive['events'] as List).first['password'] = 'synthetic-forbidden';
    for (final response in [
      encoded({'version': 1, 'error': 'invalid_request'}),
      encoded({'version': 1, 'history_version': 9, 'events': []}),
      encoded(sensitive),
      Uint8List(1048577),
    ]) {
      final native = FixtureProviderPlatform()..historyReply = response;
      final controller = ProviderController(native);
      await controller.initialize();
      controller.setActivityCurrent(true);
      await controller.refresh();
      expect(
        controller.state.historyState,
        core.ProviderHistoryState.unavailable,
      );
      expect(controller.state.history, isEmpty);
      expect(controller.state.canDecide, false);
      expect(native.settlementAttempts, isEmpty);
      controller.dispose();
    }
  });

  test(
    'completed history cannot settle or bypass uncertain decision recovery',
    () async {
      final native = FixtureProviderPlatform()..loseDecision = true;
      native.historyReply = encoded(providerHistory(outcome: 'succeeded'));
      final controller = ProviderController(native);
      await controller.initialize();
      await controller.review(providerId);
      await controller.decide(true, 'synthetic');
      final count = native.commands.length;
      controller.setActivityCurrent(true);
      expect(await controller.perform(core.ProviderCommand.history), false);
      await controller.refresh();
      expect(controller.recoveryId, providerId);
      expect(native.saved.uncertainId, providerId);
      expect(native.settlementAttempts, isEmpty);
      expect(
        native.commands
            .skip(count)
            .every(
              (c) => c['command'] == 'status' && c['request_id'] == providerId,
            ),
        true,
      );
      expect(
        native.commands.where((c) => c['command'] == 'decision'),
        hasLength(1),
      );
      expect(controller.state.history, isEmpty);
      controller.dispose();
    },
  );

  test('activity follows committed execution after durable recovery under fresh authority', () async {
    final native = FixtureProviderPlatform();
    final controller = ProviderController(native);
    await controller.initialize();
    await controller.review(providerId);
    await controller.decide(true, 'synthetic');
    expect(controller.recoveryId, isEmpty);
    expect(native.settled, [providerId]);
    expect(
      controller.state.statusProgress,
      core.ProviderStatusProgress.committed,
    );
    controller.setActivityCurrent(true);
    final count = native.commands.length;
    await controller.refresh();
    expect(native.commands.skip(count).map((c) => c['command']), [
      'status',
      'session',
      'history',
    ]);
    expect(controller.state.history, isNotEmpty);
    expect(controller.state.statusId, providerId);
    expect(
      controller.state.statusProgress,
      core.ProviderStatusProgress.committed,
    );
    final next = native.commands.length;
    await controller.refresh();
    expect(native.commands[next]['command'], 'status');
    expect(native.settlementAttempts, [providerId]);
    expect(
      native.commands.where((c) => c['command'] == 'decision'),
      hasLength(1),
    );
    controller.dispose();
  });

  test('clear-then-throw settlement recovers only after same-provider empty metadata', () async {
    final native = FixtureProviderPlatform()..clearThenFailSettlement = true;
    final controller = ProviderController(native);
    await controller.initialize();
    await controller.review(providerId);
    await controller.perform(core.ProviderCommand.deny);
    expect(native.saved.uncertainId, isEmpty);
    expect(controller.state.uncertainId, isEmpty);
    expect(controller.recoveryId, providerId);
    expect(controller.canSetup, false);
    final count = native.commands.length;
    native.failConfiguration = true;
    await controller.refresh();
    expect(controller.recoveryId, providerId);
    expect(controller.canSetup, false);
    expect(native.commands.length, count);
    native.failConfiguration = false;
    native.heldConfiguration = Completer<ProviderConfiguration>();
    final recovery = controller.refresh();
    expect(controller.busy, true);
    await controller.review(providerId);
    await controller.unlock('never-send');
    await controller.setup(
      'https://replacement.example',
      'c' * 64,
      'never-import',
    );
    expect(native.commands.length, count);
    expect(controller.canSetup, false);
    // The attempted review invalidated this read; it cannot clear recovery.
    native.heldConfiguration!.complete(native.saved);
    await recovery;
    expect(controller.recoveryId, providerId);
    native.heldConfiguration = null;
    await controller.refresh();
    expect(controller.recoveryId, isEmpty);
    expect(controller.canSetup, true);
    expect(controller.diagnostic, isEmpty);
    expect(native.settlementAttempts, [providerId]);
    expect(
      native.commands.where((c) => c['command'] == 'decision'),
      hasLength(1),
    );
    expect(native.commands.where((c) => c['command'] == 'unlock'), isEmpty);
    controller.dispose();
  });

  test(
    'empty native metadata never resolves Rust decision uncertainty',
    () async {
      final native = FixtureProviderPlatform()..loseDecision = true;
      final controller = ProviderController(native);
      await controller.initialize();
      await controller.review(providerId);
      await controller.decide(true, 'synthetic');
      native.savePending('');
      controller.suspend();
      controller.resume();
      await Future<void>.delayed(Duration.zero);
      expect(controller.state.uncertainId, providerId);
      expect(controller.recoveryId, providerId);
      expect(controller.canSetup, false);
      expect(native.settlementAttempts, isEmpty);
      expect(native.commands.last['command'], 'status');
      expect(native.commands.last['request_id'], providerId);
      controller.dispose();
    },
  );

  test(
    'stale session cannot follow with list or retain unlocked authority',
    () async {
      final native = FixtureProviderPlatform();
      final controller = ProviderController(native);
      await controller.initialize();
      native.heldSession = Completer<Uint8List>();
      final count = native.commands.length;
      final refresh = controller.refresh();
      controller.invalidate();
      native.heldSession!.complete(
        encoded({'version': 1, 'state': 'unlocked', 'generation': 1}),
      );
      await refresh;
      expect(native.commands.length, count + 1);
      expect(controller.state.outcome, core.ProviderOutcome.stale);
      expect(controller.state.locked, true);
      expect(controller.state.requests, isEmpty);
      expect(controller.refreshDelaySeconds, 10);
      controller.dispose();
    },
  );

  test('failed settlement cannot switch its original provider during metadata reload', () async {
    final native = FixtureProviderPlatform()..failSettlement = true;
    final controller = ProviderController(native);
    await controller.initialize();
    await controller.review(providerId);
    await controller.decide(false, '');
    expect(controller.recoveryId, providerId);
    final original = native.saved;
    final count = native.commands.length;
    native.saved = ProviderConfiguration(
      configured: true,
      endpoint: 'https://other.example',
      pin: 'c' * 64,
      fingerprint: 'd' * 64,
    );
    controller.suspend();
    controller.resume();
    await Future<void>.delayed(Duration.zero);
    await controller.refresh();
    expect(native.commands.length, count);
    expect(controller.recoveryId, providerId);
    expect(controller.canSetup, false);
    native.saved = original;
    native.failSettlement = false;
    await controller.refresh();
    expect(native.commands.last['command'], 'status');
    expect(native.commands.last['request_id'], providerId);
    expect(controller.recoveryId, isEmpty);
    controller.dispose();
  });

  test('saved original ID relaunch stays status-only through pending and terminal settlement', () async {
    final native = FixtureProviderPlatform();
    native.saved = ProviderConfiguration(
      configured: true,
      endpoint: native.saved.endpoint,
      pin: native.saved.pin,
      fingerprint: native.saved.fingerprint,
      uncertainId: providerId,
    );
    final controller = ProviderController(native);
    await controller.initialize();
    expect(controller.recoveryId, providerId);
    await controller.unlock('never-send');
    await controller.review('B' * 43);
    expect(
      native.commands.every(
        (c) => c['command'] == 'status' && c['request_id'] == providerId,
      ),
      true,
    );
    expect(native.settled, isEmpty);
    native.status = 'completed';
    await controller.refresh();
    expect(controller.recoveryId, isEmpty);
    expect(native.settled, [providerId]);
    expect(
      controller.state.statusProgress,
      core.ProviderStatusProgress.terminal,
    );
    controller.dispose();
  });

  test('settlement owns admission and failure recovers original status without write replay', () async {
    final native = FixtureProviderPlatform()
      ..heldSettlement = Completer<void>();
    final controller = ProviderController(native);
    await controller.initialize();
    await controller.review(providerId);
    final decision = controller.decide(false, '');
    await Future<void>.delayed(Duration.zero);
    expect(controller.busy, true);
    expect(controller.canSetup, false);
    final count = native.commands.length;
    await controller.refresh();
    await controller.unlock('never-send');
    await controller.setup('https://other', '', '');
    expect(native.commands.length, count);
    native.failSettlement = true;
    native.heldSettlement!.complete();
    await decision;
    expect(controller.recoveryId, providerId);
    expect(controller.configuration.configured, true);
    expect(controller.canSetup, false);
    native.failSettlement = false;
    await controller.refresh();
    expect(controller.recoveryId, isEmpty);
    expect(native.settled, [providerId]);
    expect(
      native.commands.where((c) => c['command'] == 'decision'),
      hasLength(1),
    );
    expect(native.commands.where((c) => c['command'] == 'unlock'), isEmpty);
    expect(native.commands.last['command'], 'status');
    expect(native.commands.last['request_id'], providerId);
    controller.dispose();
  });

  test('interrupted startup reloads metadata before admission', () async {
    final native = FixtureProviderPlatform()
      ..heldConfiguration = Completer<ProviderConfiguration>();
    final controller = ProviderController(native);
    final initial = controller.initialize();
    controller.suspend();
    native.heldConfiguration!.complete(native.saved);
    await initial;
    expect(native.commands, isEmpty);
    native.heldConfiguration = null;
    controller.resume();
    await Future<void>.delayed(Duration.zero);
    expect(controller.configuration.endpoint, native.saved.endpoint);
    expect(native.commands.map((c) => c['command']), ['session', 'list']);
    controller.dispose();
  });

  test('native setup completion while inactive reconciles replacement without network', () async {
    final native = FixtureProviderPlatform()
      ..heldSetup = Completer<ProviderConfiguration>();
    final controller = ProviderController(native);
    await controller.initialize();
    final replacement = controller.setup(
      'https://replacement.example',
      'c' * 64,
      'synthetic',
    );
    controller.suspend();
    final count = native.commands.length;
    native.heldSetup!.complete(
      ProviderConfiguration(
        configured: true,
        endpoint: 'https://replacement.example/v1/companion',
        pin: 'c' * 64,
        fingerprint: 'd' * 64,
      ),
    );
    await replacement;
    expect(controller.configuration.endpoint, native.saved.endpoint);
    expect(controller.configuration.fingerprint, 'd' * 64);
    expect(native.commands.length, count);
    controller.resume();
    await Future<void>.delayed(Duration.zero);
    expect(native.commands.length, count + 2);
    expect(controller.state.statusId, isEmpty);
    controller.dispose();
  });

  test('failed reconciliation stays recoverable and blocks old-provider operations', () async {
    final native = FixtureProviderPlatform();
    final controller = ProviderController(native);
    await controller.initialize();
    controller.suspend();
    native.failConfiguration = true;
    controller.resume();
    await Future<void>.delayed(Duration.zero);
    final count = native.commands.length;
    await controller.review(providerId);
    expect(native.commands.length, count);
    native.failConfiguration = false;
    await controller.refresh();
    expect(native.commands.length, count + 2);
    controller.dispose();
  });

  test('failed authority does not list and backs off while valid locked reply succeeds', () async {
    final native = FixtureProviderPlatform();
    final controller = ProviderController(native);
    await controller.initialize();
    for (final error in [
      'rate_limited',
      'unavailable',
      'unauthorized',
      'stale',
      'malformed',
    ]) {
      native.sessionReply = error == 'malformed'
          ? Uint8List(0)
          : encoded({'version': 1, 'error': error});
      final count = native.commands.length;
      await controller.refresh();
      expect(native.commands.length, count + 1);
      expect(native.commands.last['command'], 'session');
      expect(controller.state.locked, true);
      expect(controller.state.requests, isEmpty);
      expect(controller.refreshDelaySeconds, inInclusiveRange(10, 30));
    }
    expect(controller.refreshDelaySeconds, 30);
    native.sessionReply = encoded({
      'version': 1,
      'state': 'locked',
      'generation': 2,
    });
    final count = native.commands.length;
    await controller.refresh();
    expect(native.commands.length, count + 1);
    expect(controller.refreshDelaySeconds, 5);
    controller.dispose();
  });

  test(
    'approved and running track original ID until terminal without replay',
    () async {
      final native = FixtureProviderPlatform();
      final controller = ProviderController(native);
      await controller.initialize();
      await controller.review(providerId);
      await controller.decide(true, 'synthetic');
      expect(
        controller.state.statusProgress,
        core.ProviderStatusProgress.committed,
      );
      for (final status in ['running', 'completed']) {
        native.status = status;
        await controller.refresh();
        expect(native.commands.last['command'], 'status');
        expect(native.commands.last['request_id'], providerId);
      }
      expect(
        controller.state.statusProgress,
        core.ProviderStatusProgress.terminal,
      );
      expect(
        native.commands.where((c) => c['command'] == 'decision'),
        hasLength(1),
      );
      await controller.refresh();
      expect(native.commands.last['command'], 'list');
      controller.dispose();
    },
  );

  testWidgets(
    'inactive and synthetic route retire review and gate polling independently',
    (tester) async {
      tester.view.physicalSize = const Size(1200, 2400);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final native = FixtureProviderPlatform();
      await tester.pumpWidget(
        MaterialApp(
          home: ProviderPage(
            platform: native,
            syntheticBuilder: (_) =>
                const Scaffold(body: Text('synthetic route')),
          ),
        ),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.text('Review $providerId'));
      await tester.pumpAndSettle();
      final password = find.byKey(const Key('Fresh approval password'));
      await tester.enterText(password, 'synthetic');
      final field = tester.widget<TextField>(password).controller!;
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
      await tester.pump();
      expect(field.text, isEmpty);
      expect(find.byKey(const Key('provider-review')), findsNothing);
      final count = native.commands.length;
      await tester.pump(const Duration(seconds: 31));
      expect(native.commands.length, count);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('destination-settings')));
      await tester.pumpAndSettle();
      await tester.ensureVisible(
        find.text('Open separate synthetic signing demonstration'),
      );
      await tester.tap(
        find.text('Open separate synthetic signing demonstration'),
      );
      await tester.pumpAndSettle();
      final hiddenCount = native.commands.length;
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
      await tester.pump(const Duration(seconds: 31));
      expect(native.commands.length, hiddenCount);
      Navigator.of(tester.element(find.text('synthetic route'))).pop();
      await tester.pumpAndSettle();
      expect(native.commands.length, greaterThan(hiddenCount));
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  test('actual bridge consumes tickets, rejects duplicates and keeps original uncertainty', () async {
    final native = FixtureProviderPlatform()..loseDecision = true;
    final controller = ProviderController(native);
    await controller.initialize();
    await controller.review(providerId);
    expect(controller.state.canDecide, true);
    await controller.decide(true, 'synthetic-password');
    expect(controller.state.uncertainId, providerId);
    expect(
      native.commands.where((c) => c['command'] == 'decision'),
      hasLength(1),
    );
    await controller.refresh();
    await controller.decide(true, 'synthetic-password');
    expect(
      native.commands.where((c) => c['command'] == 'decision'),
      hasLength(1),
    );
    native.status = 'running';
    await controller.refresh();
    expect(controller.state.uncertainId, isEmpty);
    expect(native.settled, [providerId]);
    controller.dispose();
  });

  test('late review after sleep and duplicate native completion cannot restore authority', () async {
    final native = FixtureProviderPlatform()
      ..heldReview = Completer<Uint8List>();
    final controller = ProviderController(native);
    await controller.initialize();
    final pending = controller.review(providerId);
    native.invalidate!();
    native.heldReview!.complete(encoded(providerReview()));
    await pending;
    expect(controller.state.reviewText, isEmpty);
    expect(controller.state.review, isNull);
    expect(controller.state.canDecide, false);
    controller.dispose();
  });

  test('decision completes and clears durable marker after disposal', () async {
    final native = FixtureProviderPlatform()
      ..heldDecision = Completer<Uint8List>();
    final controller = ProviderController(native);
    await controller.initialize();
    await controller.review(providerId);
    final pending = controller.decide(false, '');
    controller.dispose();
    native.heldDecision!.complete(
      encoded({
        'version': 1,
        'status': {'status': 'denied'},
      }),
    );
    await pending;
    expect(core.providerSnapshot().uncertainId, isEmpty);
    expect(native.settled, [providerId]);
  });

  test('unsupported provider never invokes the native channel', () async {
    const channel = MethodChannel('test/provider-unavailable');
    var calls = 0;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (_) async {
          calls++;
          return null;
        });
    final native = NativeProviderPlatform(macOS: false, channel: channel);
    expect((await native.configuration()).configured, false);
    await expectLater(native.send(Uint8List(0)), throwsUnsupportedError);
    await expectLater(native.setup('', '', ''), throwsUnsupportedError);
    expect(calls, 0);
  });

  test(
    'native channel rejects malformed configuration and oversized responses',
    () async {
      const channel = MethodChannel('test/provider-closed');
      Object? response = {'configured': true, 'privateKey': Uint8List(32)};
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (_) async => response);
      final native = NativeProviderPlatform(macOS: true, channel: channel);
      await expectLater(native.configuration(), throwsFormatException);
      response = Uint8List(1048577);
      await expectLater(native.send(Uint8List(1)), throwsFormatException);
      response = 'not bytes';
      await expectLater(native.send(Uint8List(1)), throwsFormatException);
    },
  );

  test(
    'fixed native settings errors keep UI generic and fail closed',
    () async {
      const channel = MethodChannel('test/provider-settings-errors');
      for (final code in [
        'provider_configuration_unreadable',
        'provider_configuration_invalid',
        'provider_identity_unavailable',
      ]) {
        var calls = 0;
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(channel, (_) async {
              calls++;
              throw PlatformException(
                code: code,
                message: 'private-path password identity-reference',
                details: 'raw-response PRIVATE KEY',
              );
            });
        final controller = ProviderController(
          NativeProviderPlatform(macOS: true, channel: channel),
        );
        await controller.initialize();
        expect(
          controller.diagnostic,
          'Saved provider setup is unavailable. Check the dedicated client identity.',
        );
        expect(controller.configuration.configured, false);
        expect(controller.state.canDecide, false);
        expect(calls, 1);
        controller.dispose();
      }
    },
  );

  testWidgets(
    'provider review is complete, password clears on deny and context changes',
    (tester) async {
      tester.view.physicalSize = const Size(1200, 2400);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final native = FixtureProviderPlatform();
      await tester.pumpWidget(
        MaterialApp(
          home: ProviderPage(
            platform: native,
            syntheticBuilder: (_) => const Text('synthetic'),
          ),
        ),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.text('Review $providerId'));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('provider-review')), findsOneWidget);
      expect(find.text('Arguments (1 separate values)'), findsOneWidget);
      expect(find.text('Credentials (1)'), findsOneWidget);
      expect(reviewFact(tester, 'review-id'), '"$providerId"');
      expect(reviewFact(tester, 'review-argument-0'), '"staging"');
      expect(
        reviewFact(tester, 'review-credential-0-label'),
        '"Synthetic login"',
      );
      expect(core.providerSnapshot().review, isNotNull);
      final password = find.byKey(const Key('Fresh approval password'));
      await tester.ensureVisible(password);
      await tester.enterText(password, 'synthetic-password');
      await tester.pump(const Duration(seconds: 5));
      await tester.pumpAndSettle();
      expect(
        tester.widget<TextField>(password).controller!.text,
        'synthetic-password',
      );
      native.invalidate!();
      await tester.pump();
      expect(find.byKey(const Key('provider-review')), findsNothing);
      expect(native.commands.where((c) => c['command'] == 'decision'), isEmpty);
      tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.text('Review $providerId'));
      await tester.tap(find.text('Review $providerId'));
      await tester.pumpAndSettle();
      expect(tester.widget<TextField>(password).controller!.text, isEmpty);
      await tester.ensureVisible(password);
      await tester.enterText(password, 'must-not-accompany-denial');
      await tester.ensureVisible(find.text('Deny without password'));
      await tester.tap(find.text('Deny without password'));
      await tester.pumpAndSettle();
      final denial = native.commands.singleWhere(
        (c) => c['command'] == 'decision',
      );
      expect(denial['decision'], 'deny');
      expect(denial.containsKey('password'), false);
      expect(find.byKey(const Key('provider-review')), findsNothing);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets('unsupported screen clearly disables provider setup', (
    tester,
  ) async {
    await tester.pumpWidget(
      MaterialApp(
        home: ProviderPage(
          platform: NativeProviderPlatform(macOS: false),
          syntheticBuilder: (_) => const Text('synthetic'),
        ),
      ),
    );
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('provider-unavailable')), findsOneWidget);
    await tester.tap(find.byKey(const Key('destination-settings')));
    await tester.pumpAndSettle();
    expect(
      tester
          .widget<FilledButton>(
            find.widgetWithText(
              FilledButton,
              'Select CA and import dedicated identity',
            ),
          )
          .onPressed,
      isNull,
    );
    await tester.pumpWidget(const SizedBox.shrink());
  });
}
