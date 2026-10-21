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
      final review = tester
          .widget<SelectableText>(find.byKey(const Key('provider-review')))
          .data!;
      expect(review, contains('Arguments (1 separate values)'));
      expect(review, contains('Credentials (1)'));
      final password = find.widgetWithText(
        TextField,
        'Fresh approval password',
      );
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
