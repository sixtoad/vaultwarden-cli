import 'dart:async';

import 'package:companion_slice/platform/approval_client.dart';
import 'package:companion_slice/provider/page.dart';
import 'package:companion_slice/src/rust/frb_generated.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'installation_settings_test.dart' show FakeInstallation;
import 'provider_support.dart';
import 'touch_id_support.dart';

const secondId = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';

class FakeSignals implements DeviceSignalPlatform {
  void Function(DeviceSignal)? callback;
  @override
  bool get available => true;
  @override
  void Function() listen(void Function(DeviceSignal signal) onSignal) {
    callback = onSignal;
    return () => callback = null;
  }
}

/// Lifecycle safety shared by every approval client (#60): backgrounding,
/// locking or an app switch never approves the wrong request.
void main() {
  setUpAll(() async => RustLib.init());
  setUp(resetProvider);

  test(
    'a late signature is never sent after the same request was reopened',
    () async {
      final native = FixtureProviderPlatform()..approvalBinding = binding;
      final keys = FakeKeys()..prompt = Completer();
      final (provider, touchId) = await reviewed(native, keys);
      final approving = touchId.approve();
      await pumpEventQueue();
      provider.invalidate(); // background, lock or navigation retired it
      await provider.review(providerId); // the user reopened the same request
      expect(provider.state.reviewId, providerId);
      keys.prompt!.complete(); // the platform ignored the cancel
      await approving;
      expect(decisions(native), isEmpty);
      touchId.dispose();
      provider.dispose();
    },
  );

  Widget page(
    FixtureProviderPlatform native,
    FakeKeys keys, {
    String? os,
    FakeSignals? signals,
  }) => MaterialApp(
    home: ProviderPage(
      platform: native,
      syntheticBuilder: (_) => const SizedBox(),
      approvalKeys: keys,
      operatingSystem: os,
      deviceSignals: signals,
      installation: FakeInstallation(),
    ),
  );

  Future<void> open(WidgetTester tester, String id) async {
    await tester.pumpAndSettle();
    await tester.ensureVisible(requestRow(id));
    await tester.tap(requestRow(id));
    await tester.pumpAndSettle();
  }

  Future<void> touchIdTap(WidgetTester tester) async {
    await startAuthorization(tester);
    await tester.ensureVisible(find.byKey(const Key('approve-touch-id')));
    await tester.tap(find.byKey(const Key('approve-touch-id')));
    await tester.pump();
  }

  void wide(WidgetTester tester) {
    tester.view.physicalSize = const Size(1600, 1200);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.reset);
  }

  Map<String, dynamic> reviewOf(String id) {
    final reply = providerReview();
    reply['review']['id'] = id;
    return reply;
  }

  for (final os in ['macos', 'android', 'ios']) {
    group('on $os', () {
      testWidgets('a Touch ID result is never presented as another request', (
        tester,
      ) async {
        wide(tester);
        final native = FixtureProviderPlatform()
          ..approvalBinding = binding
          ..requestIds = [providerId, secondId];
        final keys = FakeKeys();
        await tester.pumpWidget(page(native, keys, os: os));
        await open(tester, providerId);
        await touchIdTap(tester);
        await tester.pumpAndSettle();
        expect(find.text('Approved once with Touch ID.'), findsOneWidget);
        native.reviewReply = reviewOf(secondId);
        await open(tester, secondId);
        expect(find.text('Approved once with Touch ID.'), findsNothing);
        expect(
          find.text(
            'Earlier request $providerId: Approved once with Touch ID.',
          ),
          findsOneWidget,
        );
        await tester.pumpWidget(const SizedBox.shrink());
      });

      testWidgets('a late completion names its own request, never the next', (
        tester,
      ) async {
        wide(tester);
        final native = FixtureProviderPlatform()
          ..approvalBinding = binding
          ..requestIds = [providerId, secondId];
        final keys = FakeKeys()..prompt = Completer();
        await tester.pumpWidget(page(native, keys, os: os));
        await open(tester, providerId);
        await touchIdTap(tester);
        native.reviewReply = reviewOf(secondId);
        await open(tester, secondId);
        expect(keys.cancelled, hasLength(1), reason: 'switching cancels');
        keys.prompt!.complete(); // late: the platform ignored the cancel
        await tester.pumpAndSettle();
        expect(decisions(native), isEmpty);
        final shown = tester.widget<Text>(
          find.byKey(const Key('touch-id-message')),
        );
        expect(shown.data, startsWith('Earlier request $providerId: '));
        expect(shown.data, contains('Nothing was sent'));
        await tester.pumpWidget(const SizedBox.shrink());
      });
    });
  }

  for (final os in ['android', 'ios']) {
    group('phone $os', () {
      for (final signal in DeviceSignal.values) {
        testWidgets('${signal.name} during the prompt cancels it; '
            'nothing is sent', (tester) async {
          final native = FixtureProviderPlatform()..approvalBinding = binding;
          final keys = FakeKeys()..prompt = Completer();
          final signals = FakeSignals();
          await tester.pumpWidget(page(native, keys, os: os, signals: signals));
          await open(tester, providerId);
          await touchIdTap(tester);
          signals.callback!(signal);
          expect(keys.cancelled, hasLength(1));
          keys.prompt!.complete(); // late signed reply
          await tester.pumpAndSettle();
          expect(decisions(native), isEmpty);
          expect(find.textContaining('Nothing was sent'), findsWidgets);
          await tester.pumpWidget(const SizedBox.shrink());
        });
      }

      testWidgets('returning to the foreground re-loads the open review', (
        tester,
      ) async {
        final native = FixtureProviderPlatform()..approvalBinding = binding;
        await tester.pumpWidget(page(native, FakeKeys(), os: os));
        await open(tester, providerId);
        int reviews() =>
            native.commands.where((c) => c['command'] == 'review').length;
        final before = reviews();
        for (final s in [
          AppLifecycleState.inactive,
          AppLifecycleState.hidden,
          AppLifecycleState.paused,
          AppLifecycleState.hidden,
          AppLifecycleState.inactive,
          AppLifecycleState.resumed,
        ]) {
          tester.binding.handleAppLifecycleStateChanged(s);
        }
        await tester.pumpAndSettle();
        expect(reviews(), before + 1, reason: 'a fresh review, not the old');
        expect(find.byKey(const Key('approve-start')), findsOneWidget);
        await tester.pumpWidget(const SizedBox.shrink());
      });

      testWidgets('settings never show desktop installation controls', (
        tester,
      ) async {
        final native = FixtureProviderPlatform();
        await tester.pumpWidget(page(native, FakeKeys(), os: os));
        await tester.pumpAndSettle();
        await tester.tap(find.text('Settings').first);
        await tester.pumpAndSettle();
        expect(find.byKey(const Key('desktop-installation')), findsNothing);
        await tester.pumpWidget(const SizedBox.shrink());
      });
    });
  }

  testWidgets('desktop settings keep the installation controls', (
    tester,
  ) async {
    await tester.pumpWidget(
      page(FixtureProviderPlatform(), FakeKeys(), os: 'macos'),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.text('Settings').first);
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('desktop-installation')), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
  });
}
