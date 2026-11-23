import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:companion_slice/provider/page.dart';
import 'package:companion_slice/src/rust/api/provider.dart' as core;
import 'package:companion_slice/src/rust/frb_generated.dart';

import 'golden_support.dart';
import 'provider_support.dart';
import 'touch_id_review_test.dart' show OriginFixture;
import 'touch_id_support.dart';

/// Review state captures (#50 slice 2): the authorization step three ways,
/// each final status and an unknown outcome, the ticket running out before a
/// decision and an authenticated request origin; light desktop and dark
/// compact. Only the synthetic provider fixture is rendered.
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final host = goldenHost();
  final comparator = goldenFileComparator;
  goldenFileComparator = CaptureComparator(comparator);
  tearDownAll(() => goldenFileComparator = comparator);
  setUpAll(() async {
    await RustLib.init();
    await loadGoldenFonts();
  });
  setUp(resetProvider);

  FixtureProviderPlatform finalReview(Map<String, dynamic> status) {
    final reply = providerReview();
    reply['ticket'] = null;
    reply['review']['status'] = status;
    return FixtureProviderPlatform()..reviewReply = reply;
  }

  // name: (platform, Touch ID hardware, what to bring into view)
  final scenes = <String, (FixtureProviderPlatform Function(), bool, String?)>{
    'authorize_password': (FixtureProviderPlatform.new, false, 'step'),
    'authorize_touch_id': (
      () => FixtureProviderPlatform()..approvalBinding = binding,
      true,
      'step',
    ),
    'authorize_touch_id_unavailable': (
      FixtureProviderPlatform.new,
      true,
      'step',
    ),
    'running': (() => finalReview({'status': 'running'}), false, 'review'),
    'completed': (
      () => finalReview({'status': 'completed', 'exit_code': 0}),
      false,
      'review',
    ),
    'failed': (
      () => finalReview({'status': 'failed', 'reason': 'execution_rejected'}),
      false,
      'review',
    ),
    'denied': (() => finalReview({'status': 'denied'}), false, 'review'),
    'expired': (() => finalReview({'status': 'expired'}), false, 'review'),
    'outcome_unknown': (
      () => FixtureProviderPlatform()..savePending(providerId),
      false,
      null,
    ),
    // The review's ticket ran out and Rust retired it ("Reload review").
    'expired_ticket': (FixtureProviderPlatform.new, false, 'expired'),
    'origin': (OriginFixture.new, false, 'origin'),
  };

  for (final (brightness, layout) in [
    (Brightness.light, 'desktop'),
    (Brightness.dark, 'compact'),
  ]) {
    for (final scene in scenes.entries) {
      testWidgets('review ${scene.key} ${brightness.name} $layout', (
        tester,
      ) async {
        tester.view.physicalSize = layout == 'compact'
            ? const Size(390, 844)
            : const Size(1440, 900);
        tester.view.devicePixelRatio = 1;
        tester.platformDispatcher.platformBrightnessTestValue = brightness;
        addTearDown(tester.view.resetPhysicalSize);
        addTearDown(tester.view.resetDevicePixelRatio);
        addTearDown(tester.platformDispatcher.clearPlatformBrightnessTestValue);
        final (platform, touchId, view) = scene.value;
        var now = DateTime.utc(2030, 1, 1, 12);
        await tester.pumpWidget(
          MaterialApp(
            locale: const Locale('en', 'US'),
            home: RepaintBoundary(
              key: const Key('golden'),
              child: ProviderPage(
                platform: platform(),
                approvalKeys: FakeKeys()..available = touchId,
                clock: () => now,
                syntheticBuilder: (_) => const Text('Synthetic only'),
              ),
            ),
          ),
        );
        await tester.pumpAndSettle();
        if (view != null) {
          await tester.ensureVisible(requestRow(providerId));
          await tester.tap(requestRow(providerId));
          await tester.pumpAndSettle();
        }
        if (view == 'step') {
          await startAuthorization(tester);
          await Scrollable.ensureVisible(
            tester.element(find.byKey(const Key('authorization-step'))),
            alignment: 0.1,
          );
          await tester.pumpAndSettle();
        }
        if (view == 'expired') {
          now = now.add(const Duration(seconds: 56));
          core.providerInvalidate();
          await tester.pump(const Duration(milliseconds: 300));
          await Scrollable.ensureVisible(
            tester.element(find.byKey(const Key('review-expired'))),
            alignment: 0.1,
          );
          await tester.pumpAndSettle();
        }
        if (view == 'origin') {
          await Scrollable.ensureVisible(
            tester.element(find.byKey(const Key('review-origin'))),
            alignment: 0.3,
          );
          await tester.pumpAndSettle();
        }
        if (view == 'review') {
          await Scrollable.ensureVisible(
            tester.element(find.byKey(const Key('provider-review'))),
          );
          await tester.pumpAndSettle();
        }
        FocusManager.instance.primaryFocus?.unfocus();
        await tester.pump(const Duration(milliseconds: 400));
        await expectLater(
          find.byKey(const Key('golden')),
          matchesGoldenFile(
            'goldens/$host/${brightness.name}_${layout}_review_${scene.key}.png',
          ),
        );
        expect(tester.takeException(), isNull);
        await tester.pumpWidget(const SizedBox.shrink());
      }, variant: TargetPlatformVariant.only(TargetPlatform.android));
    }
  }
}
