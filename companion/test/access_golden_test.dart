import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:companion_slice/provider/page.dart';
import 'package:companion_slice/src/rust/frb_generated.dart';

import 'provider_support.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async {
    await RustLib.init();
    // Deterministic licensed test font, never packaged with the application.
    // Include real weights so each engine uses the same glyph outlines instead
    // of host-specific synthesis/fallback. Pin icons for the same reason.
    // Register the same font for the review's test-only monospace fallback.
    final fonts = [
      for (final weight in ['Regular', 'Medium', 'Bold'])
        ByteData.sublistView(
          File('test/fonts/Roboto-$weight.ttf').readAsBytesSync(),
        ),
    ];
    for (final family in [
      'Roboto',
      'monospace',
      '.SF UI Text',
      '.SF UI Display',
      '.AppleSystemUIFont',
      'CupertinoSystemText',
      'CupertinoSystemDisplay',
      'Segoe UI',
    ]) {
      final loader = FontLoader(family);
      for (final bytes in fonts) {
        loader.addFont(Future.value(bytes));
      }
      await loader.load();
    }
    await (FontLoader('MaterialIcons')..addFont(
          Future.value(
            ByteData.sublistView(
              File('test/fonts/MaterialIcons-Regular.otf').readAsBytesSync(),
            ),
          ),
        ))
        .load();
  });
  setUp(resetProvider);
  // Only the synthetic provider fixture is rendered. Goldens never read native
  // configuration or use real credential material, identities or request data.
  for (final brightness in Brightness.values) {
    for (final layout in ['desktop', 'compact', 'large']) {
      final compact = layout != 'desktop';
      testWidgets('Quiet Instrument ${brightness.name} $layout', (
        tester,
      ) async {
        tester.view.physicalSize = compact
            ? const Size(390, 844)
            : const Size(1440, 1100);
        tester.view.devicePixelRatio = 1;
        tester.platformDispatcher.platformBrightnessTestValue = brightness;
        addTearDown(tester.view.resetPhysicalSize);
        addTearDown(tester.view.resetDevicePixelRatio);
        addTearDown(tester.platformDispatcher.clearPlatformBrightnessTestValue);
        await tester.pumpWidget(
          MaterialApp(
            locale: const Locale('en', 'US'),
            builder: (context, child) => MediaQuery(
              data: MediaQuery.of(context).copyWith(
                textScaler: TextScaler.linear(layout == 'large' ? 2 : 1),
              ),
              child: child!,
            ),
            home: RepaintBoundary(
              key: const Key('golden'),
              child: ProviderPage(
                platform: FixtureProviderPlatform(),
                syntheticBuilder: (_) => const Text('Synthetic only'),
              ),
            ),
          ),
        );
        await tester.pumpAndSettle();
        await tester.ensureVisible(find.text('Review $providerId'));
        await tester.tap(find.text('Review $providerId'));
        await tester.pumpAndSettle();
        final name = '${brightness.name}_$layout';
        await expectLater(
          find.byKey(const Key('golden')),
          matchesGoldenFile('goldens/${name}_review.png'),
        );
        await tester.ensureVisible(
          find.text(
            layout == 'large' ? 'Fresh approval password' : 'Cancel review',
          ),
        );
        await tester.pumpAndSettle();
        await expectLater(
          find.byKey(const Key('golden')),
          matchesGoldenFile('goldens/${name}_actions.png'),
        );
        expect(tester.takeException(), isNull);
        await tester.pumpWidget(const SizedBox.shrink());
      }, variant: TargetPlatformVariant.only(TargetPlatform.android));
    }
  }
}
