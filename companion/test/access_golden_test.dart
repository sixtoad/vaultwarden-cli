import 'dart:ffi' show Abi;
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:companion_slice/provider/page.dart';
import 'package:companion_slice/src/rust/frb_generated.dart';

import 'provider_support.dart';

String goldenHost() {
  if (!Platform.isMacOS) return Platform.operatingSystem;
  // CoreText rasterization changes with the OS, independently of pinned fonts.
  // Darwin kernel versions are not macOS product versions; query the latter.
  final result = Process.runSync('/usr/bin/sw_vers', ['-productVersion']);
  final version = (result.stdout as String).trim();
  if (result.exitCode != 0 ||
      !RegExp(r'^[0-9]+(?:\.[0-9]+){1,2}$').hasMatch(version)) {
    throw StateError('Cannot identify the macOS golden renderer version');
  }
  final architecture = switch (Abi.current()) {
    Abi.macosArm64 => 'arm64',
    Abi.macosX64 => 'x64',
    _ => throw StateError('Unrecognized macOS golden renderer ABI'),
  };
  return 'macos-${version.split('.').first}-$architecture';
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final host = goldenHost();
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
        // Keep exact comparisons within each engine host. The same pinned font
        // outlines rasterize differently on Linux, Windows and macOS. Missing
        // host baselines fail normally; there is no tolerance or fallback.
        final name = '$host/${brightness.name}_$layout';
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
