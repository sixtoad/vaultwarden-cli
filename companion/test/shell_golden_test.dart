import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:companion_slice/provider/page.dart';
import 'package:companion_slice/src/rust/frb_generated.dart';

import 'golden_support.dart';
import 'installation_settings_test.dart' show FakeInstallation;
import 'provider_support.dart';

/// Shell captures (#50 slice 1): the Requests list in four states, and the
/// first Devices and Settings references, light/dark, desktop/compact. Only
/// the synthetic provider fixture is rendered.
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

  final secondId = base64Url
      .encode(List<int>.filled(32, 7))
      .replaceAll('=', '');
  final scenes = <String, (String, FixtureProviderPlatform Function())>{
    'empty': ('requests', () => FixtureProviderPlatform()..requestIds = []),
    'two': (
      'requests',
      () => FixtureProviderPlatform()..requestIds = [providerId, secondId],
    ),
    'locked': (
      'requests',
      () => FixtureProviderPlatform()
        ..sessionReply = encoded({
          'version': 1,
          'state': 'locked',
          'generation': 1,
        }),
    ),
    'recovery': (
      'requests',
      () => FixtureProviderPlatform()..savePending(providerId),
    ),
    'devices': ('devices', FixtureProviderPlatform.new),
    'settings': ('settings', FixtureProviderPlatform.new),
  };

  for (final brightness in Brightness.values) {
    for (final layout in ['desktop', 'compact']) {
      for (final scene in scenes.entries) {
        testWidgets('shell ${scene.key} ${brightness.name} $layout', (
          tester,
        ) async {
          tester.view.physicalSize = layout == 'compact'
              ? const Size(390, 844)
              : const Size(1440, 900);
          tester.view.devicePixelRatio = 1;
          tester.platformDispatcher.platformBrightnessTestValue = brightness;
          addTearDown(tester.view.resetPhysicalSize);
          addTearDown(tester.view.resetDevicePixelRatio);
          addTearDown(
            tester.platformDispatcher.clearPlatformBrightnessTestValue,
          );
          await tester.pumpWidget(
            MaterialApp(
              locale: const Locale('en', 'US'),
              home: RepaintBoundary(
                key: const Key('golden'),
                child: ProviderPage(
                  platform: scene.value.$2(),
                  installation: FakeInstallation(),
                  syntheticBuilder: (_) => const Text('Synthetic only'),
                ),
              ),
            ),
          );
          await tester.pumpAndSettle();
          final destination = scene.value.$1;
          if (destination != 'requests') {
            await tester.tap(find.byKey(Key('destination-$destination')));
            await tester.pumpAndSettle();
          }
          // Hide the text caret of any focused field.
          FocusManager.instance.primaryFocus?.unfocus();
          await tester.pump(const Duration(milliseconds: 400));
          await expectLater(
            find.byKey(const Key('golden')),
            matchesGoldenFile(
              'goldens/$host/${brightness.name}_${layout}_shell_${scene.key}.png',
            ),
          );
          expect(tester.takeException(), isNull);
          await tester.pumpWidget(const SizedBox.shrink());
        }, variant: TargetPlatformVariant.only(TargetPlatform.android));
      }
    }
  }
}
