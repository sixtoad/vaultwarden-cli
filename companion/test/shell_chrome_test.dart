import 'dart:convert';
import 'dart:ui' show Tristate;

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:companion_slice/design/access_theme.dart';
import 'package:companion_slice/platform/provider.dart';
import 'package:companion_slice/provider/page.dart';
import 'package:companion_slice/src/rust/frb_generated.dart';

import 'provider_support.dart';

Future<void> show(
  WidgetTester tester,
  FixtureProviderPlatform platform, {
  Size size = const Size(1200, 1000),
}) async {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  await tester.pumpWidget(
    MaterialApp(
      home: ProviderPage(
        platform: platform,
        syntheticBuilder: (_) => const Text('Synthetic only'),
      ),
    ),
  );
  await tester.pumpAndSettle();
}

String connection(WidgetTester tester) =>
    tester.widget<Text>(find.byKey(const Key('shell-connection'))).data!;

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async => RustLib.init());
  setUp(resetProvider);

  final secondId = base64Url
      .encode(List<int>.filled(32, 7))
      .replaceAll('=', '');

  for (final size in [const Size(1200, 1000), const Size(390, 844)]) {
    testWidgets('pending badge counts request IDs with its meaning at $size', (
      tester,
    ) async {
      final semantics = tester.ensureSemantics();
      final native = FixtureProviderPlatform()
        ..requestIds = [providerId, secondId];
      await show(tester, native, size: size);
      String label() => tester
          .getSemantics(find.byKey(const Key('destination-requests')))
          .getSemanticsData()
          .label;
      expect(label(), contains('2 pending'));
      expect(find.text('2'), findsOneWidget);
      native.requestIds = [];
      await tester.tap(find.text('Refresh authority and inbox'));
      await tester.pumpAndSettle();
      expect(label(), isNot(contains('pending')));
      expect(find.text('0'), findsNothing);
      expect(native.commands.where((c) => c['command'] == 'decision'), isEmpty);
      await tester.pumpWidget(const SizedBox.shrink());
      semantics.dispose();
    });
  }

  testWidgets('footer reports connected provider host and this device role', (
    tester,
  ) async {
    await show(tester, FixtureProviderPlatform());
    expect(connection(tester), 'Connected');
    expect(find.text('Executes: provider at fixture.example'), findsOneWidget);
    expect(find.text('This device: approval client'), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('footer reports a locked provider', (tester) async {
    await show(
      tester,
      FixtureProviderPlatform()
        ..sessionReply = encoded({
          'version': 1,
          'state': 'locked',
          'generation': 1,
        }),
    );
    expect(connection(tester), 'Locked');
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('footer reports a missing configuration', (tester) async {
    await show(
      tester,
      FixtureProviderPlatform()
        ..saved = const ProviderConfiguration(configured: false),
    );
    expect(connection(tester), 'Not configured');
    expect(find.text('Executes: no provider configured'), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('footer reports an unavailable platform and no approval role', (
    tester,
  ) async {
    await show(tester, FixtureProviderPlatform()..available = false);
    expect(connection(tester), 'Unavailable on this platform');
    expect(find.text('This device: approval unavailable'), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('footer reports a lost provider connection', (tester) async {
    final native = FixtureProviderPlatform();
    await show(tester, native);
    native.invalidate!();
    await tester.pump();
    expect(connection(tester), 'Disconnected');
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('opened request row is selected and the shell keeps one back', (
    tester,
  ) async {
    final semantics = tester.ensureSemantics();
    await show(tester, FixtureProviderPlatform());
    bool selected() =>
        tester
            .getSemantics(requestRow(providerId))
            .getSemanticsData()
            .flagsCollection
            .isSelected ==
        Tristate.isTrue;
    expect(selected(), isFalse);
    await tester.tap(requestRow(providerId));
    await tester.pumpAndSettle();
    expect(selected(), isTrue);
    expect(find.byTooltip('Back to requests'), findsOneWidget);
    await tester.tap(find.byTooltip('Back to requests'));
    await tester.pumpAndSettle();
    expect(selected(), isFalse);
    expect(find.byKey(const Key('provider-review')), findsNothing);
    await tester.pumpWidget(const SizedBox.shrink());
    semantics.dispose();
  });

  test('new tokens meet contrast on the surfaces they are used on', () {
    double contrast(Color a, Color b) {
      final x = a.computeLuminance(), y = b.computeLuminance();
      return x > y ? (x + .05) / (y + .05) : (y + .05) / (x + .05);
    }

    for (final brightness in Brightness.values) {
      final theme = accessTheme(brightness);
      final c = theme.extension<AccessTheme>()!;
      final reason = brightness.name;
      for (final background in [c.surface, c.soft]) {
        expect(
          contrast(c.statusText, background),
          greaterThanOrEqualTo(4.5),
          reason: reason,
        );
        expect(
          contrast(c.secondary, background),
          greaterThanOrEqualTo(4.5),
          reason: reason,
        );
        expect(
          contrast(c.text, background),
          greaterThanOrEqualTo(4.5),
          reason: reason,
        );
        // The brand mark is 29 px text: large-text minimum.
        expect(
          contrast(c.accent, background),
          greaterThanOrEqualTo(3),
          reason: reason,
        );
      }
      expect(
        contrast(c.error, c.surface),
        greaterThanOrEqualTo(4.5),
        reason: reason,
      );
      expect(theme.colorScheme.error, c.error);
      expect(
        contrast(theme.colorScheme.onError, theme.colorScheme.error),
        greaterThanOrEqualTo(4.5),
        reason: reason,
      );
      expect(
        contrast(Colors.white, c.actionFill),
        greaterThanOrEqualTo(4.5),
        reason: reason,
      );
      expect(
        contrast(c.text, c.back),
        greaterThanOrEqualTo(4.5),
        reason: reason,
      );
      // The count badge: white 12 px label on the action fill.
      expect(
        theme.filledButtonTheme.style!.backgroundColor!.resolve({}),
        c.actionFill,
      );
    }
  });
}
