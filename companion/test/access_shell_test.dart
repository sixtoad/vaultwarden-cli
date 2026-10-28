import 'dart:async';
import 'dart:convert';
import 'dart:ui' show Tristate;

import 'package:flutter/services.dart';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:companion_slice/provider/page.dart';
import 'package:companion_slice/design/access_theme.dart';
import 'package:companion_slice/src/rust/api/provider.dart' as core;
import 'package:companion_slice/src/rust/frb_generated.dart';

import 'provider_support.dart';

Future<void> showShell(
  WidgetTester tester,
  FixtureProviderPlatform platform, {
  Size size = const Size(1200, 1500),
  double textScale = 1,
}) async {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  await tester.pumpWidget(
    MaterialApp(
      builder: (context, child) => MediaQuery(
        data: MediaQuery.of(context)
            .copyWith(textScaler: TextScaler.linear(textScale)),
        child: child!,
      ),
      home: ProviderPage(
        platform: platform,
        syntheticBuilder: (_) =>
            const Scaffold(body: Text('Synthetic diagnostics')),
      ),
    ),
  );
  await tester.pumpAndSettle();
}

Future<void> destination(WidgetTester tester, String name) async {
  await tester.tap(find.byKey(Key('destination-$name')));
  await tester.pumpAndSettle();
}

Future<void> review(WidgetTester tester) async {
  await tester.ensureVisible(find.text('Review $providerId'));
  await tester.tap(find.text('Review $providerId'));
  await tester.pumpAndSettle();
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async => RustLib.init());
  setUp(resetProvider);

  test('enabled text and action colors meet 4.5 to 1 in both themes', () {
    double contrast(Color a, Color b) {
      final x = a.computeLuminance(), y = b.computeLuminance();
      return x > y ? (x + .05) / (y + .05) : (y + .05) / (x + .05);
    }

    for (final brightness in Brightness.values) {
      final theme = accessTheme(brightness);
      final colors = theme.extension<AccessTheme>()!;
      final button = theme.filledButtonTheme.style!;
      expect(
        contrast(
          button.backgroundColor!.resolve({})!,
          button.foregroundColor!.resolve({})!,
        ),
        greaterThanOrEqualTo(4.5),
      );
      expect(
        contrast(theme.colorScheme.primary, theme.colorScheme.onPrimary),
        greaterThanOrEqualTo(4.5),
      );
      // OutlinedButton's default foreground is colorScheme.primary.
      expect(
        contrast(theme.colorScheme.primary, colors.surface),
        greaterThanOrEqualTo(4.5),
      );
      expect(
        contrast(colors.secondary, colors.surface),
        greaterThanOrEqualTo(4.5),
      );
    }
  });

  FixtureProviderPlatform longInbox() =>
      FixtureProviderPlatform()
        ..requestIds = [
          for (var i = 1; i <= 30; i++)
            base64Url.encode(List<int>.filled(32, i)).replaceAll('=', ''),
          providerId,
        ];

  ScrollPosition contentPosition(WidgetTester tester) => tester
      .state<ScrollableState>(
        find
            .descendant(
              of: find.byType(SingleChildScrollView),
              matching: find.byType(Scrollable),
            )
            .first,
      )
      .position;

  testWidgets('long inbox review, cancel and system back start at the top', (
    tester,
  ) async {
    final native = longInbox();
    await showShell(tester, native, size: const Size(390, 844));
    for (final systemBack in [false, true]) {
      await tester.ensureVisible(find.text('Review $providerId'));
      expect(contentPosition(tester).pixels, greaterThan(1000));
      await tester.tap(find.text('Review $providerId'));
      await tester.pumpAndSettle();
      expect(contentPosition(tester).pixels, 0);
      await tester.ensureVisible(find.text('Cancel review'));
      expect(contentPosition(tester).pixels, greaterThan(0));
      if (systemBack) {
        await tester.binding.handlePopRoute();
      } else {
        await tester.tap(find.text('Cancel review'));
      }
      await tester.pumpAndSettle();
      expect(contentPosition(tester).pixels, 0);
      expect(core.providerSnapshot().canDecide, false);
    }
    expect(native.commands.where((c) => c['command'] == 'decision'), isEmpty);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets(
    'activity fresh review never restores a long inbox scroll offset',
    (tester) async {
      final native = longInbox();
      await showShell(tester, native, size: const Size(390, 844));
      await review(tester);
      await tester.ensureVisible(find.text('Deny without password'));
      await tester.tap(find.text('Deny without password'));
      await tester.pumpAndSettle();
      await destination(tester, 'requests');
      await tester.ensureVisible(find.text('Review $providerId'));
      expect(contentPosition(tester).pixels, greaterThan(1000));
      await destination(tester, 'activity');
      await tester.ensureVisible(find.text('Open request with fresh review'));
      await tester.tap(find.text('Open request with fresh review'));
      await tester.pumpAndSettle();
      expect(contentPosition(tester).pixels, 0);
      expect(find.byKey(const Key('provider-review')), findsOneWidget);
      await destination(tester, 'devices');
      await destination(tester, 'requests');
      expect(contentPosition(tester).pixels, 0);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets(
    'locked activity disables fresh review and sends no review command',
    (tester) async {
      final native = FixtureProviderPlatform();
      await showShell(tester, native);
      await review(tester);
      await tester.ensureVisible(find.text('Deny without password'));
      await tester.tap(find.text('Deny without password'));
      await tester.pumpAndSettle();
      native.sessionReply = encoded({
        'version': 1,
        'state': 'locked',
        'generation': 1,
      });
      await destination(tester, 'activity');
      expect(core.providerSnapshot().locked, true);
      final button = find.widgetWithText(
        OutlinedButton,
        'Open request with fresh review',
      );
      expect(tester.widget<OutlinedButton>(button).onPressed, isNull);
      final reviews = native.commands
          .where((c) => c['command'] == 'review')
          .length;
      await tester.tap(button);
      await tester.pumpAndSettle();
      expect(
        native.commands.where((c) => c['command'] == 'review'),
        hasLength(reviews),
      );
      expect(core.providerSnapshot().canDecide, false);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets(
    'every tab retires review and clears passwords before returning',
    (tester) async {
      final native = FixtureProviderPlatform();
      await showShell(tester, native);
      for (final tab in ['devices', 'activity', 'settings', 'requests']) {
        await review(tester);
        final password = find.byKey(const Key('Fresh approval password'));
        await tester.ensureVisible(password);
        await tester.enterText(password, 'synthetic-never-send');
        final field = tester.widget<TextField>(password).controller!;
        await destination(tester, tab);
        expect(field.text, isEmpty);
        expect(core.providerSnapshot().canDecide, false);
        expect(core.providerSnapshot().reviewText, isEmpty);
        await destination(tester, 'requests');
        expect(find.byKey(const Key('provider-review')), findsNothing);
      }
      expect(native.commands.where((c) => c['command'] == 'decision'), isEmpty);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets(
    'compact back and cancel retire authority without cancelling request',
    (tester) async {
      final native = FixtureProviderPlatform();
      await showShell(tester, native, size: const Size(390, 844));
      await review(tester);
      final password = find.byKey(const Key('Fresh approval password'));
      await tester.ensureVisible(password);
      await tester.enterText(password, 'synthetic-never-send');
      final field = tester.widget<TextField>(password).controller!;
      await tester.binding.handlePopRoute();
      await tester.pumpAndSettle();
      expect(field.text, isEmpty);
      expect(core.providerSnapshot().canDecide, false);
      expect(find.text('Review $providerId'), findsOneWidget);
      await review(tester);
      await tester.ensureVisible(find.text('Cancel review'));
      await tester.tap(find.text('Cancel review'));
      await tester.pumpAndSettle();
      expect(core.providerSnapshot().canDecide, false);
      expect(find.text('Review $providerId'), findsOneWidget);
      expect(native.commands.where((c) => c['command'] == 'decision'), isEmpty);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets('late review after tab switch cannot restore authority', (
    tester,
  ) async {
    final native = FixtureProviderPlatform()
      ..heldReview = Completer<Uint8List>();
    await showShell(tester, native);
    await tester.tap(find.text('Review $providerId'));
    await tester.pump();
    await tester.tap(find.byKey(const Key('destination-devices')));
    await tester.pump();
    native.heldReview!.complete(encoded(providerReview()));
    await tester.pumpAndSettle();
    expect(core.providerSnapshot().canDecide, false);
    expect(core.providerSnapshot().reviewText, isEmpty);
    await destination(tester, 'requests');
    expect(find.byKey(const Key('provider-review')), findsNothing);
    expect(native.commands.where((c) => c['command'] == 'decision'), isEmpty);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets(
    'unknown outcome stays visible across destinations and only recovers original ID',
    (tester) async {
      final native = FixtureProviderPlatform()..loseDecision = true;
      await showShell(tester, native);
      await review(tester);
      final password = find.byKey(const Key('Fresh approval password'));
      await tester.ensureVisible(password);
      await tester.enterText(password, 'synthetic');
      await tester.ensureVisible(find.text('Approve once with password'));
      await tester.tap(find.text('Approve once with password'));
      await tester.pumpAndSettle();
      final count = native.commands.length;
      for (final tab in ['devices', 'activity', 'settings', 'requests']) {
        await destination(tester, tab);
        expect(find.byKey(const Key('provider-uncertain')), findsOneWidget);
        await tester.ensureVisible(
          find.text('Refresh original request status'),
        );
        await tester.tap(find.text('Refresh original request status'));
        await tester.pumpAndSettle();
      }
      expect(
        native.commands.where((c) => c['command'] == 'decision'),
        hasLength(1),
      );
      expect(
        native.commands
            .skip(count)
            .every(
              (c) => c['command'] == 'status' && c['request_id'] == providerId,
            ),
        true,
      );
      expect(core.providerSnapshot().canDecide, false);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets(
    'activity shows validated latest status and reopening explicitly requests fresh review',
    (tester) async {
      final native = FixtureProviderPlatform();
      await showShell(tester, native);
      await review(tester);
      await tester.ensureVisible(find.text('Deny without password'));
      await tester.tap(find.text('Deny without password'));
      await tester.pumpAndSettle();
      final reviews = native.commands
          .where((c) => c['command'] == 'review')
          .length;
      await destination(tester, 'activity');
      expect(
        find.text('Latest known request status · not a durable history'),
        findsOneWidget,
      );
      expect(find.textContaining('denied'), findsWidgets);
      expect(core.providerSnapshot().canDecide, false);
      expect(
        native.commands.where((c) => c['command'] == 'review'),
        hasLength(reviews),
      );
      await tester.tap(find.text('Open request with fresh review'));
      await tester.pumpAndSettle();
      expect(
        native.commands.where((c) => c['command'] == 'review'),
        hasLength(reviews + 1),
      );
      expect(find.byKey(const Key('provider-review')), findsOneWidget);
      expect(
        native.commands.where((c) => c['command'] == 'decision'),
        hasLength(1),
      );
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets(
    'late decision after navigation settles only its original request',
    (tester) async {
      final native = FixtureProviderPlatform()
        ..heldDecision = Completer<Uint8List>();
      await showShell(tester, native);
      await review(tester);
      await tester.ensureVisible(find.text('Deny without password'));
      await tester.tap(find.text('Deny without password'));
      await tester.pump();
      await tester.tap(find.byKey(const Key('destination-settings')));
      await tester.pump();
      expect(core.providerSnapshot().canDecide, false);
      native.heldDecision!.complete(
        encoded({
          'version': 1,
          'status': {'status': 'denied'},
        }),
      );
      await tester.pumpAndSettle();
      expect(
        native.commands.where((c) => c['command'] == 'decision'),
        hasLength(1),
      );
      expect(native.settled, [providerId]);
      expect(core.providerSnapshot().statusId, providerId);
      await destination(tester, 'activity');
      expect(find.text(providerId), findsOneWidget);
      expect(find.textContaining('denied'), findsWidgets);
      expect(core.providerSnapshot().canDecide, false);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets(
    'navigation exposes selected button semantics and supports keyboard activation',
    (tester) async {
      final semantics = tester.ensureSemantics();

      await showShell(tester, FixtureProviderPlatform());
      final requests = tester.getSemantics(
        find.byKey(const Key('destination-requests')),
      );
      expect(requests.getSemanticsData().flagsCollection.isButton, true);
      expect(
        requests.getSemanticsData().flagsCollection.isSelected ==
            Tristate.isTrue,
        true,
      );
      await tester.sendKeyEvent(LogicalKeyboardKey.tab);
      await tester.sendKeyEvent(LogicalKeyboardKey.tab);
      await tester.sendKeyEvent(LogicalKeyboardKey.enter);
      await tester.pumpAndSettle();
      expect(
        find.text('Known local connection and client identity'),
        findsOneWidget,
      );
      expect(
        tester
                .getSemantics(find.byKey(const Key('destination-devices')))
                .getSemanticsData()
                .flagsCollection
                .isSelected ==
            Tristate.isTrue,
        true,
      );
      expect(core.providerSnapshot().canDecide, false);
      await tester.pumpWidget(const SizedBox.shrink());
      semantics.dispose();
    },
  );

  for (final size in [const Size(390, 844), const Size(1200, 1000)]) {
    testWidgets(
      'complete scope and actions remain reachable at 200% on $size',
      (tester) async {
        await showShell(
          tester,
          FixtureProviderPlatform(),
          size: size,
          textScale: 2,
        );
        await review(tester);
        final actual = tester
            .widget<SelectableText>(find.byKey(const Key('provider-review')))
            .data;
        expect(actual, core.providerSnapshot().reviewText);
        expect(actual, contains('Credentials (1)'));
        for (final label in [
          'Fresh approval password',
          'Approve once with password',
          'Deny without password',
          'Cancel review',
        ]) {
          await tester.ensureVisible(find.text(label));
          await tester.pump();
          expect(tester.takeException(), isNull);
        }
        for (final tab in ['devices', 'activity', 'settings', 'requests']) {
          await destination(tester, tab);
          expect(tester.takeException(), isNull);
        }
        await tester.pumpWidget(const SizedBox.shrink());
      },
    );
  }
}
