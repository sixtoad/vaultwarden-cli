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

  testWidgets(
    'observation loss shows an unknown result without decision authority',
    (tester) async {
      final native = FixtureProviderPlatform();
      final history = providerHistory();
      (history['events'] as List).first['outcome'] = 'observation_lost';
      native.historyReply = encoded(history);
      await showShell(tester, native);
      await destination(tester, 'activity');
      expect(find.text('Result unknown'), findsOneWidget);
      expect(find.text('Completed successfully'), findsNothing);
      expect(
        core.providerSnapshot().history.single.outcome,
        core.ProviderHistoryOutcome.observationLost,
      );
      expect(core.providerSnapshot().canDecide, isFalse);
      expect(core.providerSnapshot().statusId, isEmpty);
      expect(native.commands.where((c) => c['command'] == 'decision'), isEmpty);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets(
    'history preserves order, legacy unknown time and exact second-event reopening',
    (tester) async {
      const secondId = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';
      final native = FixtureProviderPlatform();
      final history = providerHistory();
      (history['events'] as List).add({
        'request_id': secondId,
        'operation': 'legacy-task',
        'at_unix_seconds': null,
        'ordinal': 0,
        'outcome': 'legacy_unknown',
      });
      native.historyReply = encoded(history);
      native.reviewReply = providerReview();
      native.reviewReply!['review']['id'] = secondId;
      await showShell(tester, native, size: const Size(390, 844), textScale: 2);
      await destination(tester, 'activity');
      expect(find.text('Unknown · legacy event'), findsOneWidget);
      expect(find.text('2023-11-14 22:13:20 UTC'), findsOneWidget);
      final events = core.providerSnapshot().history;
      expect(events.map((e) => e.requestId), [providerId, secondId]);
      expect(native.commands.where((c) => c['command'] == 'review'), isEmpty);
      final second = find.byKey(
        const ValueKey(
          'activity-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB-0',
        ),
      );
      final button = find.descendant(
        of: second,
        matching: find.text('Open request with fresh review'),
      );
      await tester.ensureVisible(button);
      await tester.tap(button);
      await tester.pumpAndSettle();
      expect(native.commands[native.commands.length - 2]['command'], 'review');
      expect(native.commands.last['command'], 'request_origin');
      expect(native.commands.last['request_id'], secondId);
      expect(core.providerSnapshot().reviewId, secondId);
      expect(core.providerSnapshot().history, isEmpty);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets(
    'activity exposes loading empty unavailable and disconnected states',
    (tester) async {
      final native = FixtureProviderPlatform()
        ..heldHistory = Completer<Uint8List>();
      await showShell(tester, native);
      await tester.tap(find.byKey(const Key('destination-activity')));
      await tester.pump();
      await tester.pump();
      expect(find.text('Loading recent activity…'), findsOneWidget);
      native.heldHistory!.complete(
        encoded({'version': 1, 'history_version': 1, 'events': []}),
      );
      await tester.pumpAndSettle();
      expect(find.text('No history events are available.'), findsOneWidget);
      native.heldHistory = null;
      native.historyReply = encoded({'version': 1, 'error': 'invalid_request'});
      await tester.tap(find.text('Refresh activity'));
      await tester.pumpAndSettle();
      expect(find.textContaining('Activity unavailable.'), findsOneWidget);
      native.invalidate!();
      await tester.pump();
      expect(
        find.text('Disconnected. Refresh to load current provider activity.'),
        findsOneWidget,
      );
      expect(find.text('Open request with fresh review'), findsNothing);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets('activity renders full u64 timestamps without truncation', (
    tester,
  ) async {
    final native = FixtureProviderPlatform();
    native.historyReply = Uint8List.fromList(
      utf8.encode(
        jsonEncode(providerHistory())
            .replaceFirst('1700000000', '18446744073709551615'),
      ),
    );
    await showShell(tester, native);
    await destination(tester, 'activity');
    expect(find.text('Unix seconds: 18446744073709551615'), findsOneWidget);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox.shrink());
  });

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
      expect(button, findsNothing);
      expect(
        find.text(
          'Provider locked. Unlock separately in Requests before loading Activity.',
        ),
        findsOneWidget,
      );
      final reviews = native.commands
          .where((c) => c['command'] == 'review')
          .length;
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
        expect(core.providerSnapshot().review, isNull);
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
    expect(core.providerSnapshot().review, isNull);
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
    'activity shows durable history and reopening explicitly requests fresh review',
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
        find.text('Recent redacted provider history · up to 50 events'),
        findsOneWidget,
      );
      expect(find.textContaining('Denied'), findsWidgets);
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
      expect(core.providerSnapshot().statusText, contains('denied'));
      expect(find.textContaining('Submitted'), findsOneWidget);
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
        find.text(
          'Authoritative provider identities · names are labels, not identity proof.',
        ),
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

  testWidgets(
    'typed facts preserve complete scope and escaped argument boundaries',
    (tester) async {
      final response = providerReview();
      final scope = response['review'] as Map<String, dynamic>;
      scope['requester'] = 'agent\u202e';
      scope['effect'] = 'Deploy\nwithout hiding scope';
      scope['arguments'] = [
        '',
        ' a b ',
        'a\nb',
        '\u202ehidden',
        r'literal\u{202e}',
        '"quoted"',
      ];
      scope['credentials'] = [
        {'label': 'Login\u200b', 'use_type': 'log\nin'},
        {'label': 'Second', 'use_type': 'key'},
      ];
      final native = FixtureProviderPlatform()..reviewReply = response;
      await showShell(tester, native, size: const Size(390, 844));
      await review(tester);
      final expected = <String, String>{
        'id': '"$providerId"',
        'requester': r'"agent\u{202e}"',
        'operation': '"deploy"',
        'effect': r'"Deploy\u{000a}without hiding scope"',
        'target': '"staging"',
        'argument-0': '""',
        'argument-1': '" a b "',
        'argument-2': r'"a\u{000a}b"',
        'argument-3': r'"\u{202e}hidden"',
        'argument-4': r'"literal\\u{202e}"',
        'argument-5': r'"\"quoted\""',
        'credential-0-label': r'"Login\u{200b}"',
        'credential-0-use-type': r'"log\u{000a}in"',
        'credential-1-label': '"Second"',
        'credential-1-use-type': '"key"',
        'executable-digest': 'a' * 64,
        'policy-digest': 'b' * 64,
        'arguments-digest': 'c' * 64,
        'expiry': '2000000000',
        'one-time': '"Approve this operation once"',
        'status': '{"status":"pending"}',
      };
      for (final entry in expected.entries) {
        final key = 'review-${entry.key}';
        await tester.ensureVisible(find.byKey(Key(key)));
        await tester.pump();
        expect(reviewFact(tester, key), entry.value, reason: key);
        expect(tester.takeException(), isNull);
      }
      expect(find.text('Arguments (6 separate values)'), findsOneWidget);
      expect(find.text('Credentials (2)'), findsOneWidget);
      expect(
        find.text('Not supplied by provider protocol v1.'),
        findsOneWidget,
      );
      expect(native.commands.where((c) => c['command'] == 'decision'), isEmpty);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  for (final extension in ['create', 'ssh', 'future_scope']) {
    testWidgets(
      'unsupported $extension review never exposes partial scope or actions',
      (tester) async {
        final response = providerReview();
        (response['review'] as Map<String, dynamic>)[extension] = {
          'effect': 'not safe to omit',
        };
        final native = FixtureProviderPlatform()..reviewReply = response;
        await showShell(tester, native);
        await review(tester);
        expect(core.providerSnapshot().review, isNull);
        expect(core.providerSnapshot().reviewText, isEmpty);
        expect(core.providerSnapshot().canDecide, false);
        expect(find.byKey(const Key('provider-review')), findsNothing);
        expect(find.text('Approve once with password'), findsNothing);
        expect(
          native.commands.where((c) => c['command'] == 'decision'),
          isEmpty,
        );
        await tester.pumpWidget(const SizedBox.shrink());
      },
    );
  }

  testWidgets(
    'empty collections stay explicit and expiry retains all 64 bits',
    (tester) async {
      final response = providerReview();
      final scope = response['review'] as Map<String, dynamic>;
      scope['arguments'] = <String>[];
      scope['credentials'] = <Object>[];
      // Greater than the exact integer range of a double, still a valid u64.
      scope['expires_at_unix_seconds'] = 9007199254740993;
      await showShell(
        tester,
        FixtureProviderPlatform()..reviewReply = response,
      );
      await review(tester);
      expect(find.text('Arguments (0 separate values)'), findsOneWidget);
      expect(find.text('Credentials (0)'), findsOneWidget);
      expect(find.byKey(const Key('review-argument-0')), findsNothing);
      expect(find.byKey(const Key('review-credential-0-label')), findsNothing);
      expect(reviewFact(tester, 'review-expiry'), '9007199254740993');
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets(
    'provider count boundaries preserve complete scope at 200% text',
    (tester) async {
      final response = providerReview();
      final scope = response['review'] as Map<String, dynamic>;
      scope['arguments'] = List.generate(32, (i) => 'argument $i');
      scope['credentials'] = List.generate(
        16,
        (i) => {'label': 'credential $i', 'use_type': 'login'},
      );
      final native = FixtureProviderPlatform()..reviewReply = response;
      await showShell(tester, native, size: const Size(390, 844), textScale: 2);
      await review(tester);
      expect(core.providerSnapshot().canDecide, true);
      expect(find.text('Arguments (32 separate values)'), findsOneWidget);
      expect(find.text('Credentials (16)'), findsOneWidget);
      for (var i = 0; i < 32; i++) {
        expect(reviewFact(tester, 'review-argument-$i'), '"argument $i"');
      }
      for (var i = 0; i < 16; i++) {
        expect(
          reviewFact(tester, 'review-credential-$i-label'),
          '"credential $i"',
        );
        expect(reviewFact(tester, 'review-credential-$i-use-type'), '"login"');
      }
      for (final key in [
        'review-argument-31',
        'review-credential-15-use-type',
        'Fresh approval password',
      ]) {
        await tester.ensureVisible(find.byKey(Key(key)));
        await tester.pump();
        expect(tester.takeException(), isNull);
      }
      expect(native.commands.where((c) => c['command'] == 'decision'), isEmpty);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  for (final counts in [(33, 1), (1, 17), (300000, 1)]) {
    testWidgets(
      'excessive review counts $counts clear prior scope without decisions',
      (tester) async {
        final native = FixtureProviderPlatform();
        await showShell(tester, native);
        await review(tester);
        expect(core.providerSnapshot().review, isNotNull);
        final response = providerReview();
        final scope = response['review'] as Map<String, dynamic>;
        scope['arguments'] = List<String>.filled(counts.$1, '');
        scope['credentials'] = List.generate(
          counts.$2,
          (_) => {'label': '', 'use_type': 'login'},
        );
        expect(encoded(response).length, lessThan(1048576));
        native.reviewReply = response;
        await review(tester);
        final state = core.providerSnapshot();
        expect(state.outcome, core.ProviderOutcome.invalid);
        expect(state.review, isNull);
        expect(state.reviewText, isEmpty);
        expect(state.canDecide, false);
        expect(find.byKey(const Key('provider-review')), findsNothing);
        expect(find.text('Approve once with password'), findsNothing);
        expect(find.text('Deny without password'), findsNothing);
        expect(
          native.commands.where((c) => c['command'] == 'decision'),
          isEmpty,
        );
        expect(native.commands.where((c) => c['command'] == 'unlock'), isEmpty);
        await tester.pumpWidget(const SizedBox.shrink());
      },
    );
  }

  for (final brightness in Brightness.values) {
    for (final size in [const Size(390, 844), const Size(1200, 1000)]) {
      testWidgets(
        'complete scope and actions remain reachable at 200% on $size ${brightness.name}',
        (tester) async {
          tester.platformDispatcher.platformBrightnessTestValue = brightness;
          addTearDown(
            tester.platformDispatcher.clearPlatformBrightnessTestValue,
          );
          final response = providerReview();
          (response['review'] as Map<String, dynamic>)['target'] =
              'long-scope-' * 100;
          await showShell(
            tester,
            FixtureProviderPlatform()..reviewReply = response,
            size: size,
            textScale: 2,
          );
          await review(tester);
          expect(
            reviewFact(tester, 'review-target'),
            '"${'long-scope-' * 100}"',
          );
          expect(find.text('Credentials (1)'), findsOneWidget);
          for (final field in [
            'id',
            'requester',
            'operation',
            'effect',
            'target',
            'argument-0',
            'credential-0-label',
            'credential-0-use-type',
            'executable-digest',
            'policy-digest',
            'arguments-digest',
            'expiry',
            'one-time',
            'status',
          ]) {
            await tester.ensureVisible(find.byKey(Key('review-$field')));
            await tester.pump();
            expect(tester.takeException(), isNull);
          }
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
}
