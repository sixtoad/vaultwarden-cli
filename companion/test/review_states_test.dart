import 'package:companion_slice/provider/page.dart';
import 'package:companion_slice/provider/review/review_status.dart';
import 'package:companion_slice/src/rust/api/provider.dart' as core;
import 'package:companion_slice/src/rust/frb_generated.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'provider_support.dart';
import 'touch_id_support.dart';

Future<void> showPage(
  WidgetTester tester,
  FixtureProviderPlatform native,
) async {
  tester.view.physicalSize = const Size(1200, 1600);
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  await tester.pumpWidget(
    MaterialApp(
      home: ProviderPage(
        platform: native,
        syntheticBuilder: (_) => const SizedBox(),
        approvalKeys: FakeKeys()..available = false,
      ),
    ),
  );
  await tester.pumpAndSettle();
}

/// "Cancelled" is never a request status (owner decision, #50 slice 2).
final cancelled = find.textContaining(
  RegExp('cancelled', caseSensitive: false),
);

void main() {
  setUpAll(() async => RustLib.init());
  setUp(resetProvider);

  group('status classification reads only the status object', () {
    for (final (raw, phase, label) in [
      ('{"status":"pending"}', ReviewPhase.pending, 'Awaiting your approval'),
      (
        '{"status":"approved"}',
        ReviewPhase.approved,
        'Approved · not completed',
      ),
      ('{"status":"running"}', ReviewPhase.running, 'Running · not completed'),
      (
        '{"status":"completed","exit_code":3}',
        ReviewPhase.completed,
        'Completed · exit code 3',
      ),
      (
        '{"status":"completed"}',
        ReviewPhase.completed,
        'Completed · exit code not reported',
      ),
      (
        '{"status":"failed","reason":"execution_rejected"}',
        ReviewPhase.failed,
        'Failed',
      ),
      ('{"status":"denied"}', ReviewPhase.denied, 'Denied'),
      ('{"status":"expired"}', ReviewPhase.expired, 'Expired'),
      ('{"status":"cancelled"}', ReviewPhase.unreadable, 'Status not readable'),
      ('["pending"]', ReviewPhase.unreadable, 'Status not readable'),
      ('not json', ReviewPhase.unreadable, 'Status not readable'),
      ('', ReviewPhase.unreadable, 'Status not readable'),
    ]) {
      test(raw.isEmpty ? '(empty)' : raw, () {
        final status = ReviewStatus.parse(raw);
        expect(status.phase, phase);
        expect(status.label, label);
        expect(status.isFinal, phase != ReviewPhase.pending);
        expect(status.label.toLowerCase(), isNot(contains('cancel')));
      });
    }
  });

  for (final (status, label, sentence)
      in <(Map<String, dynamic>, String, String)>[
        (
          {'status': 'approved'},
          'Approved · not completed',
          'this is not a completed operation',
        ),
        (
          {'status': 'running'},
          'Running · not completed',
          'execution has not completed',
        ),
        (
          {'status': 'completed', 'exit_code': 0},
          'Completed · exit code 0',
          'completed with exit code 0',
        ),
        (
          {'status': 'completed', 'exit_code': 7},
          'Completed · exit code 7',
          'completed with exit code 7',
        ),
        (
          {'status': 'failed', 'reason': 'execution_rejected'},
          'Failed',
          'execution failed',
        ),
        ({'status': 'denied'}, 'Denied', 'Nothing will execute'),
        ({'status': 'expired'}, 'Expired', 'Expired before a decision'),
      ]) {
    testWidgets('a final $status review shows its own state only', (
      tester,
    ) async {
      final reply = providerReview();
      reply['ticket'] = null;
      reply['review']['status'] = status;
      final native = FixtureProviderPlatform()..reviewReply = reply;
      await showPage(tester, native);
      await tester.tap(requestRow(providerId));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('provider-review')), findsOneWidget);
      expect(find.text(label), findsWidgets);
      expect(
        tester.widget<Text>(find.byKey(const Key('review-final'))).data,
        contains(sentence),
      );
      if (status['reason'] != null) {
        expect(
          find.text('Reason reported by the provider: execution_rejected'),
          findsOneWidget,
        );
      }
      // Verification details stay rendered on a final review too.
      expect(find.byKey(const Key('review-verification')), findsOneWidget);
      expect(find.byKey(const Key('review-executable-digest')), findsOneWidget);
      expect(find.byKey(const Key('approve-start')), findsNothing);
      expect(find.byKey(const Key('deny-start')), findsNothing);
      expect(find.byKey(const Key('review-validity')), findsNothing);
      expect(find.byType(TextField), findsNothing);
      expect(cancelled, findsNothing);
      expect(native.commands.where((c) => c['command'] == 'decision'), isEmpty);
      await tester.pumpWidget(const SizedBox.shrink());
    });
  }

  testWidgets('a pending review shows every section and both first steps', (
    tester,
  ) async {
    await showPage(tester, FixtureProviderPlatform());
    await tester.tap(requestRow(providerId));
    await tester.pumpAndSettle();
    expect(find.text('Awaiting your approval'), findsOneWidget);
    expect(find.text('"deploy"'), findsWidgets, reason: 'title, verbatim');
    expect(
      find.text(
        '"agent synthetic (synthetic fingerprint)" wants to "Deploy synthetic application"',
      ),
      findsOneWidget,
    );
    expect(find.text('What you’re allowing'), findsOneWidget);
    expect(find.text('Verification details'), findsOneWidget);
    // Verification details sit between the consequence and the decision.
    double y(String key) => tester.getTopLeft(find.byKey(Key(key))).dy;
    expect(y('review-effect'), lessThan(y('review-verification')));
    expect(y('review-verification'), lessThan(y('approve-start')));
    for (final key in ['approve-start', 'deny-start']) {
      expect(
        tester.widget<ButtonStyleButton>(find.byKey(Key(key))).onPressed,
        isNotNull,
      );
    }
    expect(cancelled, findsNothing);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('a provider "cancelled" status is never shown as a state', (
    tester,
  ) async {
    final reply = providerReview();
    reply['ticket'] = null;
    reply['review']['status'] = {'status': 'cancelled'};
    final native = FixtureProviderPlatform()..reviewReply = reply;
    await showPage(tester, native);
    await tester.tap(requestRow(providerId));
    await tester.pumpAndSettle();
    expect(core.providerSnapshot().review, isNull);
    expect(find.byKey(const Key('provider-review')), findsNothing);
    expect(cancelled, findsNothing);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('outcome unknown checks only the original request', (
    tester,
  ) async {
    final native = FixtureProviderPlatform()..savePending(providerId);
    await showPage(tester, native);
    expect(find.text('Outcome unknown'), findsOneWidget);
    expect(find.text('Original request: $providerId'), findsOneWidget);
    // No row can open a new review while the outcome is unknown.
    for (final row in tester.widgetList<ButtonStyleButton>(
      requestRow(providerId),
    )) {
      expect(row.onPressed, isNull);
    }
    final count = native.commands.length;
    await tester.tap(find.byKey(const Key('check-status')));
    await tester.pumpAndSettle();
    final sent = native.commands.skip(count);
    expect(sent, isNotEmpty);
    expect(
      sent.every(
        (c) => c['command'] == 'status' && c['request_id'] == providerId,
      ),
      isTrue,
    );
    expect(cancelled, findsNothing);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('a locked provider opens no review', (tester) async {
    final native = FixtureProviderPlatform()
      ..sessionReply = encoded({
        'version': 1,
        'state': 'locked',
        'generation': 1,
      });
    await showPage(tester, native);
    for (final row in tester.widgetList<ButtonStyleButton>(
      requestRow(providerId),
    )) {
      expect(row.onPressed, isNull);
    }
    expect(find.byKey(const Key('provider-review')), findsNothing);
    expect(native.commands.where((c) => c['command'] == 'review'), isEmpty);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('an unavailable transport shows no review or decision', (
    tester,
  ) async {
    final native = FixtureProviderPlatform()..available = false;
    await showPage(tester, native);
    expect(find.byKey(const Key('provider-unavailable')), findsOneWidget);
    expect(find.byKey(const Key('provider-review')), findsNothing);
    expect(find.byKey(const Key('approve-start')), findsNothing);
    expect(native.commands, isEmpty);
    await tester.pumpWidget(const SizedBox.shrink());
  });
}
