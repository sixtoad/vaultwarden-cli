import 'package:companion_slice/provider/review/review_session.dart';
import 'package:companion_slice/src/rust/frb_generated.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'provider_support.dart';
import 'review_authorization_test.dart' show open, showPage;
import 'review_followups_test.dart' show review, snapshot;

String statusLine(WidgetTester tester) =>
    tester.widget<Text>(find.byKey(const Key('provider-status'))).data!;

void main() {
  setUpAll(() async => RustLib.init());
  setUp(resetProvider);

  test('a failed ask never dates a review opened later another way', () {
    final t0 = DateTime.utc(2030, 1, 1, 12);
    final session = ReviewSession()..beginLoad('X', t0);
    // The review of X fails: no review arrives.
    session.observe(snapshot(busy: false), t0.add(const Duration(seconds: 1)));
    // Much later a notification opens X (navigation-style close, no ask).
    final later = t0.add(const Duration(minutes: 5));
    session.closeStep();
    session.observe(snapshot(busy: true), later);
    session.observe(
      snapshot(busy: false, review: review('X'), reviewId: 'X'),
      later.add(const Duration(seconds: 2)),
    );
    final shown = later.add(const Duration(seconds: 2));
    expect(session.expiredAt(shown), isFalse);
    // Counted from the in-flight snapshot: early, never late.
    expect(session.remaining(shown), const Duration(seconds: 53));
  });

  testWidgets('a suspended app says the list is paused, not unanswered', (
    tester,
  ) async {
    await showPage(tester, FixtureProviderPlatform());
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    await tester.pump();
    expect(find.byKey(const Key('requests-paused')), findsOneWidget);
    expect(
      find.textContaining('has not answered a fresh authority read'),
      findsNothing,
    );
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('requests-paused')), findsNothing);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('an unreachable provider still reads as unanswered', (
    tester,
  ) async {
    await showPage(tester, UnreachableProvider());
    expect(find.byKey(const Key('requests-paused')), findsNothing);
    expect(
      find.textContaining('has not answered a fresh authority read'),
      findsOneWidget,
    );
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('the status line settles after an inbox refresh', (
    tester,
  ) async {
    await showPage(tester, FixtureProviderPlatform());
    expect(statusLine(tester), isNot('Contacting provider…'));
    expect(statusLine(tester), 'Inbox refreshed: 1 pending');
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('the status line reads a review status plainly', (tester) async {
    await showPage(tester, FixtureProviderPlatform());
    await open(tester, providerId);
    expect(statusLine(tester), isNot(contains('{')));
    expect(statusLine(tester), 'Request status: Awaiting your approval');
    await tester.pumpWidget(const SizedBox.shrink());
  });
}
