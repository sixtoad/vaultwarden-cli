import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:companion_slice/design/metrics.dart';
import 'package:companion_slice/provider/page.dart';
import 'package:companion_slice/provider/review/review_session.dart';
import 'package:companion_slice/src/rust/api/provider.dart' as core;
import 'package:companion_slice/src/rust/frb_generated.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'provider_support.dart';
import 'review_authorization_test.dart' show open, showPage;
import 'touch_id_support.dart';

/// Answers `request_origin` with the provider's explicit "no authenticated
/// origin" (`origin: null`), as a v2 provider does for a legacy request.
class NoOrigin extends FixtureProviderPlatform {
  @override
  Future<Uint8List> send(Uint8List body) async {
    final command = jsonDecode(utf8.decode(body)) as Map<String, dynamic>;
    if (command['command'] != 'request_origin') return super.send(body);
    commands.add(command);
    return encoded({
      'version': 2,
      'request_id': command['request_id'],
      'origin': null,
    });
  }
}

core.ProviderSnapshot snapshot({
  required bool busy,
  core.ProviderReview? review,
  String reviewId = '',
}) => core.ProviderSnapshot(
  outcome: core.ProviderOutcome.none,
  statusProgress: core.ProviderStatusProgress.none,
  configured: true,
  busy: busy,
  locked: false,
  authorityKnown: true,
  historyState: core.ProviderHistoryState.values.first,
  history: const [],
  requests: const [],
  reviewText: reviewId,
  review: review,
  reviewId: reviewId,
  canDecide: review != null,
  uncertainId: '',
  statusId: '',
  statusText: '',
  message: '',
);

core.ProviderReview review(String id) => core.ProviderReview(
  id: id,
  requester: '"agent"',
  operation: '"deploy"',
  effect: '"Deploy"',
  target: '"staging"',
  arguments: const [],
  credentials: const [],
  executableDigest: 'a' * 64,
  policyDigest: 'b' * 64,
  argumentsDigest: 'c' * 64,
  // Far beyond the 55 s ticket: the ticket bounds the countdown.
  expiresAtUnixSeconds: BigInt.from(4000000000),
  oneTime: '"Approve this operation once"',
  status: '{"status":"pending"}',
);

/// The page state, for checks no control can reach (its members are public).
dynamic pageState(WidgetTester tester) =>
    tester.state(find.byType(ProviderPage));

void main() {
  setUpAll(() async => RustLib.init());
  setUp(resetProvider);

  test('a review replacing another counts from its own request', () {
    final t0 = DateTime.utc(2030, 1, 1, 12);
    final session = ReviewSession()
      ..observe(snapshot(busy: false, review: review('A'), reviewId: 'A'), t0);
    // B is asked for at t0 + 10 s; its review replaces A's with no empty
    // snapshot in between and lands 3 s later.
    final asked = t0.add(const Duration(seconds: 10));
    session.beginLoad('B', asked);
    session.observe(
      snapshot(busy: false, review: review('B'), reviewId: 'B'),
      asked.add(const Duration(seconds: 3)),
    );
    expect(session.loadedId, 'B');
    expect(
      session.remaining(asked.add(const Duration(seconds: 3))),
      const Duration(seconds: 52),
    );
  });

  test('AccessMetrics.copyWith applies its arguments', () {
    final changed = AccessMetrics.standard.copyWith(
      target: 44,
      detailMaxWidth: 700,
      space: const [2, 4],
    );
    expect(changed.target, 44);
    expect(changed.detailMaxWidth, 700);
    expect(changed.space, const [2, 4]);
    expect(changed.listWidth, AccessMetrics.standard.listWidth);
  });

  testWidgets('an automatic poll keeps the expired notice and its reload', (
    tester,
  ) async {
    var now = DateTime.utc(2030, 1, 1, 12);
    final native = FixtureProviderPlatform();
    await showPage(tester, native, clock: () => now);
    await open(tester, providerId);
    now = now.add(const Duration(seconds: 56));
    core.providerInvalidate();
    await tester.pump(const Duration(milliseconds: 300));
    expect(find.byKey(const Key('review-expired')), findsOneWidget);
    // The next automatic read stays in flight.
    native.heldSession = Completer();
    await tester.pump(const Duration(seconds: 6));
    expect(
      native.commands.where((c) => c['command'] == 'session').length,
      greaterThan(1),
    );
    final expired = find.byKey(const Key('review-expired')).evaluate().length;
    final loading = find
        .text('Loading or finishing the original operation…')
        .evaluate()
        .length;
    // Settle the read before asserting, so a failure leaves Rust idle.
    native.heldSession!.complete(
      encoded({'version': 1, 'state': 'unlocked', 'generation': 1}),
    );
    await tester.pumpAndSettle();
    expect(expired, 1);
    expect(loading, 0);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('a review in flight still reads as loading', (tester) async {
    final native = FixtureProviderPlatform();
    await showPage(tester, native);
    native.heldReview = Completer();
    await tester.ensureVisible(requestRow(providerId));
    await tester.tap(requestRow(providerId));
    await tester.pump();
    final loading = find
        .text('Loading or finishing the original operation…')
        .evaluate()
        .length;
    native.heldReview!.complete(encoded(providerReview()));
    await tester.pumpAndSettle();
    expect(loading, 1);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('suspending the app closes the authorization step', (
    tester,
  ) async {
    await showPage(tester, FixtureProviderPlatform());
    await open(tester, providerId);
    await startAuthorization(tester);
    final session = pageState(tester).reviewSession as ReviewSession;
    expect(session.step(providerId), ReviewStep.authorize);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    await tester.pump();
    expect(session.step(providerId), ReviewStep.review);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pumpAndSettle();
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('a denial never sends or keeps a typed approval password', (
    tester,
  ) async {
    final native = FixtureProviderPlatform();
    await showPage(tester, native);
    await open(tester, providerId);
    final state = pageState(tester);
    final field = state.approvalPassword as TextEditingController;
    field.text = 'synthetic-never-send';
    state.deny();
    await tester.pumpAndSettle();
    expect(field.text, isEmpty);
    expect(decisions(native).single['decision'], 'deny');
    expect(decisions(native).single.containsKey('password'), isFalse);
    expect(jsonEncode(native.commands), isNot(contains('synthetic-never')));
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('one argument reads in the singular', (tester) async {
    await showPage(tester, FixtureProviderPlatform());
    await open(tester, providerId);
    expect(find.text('Arguments (1 separate value)'), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('the provider status keeps its exact value and reads plainly', (
    tester,
  ) async {
    await showPage(tester, FixtureProviderPlatform());
    await open(tester, providerId);
    await tester.ensureVisible(find.byKey(const Key('review-status')));
    expect(reviewFact(tester, 'review-status'), '{"status":"pending"}');
    expect(
      find.descendant(
        of: find.byKey(const Key('review-status')),
        matching: find.text('Reads as: Awaiting your approval'),
      ),
      findsOneWidget,
    );
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('an origin the provider could not authenticate is not '
      'labelled authenticated', (tester) async {
    await showPage(tester, NoOrigin());
    await open(tester, providerId);
    expect(find.text('Authenticated request origin'), findsNothing);
    expect(find.text('Originating device'), findsNothing);
    expect(find.text('Request origin'), findsOneWidget);
    expect(
      reviewFact(tester, 'review-origin'),
      startsWith('Unavailable: no authenticated origin snapshot'),
    );
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('an unreachable provider lists no requests and no unlock', (
    tester,
  ) async {
    await showPage(tester, UnreachableProvider());
    expect(find.byKey(const Key('requests-disconnected')), findsOneWidget);
    expect(find.text('Provider unlocked'), findsNothing);
    expect(find.text('Unlock provider'), findsNothing);
    expect(find.text('Refresh authority and inbox'), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('wide layout: Back follows the sidebar, before the review', (
    tester,
  ) async {
    await showPage(tester, FixtureProviderPlatform());
    await open(tester, providerId);
    final settings = find.byKey(const Key('destination-settings'));
    Focus.of(
      tester.element(
        find.descendant(of: settings, matching: find.byType(Text)).first,
      ),
    ).requestFocus();
    await tester.pump();
    FocusManager.instance.primaryFocus!.nextFocus();
    await tester.pump();
    final back = tester.element(find.byTooltip('Back to requests'));
    var inBack = false;
    FocusManager.instance.primaryFocus!.context!.visitAncestorElements((e) {
      inBack = inBack || e == back;
      return !inBack;
    });
    expect(inBack, isTrue);
    await tester.pumpWidget(const SizedBox.shrink());
  });
}
