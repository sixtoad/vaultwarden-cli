import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:companion_slice/provider/page.dart';
import 'package:companion_slice/provider/review/review_session.dart';
import 'package:companion_slice/src/rust/api/provider.dart' as core;
import 'package:companion_slice/src/rust/frb_generated.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'provider_support.dart';
import 'touch_id_support.dart';

/// Second request of the two-request inbox below.
final secondId = base64Url.encode(List<int>.filled(32, 9)).replaceAll('=', '');

/// Answers each review with the requested ID, so two requests can be
/// reviewed in turn; only [providerId] carries a Touch ID binding.
class TwoRequests extends FixtureProviderPlatform {
  TwoRequests() {
    requestIds = [providerId, secondId];
    approvalBinding = (reply) =>
        reply['review']['id'] == providerId ? binding(reply) : null;
  }
  @override
  Future<Uint8List> send(Uint8List body) async {
    final command = jsonDecode(utf8.decode(body)) as Map<String, dynamic>;
    if (command['command'] == 'review') {
      reviewReply = providerReview()..['review']['id'] = command['request_id'];
    }
    return super.send(body);
  }
}

/// The 200% text-free desktop page with an adjustable clock.
Future<void> showPage(
  WidgetTester tester,
  FixtureProviderPlatform native, {
  FakeKeys? keys,
  DateTime Function()? clock,
}) async {
  tester.view.physicalSize = const Size(1200, 1600);
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  await tester.pumpWidget(
    MaterialApp(
      home: ProviderPage(
        platform: native,
        syntheticBuilder: (_) => const SizedBox(),
        approvalKeys: keys ?? (FakeKeys()..available = false),
        clock: clock,
      ),
    ),
  );
  await tester.pumpAndSettle();
}

Future<void> open(WidgetTester tester, String id) async {
  await tester.ensureVisible(requestRow(id));
  await tester.tap(requestRow(id));
  await tester.pumpAndSettle();
}

Finder get step => find.byKey(const Key('authorization-step'));
Finder get passwordField => find.byKey(const Key('Fresh approval password'));

Future<TextEditingController> typePassword(WidgetTester tester) async {
  await tester.ensureVisible(passwordField);
  await tester.enterText(passwordField, 'synthetic-never-send');
  return tester.widget<TextField>(passwordField).controller!;
}

void main() {
  setUpAll(() async => RustLib.init());
  setUp(resetProvider);

  test('a step belongs to one request ID only', () {
    final session = ReviewSession()..setStep(providerId, ReviewStep.authorize);
    expect(session.step(providerId), ReviewStep.authorize);
    expect(session.step(secondId), ReviewStep.review);
    expect(session.step(''), ReviewStep.review);
    session.setStep('', ReviewStep.deny);
    expect(session.step(''), ReviewStep.review);
    session.closeStep();
    expect(session.step(providerId), ReviewStep.review);
  });

  testWidgets('approval takes two steps; cancelling the step clears it', (
    tester,
  ) async {
    final native = FixtureProviderPlatform();
    await showPage(tester, native);
    await open(tester, providerId);
    expect(find.byType(TextField), findsNothing);
    expect(find.byKey(const Key('approve-touch-id')), findsNothing);
    expect(
      find.text(
        'Password required next · approval applies to this request only',
      ),
      findsOneWidget,
    );
    await startAuthorization(tester);
    expect(step, findsOneWidget);
    expect(find.byKey(const Key('approve-start')), findsNothing);
    final field = await typePassword(tester);
    await tester.ensureVisible(find.byKey(const Key('cancel-authorization')));
    await tester.tap(find.byKey(const Key('cancel-authorization')));
    await tester.pumpAndSettle();
    expect(step, findsNothing);
    expect(field.text, isEmpty, reason: 'leaving the step clears it');
    await startAuthorization(tester);
    expect(tester.widget<TextField>(passwordField).controller!.text, isEmpty);
    expect(decisions(native), isEmpty);
    expect(core.providerSnapshot().canDecide, isTrue);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('Touch ID is the primary action only when it can approve', (
    tester,
  ) async {
    for (final (name, available, bound) in [
      ('can approve', true, true),
      ('no binding', true, false),
      ('no Touch ID', false, true),
    ]) {
      resetProvider();
      final native = FixtureProviderPlatform()
        ..approvalBinding = bound ? binding : null;
      await showPage(tester, native, keys: FakeKeys()..available = available);
      await open(tester, providerId);
      await startAuthorization(tester);
      final touch = find.byKey(const Key('approve-touch-id'));
      final password = find.byKey(const Key('approve-password'));
      if (!available) {
        expect(touch, findsNothing, reason: name);
        expect(tester.widget(password), isA<FilledButton>(), reason: name);
      } else if (bound) {
        expect(tester.widget(touch), isA<FilledButton>(), reason: name);
        expect(tester.widget(password), isA<OutlinedButton>(), reason: name);
      } else {
        expect(tester.widget(touch), isA<OutlinedButton>(), reason: name);
        expect(
          tester.widget<OutlinedButton>(touch).onPressed,
          isNull,
          reason: name,
        );
        expect(tester.widget(password), isA<FilledButton>(), reason: name);
        expect(find.byKey(const Key('touch-id-note')), findsOneWidget);
      }
      await tester.pumpWidget(const SizedBox.shrink());
    }
  });

  testWidgets('selecting another request closes the step and clears it', (
    tester,
  ) async {
    final native = TwoRequests();
    await showPage(tester, native);
    await open(tester, providerId);
    await startAuthorization(tester);
    final field = await typePassword(tester);
    await open(tester, secondId);
    expect(core.providerSnapshot().reviewId, secondId);
    expect(field.text, isEmpty);
    expect(step, findsNothing, reason: 'the step never follows a selection');
    expect(find.byKey(const Key('approve-start')), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('reselecting the same request closes its step', (tester) async {
    final native = TwoRequests();
    await showPage(tester, native);
    await open(tester, providerId);
    await startAuthorization(tester);
    final field = await typePassword(tester);
    await open(tester, providerId);
    expect(core.providerSnapshot().reviewId, providerId);
    expect(field.text, isEmpty);
    expect(step, findsNothing);
    expect(decisions(native), isEmpty);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('a late Touch ID completion is not attributed to the next '
      'request', (tester) async {
    final native = TwoRequests();
    final keys = FakeKeys()..prompt = Completer();
    await showPage(tester, native, keys: keys);
    // A foreground window: the end of the prompt does not suspend.
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await open(tester, providerId);
    await startAuthorization(tester);
    await tester.ensureVisible(find.byKey(const Key('approve-touch-id')));
    await tester.tap(find.byKey(const Key('approve-touch-id')));
    // The fresh review lands; the system prompt stays open.
    await tester.pumpAndSettle();
    await tester.ensureVisible(requestRow(secondId));
    await tester.tap(requestRow(secondId));
    await tester.pump();
    keys.prompt!.complete();
    await tester.pumpAndSettle();
    expect(decisions(native), isEmpty, reason: 'nothing sent for either');
    expect(core.providerSnapshot().reviewId, secondId);
    expect(step, findsNothing);
    expect(find.textContaining('Nothing was sent'), findsWidgets);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('the countdown never re-enables a decision after expiry', (
    tester,
  ) async {
    var now = DateTime.utc(2030, 1, 1, 12);
    await showPage(tester, FixtureProviderPlatform(), clock: () => now);
    await open(tester, providerId);
    expect(find.text('Valid for 55 s'), findsOneWidget);
    await startAuthorization(tester);
    now = now.add(const Duration(seconds: 54, milliseconds: 500));
    await tester.pump(const Duration(milliseconds: 300));
    expect(step, findsOneWidget);
    expect(find.text('Valid for 1 s'), findsOneWidget);
    now = now.add(const Duration(seconds: 1));
    await tester.pump(const Duration(milliseconds: 300));
    expect(find.byKey(const Key('review-expired')), findsOneWidget);
    expect(step, findsNothing);
    expect(find.byKey(const Key('approve-start')), findsNothing);
    expect(find.byKey(const Key('approve-password')), findsNothing);
    // A clock moving backwards does not bring the decision back.
    now = DateTime.utc(2030, 1, 1, 12);
    await tester.pump(const Duration(milliseconds: 300));
    expect(find.byKey(const Key('review-expired')), findsOneWidget);
    expect(find.byKey(const Key('approve-start')), findsNothing);
    // Only a fresh load starts a new countdown.
    now = now.add(const Duration(minutes: 5));
    await tester.ensureVisible(find.byKey(const Key('reload-review')));
    await tester.tap(find.byKey(const Key('reload-review')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('review-expired')), findsNothing);
    expect(find.text('Valid for 55 s'), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('the request deadline bounds the countdown below 55 s', (
    tester,
  ) async {
    // The fixture request expires at Unix 2000000000 (2033-05-18 03:33:20).
    var now = DateTime.fromMillisecondsSinceEpoch(
      (2000000000 - 20) * 1000,
      isUtc: true,
    );
    await showPage(tester, FixtureProviderPlatform(), clock: () => now);
    await open(tester, providerId);
    expect(find.text('Valid for 20 s'), findsOneWidget);
    expect(find.text('2033-05-18 03:33:20 UTC'), findsOneWidget);
    now = now.add(const Duration(seconds: 20));
    await tester.pump(const Duration(milliseconds: 300));
    expect(find.byKey(const Key('review-expired')), findsOneWidget);
    expect(find.byKey(const Key('approve-start')), findsNothing);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('denial is confirmed and carries no password', (tester) async {
    final native = FixtureProviderPlatform();
    await showPage(tester, native);
    await open(tester, providerId);
    await tester.ensureVisible(find.byKey(const Key('deny-start')));
    await tester.tap(find.byKey(const Key('deny-start')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('deny-confirm')), findsOneWidget);
    expect(find.byType(TextField), findsNothing);
    await tester.ensureVisible(find.byKey(const Key('keep-reviewing')));
    await tester.tap(find.byKey(const Key('keep-reviewing')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('deny-confirm')), findsNothing);
    expect(decisions(native), isEmpty);
    await denyRequest(tester);
    expect(decisions(native).single['decision'], 'deny');
    expect(decisions(native).single.containsKey('password'), isFalse);
    expect(find.byKey(const Key('latest-status')), findsOneWidget);
    expect(find.text('Denied'), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('an approval shows the latest status as not completed', (
    tester,
  ) async {
    final native = FixtureProviderPlatform();
    await showPage(tester, native);
    await open(tester, providerId);
    await startAuthorization(tester);
    await typePassword(tester);
    await tester.ensureVisible(find.byKey(const Key('approve-password')));
    await tester.tap(find.byKey(const Key('approve-password')));
    await tester.pumpAndSettle();
    expect(decisions(native).single['decision'], 'approve');
    expect(find.text('Approved · not completed'), findsOneWidget);
    expect(find.textContaining('Do not approve again'), findsOneWidget);
    expect(find.textContaining('Completed'), findsNothing);
    await tester.pumpWidget(const SizedBox.shrink());
  });
}
