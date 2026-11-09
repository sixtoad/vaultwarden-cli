import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:companion_slice/platform/approval_key.dart';
import 'package:companion_slice/provider/controller.dart';
import 'package:companion_slice/provider/page.dart';
import 'package:companion_slice/provider/touch_id.dart';
import 'package:companion_slice/src/rust/frb_generated.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'provider_support.dart';
import 'touch_id_support.dart';

/// Review round 1 of the Touch ID approval screens (issue 49, PR D).
void main() {
  setUpAll(() async => RustLib.init());
  setUp(resetProvider);

  group(
    'enrollment never reuses a key the provider does not hold as current',
    () {
      Future<(KeyFixture, FakeKeys, ProviderController, TouchIdController)>
      enrolled({
        String? providerKey,
        KeyOutcome local = KeyOutcome.present,
      }) async {
        final g = golden['enroll'] as Map<String, dynamic>;
        final native = KeyFixture(
          g,
          golden['approval']['provider_identity'] as String,
          golden['approval']['approval_client'] as String,
        )..keyId = providerKey;
        final keys = FakeKeys()
          ..presentOutcome = local
          ..signature = b64(g['signature'] as String);
        final controller = ProviderController(native);
        await controller.initialize();
        final touchId = TouchIdController(controller, keys);
        await touchId.refreshLocal();
        return (native, keys, controller, touchId);
      }

      List<Map<String, dynamic>> enrolls(KeyFixture n) =>
          n.commands.where((c) => c['command'] == 'biometric_enroll').toList();

      for (final (name, providerKey, local) in [
        (
          'provider not enrolled (lost revoke response)',
          null,
          KeyOutcome.present,
        ),
        (
          'provider retired it (another current key)',
          'e' * 64,
          KeyOutcome.present,
        ),
        (
          'a fingerprint change invalidated it',
          goldenKeyId,
          KeyOutcome.invalidated,
        ),
      ]) {
        test(name, () async {
          final (native, keys, controller, touchId) = await enrolled(
            providerKey: providerKey,
            local: local,
          );
          await touchId.enroll('fresh');
          expect(
            keys.deleted,
            hasLength(1),
            reason: 'the stale key is deleted',
          );
          expect(keys.created, hasLength(1), reason: 'a fresh key replaces it');
          expect(keys.signed.single.$1, KeyPurpose.enroll);
          expect(enrolls(native), hasLength(1));
          expect(controller.keys.keyId, goldenKeyId);
          expect(touchId.local, KeyOutcome.present);
          touchId.dispose();
          controller.dispose();
        });
      }

      test(
        'a usable key the provider holds as current is kept; nothing is sent',
        () async {
          final (native, keys, controller, touchId) = await enrolled(
            providerKey: goldenKeyId,
          );
          await touchId.enroll('fresh');
          expect(keys.deleted, isEmpty);
          expect(keys.created, isEmpty);
          expect(keys.signed, isEmpty);
          expect(enrolls(native), isEmpty);
          expect(touchId.message, contains('already'));
          touchId.dispose();
          controller.dispose();
        },
      );
    },
  );

  group('a signature is never silently discarded', () {
    test(
      'a poll firing while the prompt is open does not break approval',
      () async {
        final native = FixtureProviderPlatform()..approvalBinding = binding;
        final keys = FakeKeys()..prompt = Completer();
        final (provider, touchId) = await reviewed(native, keys);
        final approving = touchId.approve();
        await pumpEventQueue();
        expect(touchId.prompting, isTrue);
        // The poll timer fires; its exchange is still in flight when the
        // prompt returns.
        native.heldSession = Completer();
        final polling = provider.refresh(automatic: true);
        await pumpEventQueue();
        keys.prompt!.complete();
        await pumpEventQueue();
        native.heldSession!.complete(
          encoded({'version': 1, 'state': 'unlocked', 'generation': 1}),
        );
        await approving;
        await polling;
        expect(decisions(native), hasLength(1));
        expect(touchId.message, 'Approved once with Touch ID.');
        touchId.dispose();
        provider.dispose();
      },
    );

    test('selecting another request during the prompt cancels it and sends nothing', () async {
      final native = FixtureProviderPlatform()..approvalBinding = binding;
      final keys = FakeKeys()..prompt = Completer();
      final (provider, touchId) = await reviewed(native, keys);
      final approving = touchId.approve();
      await pumpEventQueue();
      final other = providerReview();
      other['review']['id'] = 'B' * 43;
      native.reviewReply = other;
      await provider.review('B' * 43); // the user selected another request
      expect(keys.cancelled, hasLength(1), reason: 'the prompt is cancelled');
      keys.prompt!.complete();
      await approving;
      expect(decisions(native), isEmpty);
      expect(touchId.message, contains('Nothing was sent; try again.'));
      touchId.dispose();
      provider.dispose();
    });

    test(
      'a review invalidated during the prompt sends nothing and says so',
      () async {
        final native = FixtureProviderPlatform()..approvalBinding = binding;
        final keys = FakeKeys()..prompt = Completer();
        final (provider, touchId) = await reviewed(native, keys);
        final approving = touchId.approve();
        await pumpEventQueue();
        provider.invalidate();
        keys.prompt!.complete();
        await approving;
        expect(decisions(native), isEmpty);
        expect(touchId.message, contains('Nothing was sent; try again.'));
        touchId.dispose();
        provider.dispose();
      },
    );
  });

  test('a changed authenticated origin is never signed', () async {
    final native = OriginFixture()..approvalBinding = binding;
    final keys = FakeKeys();
    final (provider, touchId) = await reviewed(native, keys);
    expect(provider.management.originText, contains('agent one'));
    native.label = 'agent two';
    await touchId.approve();
    expect(keys.signed, isEmpty);
    expect(decisions(native), isEmpty);
    expect(touchId.message, contains('changed or is no longer pending'));
    touchId.dispose();
    provider.dispose();
  });

  Future<void> openReview(WidgetTester tester) async {
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.text('Review $providerId'));
    await tester.tap(find.text('Review $providerId'));
    await tester.pumpAndSettle();
  }

  Widget page(FixtureProviderPlatform native, FakeKeys keys) => MaterialApp(
    home: ProviderPage(
      platform: native,
      syntheticBuilder: (_) => const SizedBox(),
      approvalKeys: keys,
    ),
  );

  for (final status in <Map<String, dynamic>>[
    {'status': 'expired'},
    {'status': 'approved'},
    {'status': 'denied'},
    {'status': 'failed', 'reason': 'execution_rejected'},
  ]) {
    testWidgets(
      'a final ${status['status']} request shows no approval controls',
      (tester) async {
        final reply = providerReview();
        reply['ticket'] = null;
        reply['review']['status'] = status;
        final native = FixtureProviderPlatform()..reviewReply = reply;
        await tester.pumpWidget(page(native, FakeKeys()));
        await openReview(tester);
        expect(find.byKey(const Key('review-final')), findsOneWidget);
        expect(find.byType(TextField), findsNothing);
        expect(find.byKey(const Key('approve-touch-id')), findsNothing);
        expect(find.text('Approve once with password'), findsNothing);
        expect(find.text('Deny without password'), findsNothing);
        expect(find.textContaining('expires within 55 seconds'), findsNothing);
        expect(find.text('Back to requests'), findsOneWidget);
        await tester.pumpWidget(const SizedBox.shrink());
      },
    );
  }

  group('lifecycle around the Touch ID prompt', () {
    int sessions(FixtureProviderPlatform n) => n.commands.length;

    void lifecycle(WidgetTester tester, List<AppLifecycleState> states) {
      for (final s in states) {
        tester.binding.handleAppLifecycleStateChanged(s);
      }
    }

    testWidgets('hiding and returning during the prompt resumes afterwards', (
      tester,
    ) async {
      final native = FixtureProviderPlatform()..approvalBinding = binding;
      final keys = FakeKeys()..prompt = Completer();
      await tester.pumpWidget(page(native, keys));
      await openReview(tester);
      await tester.ensureVisible(find.byKey(const Key('approve-touch-id')));
      await tester.tap(find.byKey(const Key('approve-touch-id')));
      await tester.pump();
      lifecycle(tester, [AppLifecycleState.inactive, AppLifecycleState.hidden]);
      expect(keys.cancelled, hasLength(1), reason: 'hiding cancels the prompt');
      lifecycle(tester, [
        AppLifecycleState.inactive,
        AppLifecycleState.resumed,
      ]);
      final before = sessions(native);
      keys.prompt!.complete();
      await tester.pump();
      await tester.pump();
      expect(
        decisions(native),
        isEmpty,
        reason: 'the hidden review was dropped',
      );
      expect(find.textContaining('Nothing was sent'), findsWidgets);
      await tester.pump(const Duration(seconds: 1));
      await tester.pumpAndSettle();
      expect(
        sessions(native),
        greaterThan(before),
        reason: 'resumed afterwards',
      );
      await tester.pumpWidget(const SizedBox.shrink());
    });

    testWidgets('switching away during the prompt suspends when it ends', (
      tester,
    ) async {
      final native = FixtureProviderPlatform()..approvalBinding = binding;
      final keys = FakeKeys()..prompt = Completer();
      await tester.pumpWidget(page(native, keys));
      await openReview(tester);
      await tester.ensureVisible(find.byKey(const Key('approve-touch-id')));
      await tester.tap(find.byKey(const Key('approve-touch-id')));
      await tester.pump();
      lifecycle(tester, [AppLifecycleState.inactive]);
      keys.prompt!.complete();
      await tester.pumpAndSettle();
      final before = sessions(native);
      await tester.pump(const Duration(seconds: 40));
      await tester.pumpAndSettle();
      expect(sessions(native), before, reason: 'suspended: no polling');
      lifecycle(tester, [AppLifecycleState.resumed]);
      await tester.pumpAndSettle();
      expect(sessions(native), greaterThan(before));
      await tester.pumpWidget(const SizedBox.shrink());
    });
  });

  testWidgets('Touch ID availability is checked again on resume', (
    tester,
  ) async {
    final native = FixtureProviderPlatform()..approvalBinding = binding;
    final keys = FakeKeys()..available = false;
    await tester.pumpWidget(page(native, keys));
    await tester.pumpAndSettle();
    keys.available = true;
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await openReview(tester);
    expect(find.byKey(const Key('approve-touch-id')), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('the local key state is read even when initialization fails', (
    tester,
  ) async {
    final keys = FakeKeys();
    await tester.pumpWidget(page(ThrowingInitialization(), keys));
    await tester.pumpAndSettle();
    expect(tester.takeException(), isStateError);
    expect(keys.availabilityChecks, greaterThan(0));
    await tester.pumpWidget(const SizedBox.shrink());
  });
}

/// Answers `request_origin` with an authenticated requester-agent binding
/// whose label the test can change between reviews.
class OriginFixture extends FixtureProviderPlatform {
  String label = 'agent one';
  @override
  Future<Uint8List> send(Uint8List body) async {
    final command = jsonDecode(utf8.decode(body)) as Map<String, dynamic>;
    if (command['command'] != 'request_origin') return super.send(body);
    commands.add(command);
    return encoded({
      'version': 2,
      'request_id': command['request_id'],
      'origin': {
        'kind': 'requester_agent',
        'binding_id': 'C' * 43,
        'label': label,
        'fingerprint': 'f' * 64,
        'evidence': 'signed_os_binding',
      },
    });
  }
}

class ThrowingInitialization extends FixtureProviderPlatform {
  @override
  void Function() onInvalidation(void Function() callback) =>
      throw StateError('Synthetic initialization failure');
}
