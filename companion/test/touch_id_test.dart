import 'package:companion_slice/platform/approval_key.dart';
import 'package:companion_slice/provider/controller.dart';
import 'package:companion_slice/provider/page.dart';
import 'package:companion_slice/provider/touch_id.dart';
import 'package:companion_slice/src/rust/api/biometric.dart' as bio;
import 'package:companion_slice/src/rust/frb_generated.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'provider_support.dart';
import 'touch_id_support.dart';

void main() {
  setUpAll(() async => RustLib.init());
  setUp(resetProvider);

  test('Touch ID approves once after a fresh identical review', () async {
    final native = FixtureProviderPlatform()..approvalBinding = binding;
    final keys = FakeKeys();
    final (provider, touchId) = await reviewed(native, keys);
    expect(
      native.commands.firstWhere((c) => c['command'] == 'review')['version'],
      2,
    );
    expect(touchId.canApprove, isTrue);
    expect(touchId.unavailableReason, isEmpty);
    final reviewsBefore = native.commands
        .where((c) => c['command'] == 'review')
        .length;
    await touchId.approve();
    expect(
      native.commands.where((c) => c['command'] == 'review').length,
      reviewsBefore + 1,
      reason: 'fresh state is fetched before signing',
    );
    expect(keys.signed.single.$1, KeyPurpose.approve);
    expect(
      prefix(keys.signed.single.$2),
      'dev.vaultwarden.provider.approval.v2',
    );
    final decision = decisions(native).single;
    expect(decision['version'], 2);
    expect(decision['decision'], 'approve');
    expect(decision.containsKey('password'), isFalse);
    expect(decision['proof']['key_id'], goldenKeyId);
    expect(touchId.message, 'Approved once with Touch ID.');
    expect(
      bio.providerBiometricState().result,
      bio.BiometricDecisionResult.approved,
    );
    expect(touchId.canApprove, isFalse, reason: 'one approval per request');
    touchId.dispose();
    provider.dispose();
  });

  test('cancelled, unavailable or refused signing sends nothing', () async {
    for (final outcome in [
      KeyOutcome.cancelled,
      KeyOutcome.unavailable,
      KeyOutcome.refused,
      KeyOutcome.failed,
    ]) {
      resetProvider();
      final native = FixtureProviderPlatform()..approvalBinding = binding;
      final keys = FakeKeys()..signOutcome = outcome;
      final (provider, touchId) = await reviewed(native, keys);
      await touchId.approve();
      expect(keys.signed, hasLength(1), reason: '$outcome');
      expect(decisions(native), isEmpty, reason: '$outcome');
      expect(touchId.message, contains('Nothing was sent'), reason: '$outcome');
      // The password path stays available on the same fresh review.
      expect(provider.state.canDecide, isTrue, reason: '$outcome');
      touchId.dispose();
      provider.dispose();
    }
  });

  test('a review that changed before signing is never signed', () async {
    final native = FixtureProviderPlatform()..approvalBinding = binding;
    final keys = FakeKeys();
    final (provider, touchId) = await reviewed(native, keys);
    final changed = providerReview();
    changed['review']['target'] = 'production';
    native.reviewReply = changed;
    await touchId.approve();
    expect(keys.signed, isEmpty);
    expect(decisions(native), isEmpty);
    expect(touchId.message, contains('changed or is no longer pending'));
    touchId.dispose();
    provider.dispose();
  });

  test(
    'no enrolled key, password policy or no binding fall back to password',
    () async {
      for (final (name, make) in [
        ('none', (Map<String, dynamic> r) => binding(r, allowed: false)),
        ('null', (Map<String, dynamic> r) => null),
      ]) {
        resetProvider();
        final native = FixtureProviderPlatform()..approvalBinding = make;
        final keys = FakeKeys();
        final (provider, touchId) = await reviewed(native, keys);
        expect(touchId.canApprove, isFalse, reason: name);
        expect(touchId.unavailableReason, contains('password'), reason: name);
        await touchId.approve();
        expect(keys.signed, isEmpty, reason: name);
        expect(provider.state.canDecide, isTrue, reason: name);
        touchId.dispose();
        provider.dispose();
      }
      resetProvider();
      final native = FixtureProviderPlatform()..approvalBinding = binding;
      final (provider, touchId) = await reviewed(
        native,
        FakeKeys()..available = false,
      );
      expect(touchId.canApprove, isFalse);
      expect(touchId.unavailableReason, contains('unavailable on this Mac'));
      touchId.dispose();
      provider.dispose();
    },
  );

  test('provider refusals end in honest final states', () async {
    for (final (error, text) in [
      ('stale', 'expired or changed'),
      ('authentication_failed', 'Approve with your password'),
      ('rate_limited', 'Too many attempts'),
      ('invalid_request', 'request is final'),
    ]) {
      resetProvider();
      final native = FixtureProviderPlatform()
        ..approvalBinding = binding
        ..decisionError = error;
      final (provider, touchId) = await reviewed(native, FakeKeys());
      await touchId.approve();
      expect(decisions(native), hasLength(1), reason: error);
      expect(touchId.message, contains(text), reason: error);
      expect(touchId.canApprove, isFalse, reason: error);
      touchId.dispose();
      provider.dispose();
    }
  });

  test('enrollment proves possession after Touch ID and revocation deletes after confirmation', () async {
    final g = golden['enroll'] as Map<String, dynamic>;
    final provider = golden['approval']['provider_identity'] as String;
    final client = golden['approval']['approval_client'] as String;
    final native = KeyFixture(g, provider, client);
    final keys = FakeKeys()
      ..present = false
      ..signature = b64(g['signature'] as String);
    final controller = ProviderController(native);
    await controller.initialize();
    expect(controller.keys.configured, isTrue);
    final touchId = TouchIdController(controller, keys);
    await touchId.refreshLocal();
    await touchId.enroll('fresh');
    expect(keys.created, hasLength(1));
    expect(keys.signed.single.$1, KeyPurpose.enroll);
    expect(
      prefix(keys.signed.single.$2),
      'dev.vaultwarden.provider.approval-enroll.v2',
    );
    final sent = native.commands
        .where((c) => c['command'] == 'biometric_enroll')
        .single;
    expect(sent['password'], 'fresh');
    expect(sent['enroll_signature'], g['signature']);
    expect(controller.keys.state, bio.BiometricKeyState.enrolled);
    expect(controller.keys.keyId, goldenKeyId);
    expect(touchId.local, KeyOutcome.present);
    // Revocation that the provider does not confirm keeps the local key.
    native.loseRevoke = true;
    await touchId.revoke('fresh');
    expect(keys.deleted, isEmpty);
    native.loseRevoke = false;
    await touchId.revoke('fresh');
    expect(keys.deleted, hasLength(1));
    expect(controller.keys.state, bio.BiometricKeyState.notEnrolled);
    touchId.dispose();
    controller.dispose();
  });

  testWidgets('review shows Touch ID only on a Touch ID Mac and final states', (
    tester,
  ) async {
    for (final available in [true, false]) {
      resetProvider();
      final native = FixtureProviderPlatform()..approvalBinding = binding;
      await tester.pumpWidget(
        MaterialApp(
          home: ProviderPage(
            platform: native,
            syntheticBuilder: (_) => const SizedBox(),
            approvalKeys: FakeKeys()..available = available,
          ),
        ),
      );
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.text('Review $providerId'));
      await tester.tap(find.text('Review $providerId'));
      await tester.pumpAndSettle();
      final button = find.byKey(const Key('approve-touch-id'));
      expect(button, available ? findsOneWidget : findsNothing);
      expect(find.text('Approve once with password'), findsOneWidget);
      if (available) {
        await tester.ensureVisible(button);
        await tester.tap(button);
        await tester.pumpAndSettle();
        expect(find.text('Approved once with Touch ID.'), findsOneWidget);
        expect(decisions(native).single['proof'], isNotNull);
      }
      await tester.pumpWidget(const SizedBox.shrink());
    }
    resetProvider();
    final expired = providerReview();
    expired['ticket'] = null;
    expired['review']['status'] = {'status': 'expired'};
    final native = FixtureProviderPlatform()..reviewReply = expired;
    await tester.pumpWidget(
      MaterialApp(
        home: ProviderPage(
          platform: native,
          syntheticBuilder: (_) => const SizedBox(),
          approvalKeys: FakeKeys(),
        ),
      ),
    );
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.text('Review $providerId'));
    await tester.tap(find.text('Review $providerId'));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('review-final')), findsOneWidget);
    // A final request shows its state only (review round 1, #61).
    expect(find.byKey(const Key('approve-touch-id')), findsNothing);
    await tester.pumpWidget(const SizedBox.shrink());
  });
}
