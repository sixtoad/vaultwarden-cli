import 'package:companion_slice/src/rust/frb_generated.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'provider_support.dart';
import 'review_authorization_test.dart' show open, showPage, typePassword;
import 'touch_id_support.dart' show decisions;

/// A provider review of a protected update (issue 48 phase 2).
Map<String, dynamic> updateReview() {
  final reply = providerReview();
  final review = Map<String, dynamic>.of(
    reply['review'] as Map<String, dynamic>,
  );
  review['effect'] = 'UPDATE personal vault item (no create)';
  review['target'] = 'homelab/production/github/token';
  review['update'] = {
    'server': 'https://vault.example',
    'item_id': '33333333-3333-3333-3333-333333333333',
    'destination': {
      'account_id': '11111111-1111-1111-1111-111111111111',
      'folder': 'homelab/production',
      'folder_id': '22222222-2222-2222-2222-222222222222',
      'reference': 'homelab/production/github/token',
    },
    'fields': ['password', 'custom:api-key'],
    'expected_revision': '2026-11-21T10:00:00.000000Z',
  };
  return {...reply, 'review': review};
}

void main() {
  setUpAll(() async => RustLib.init());
  setUp(resetProvider);

  testWidgets('an update review shows its item, binding, fields and revision', (
    tester,
  ) async {
    final native = FixtureProviderPlatform()..reviewReply = updateReview();
    await showPage(tester, native);
    await open(tester, providerId);
    expect(find.byKey(const Key('review-update')), findsOneWidget);
    for (final (key, value) in [
      ('review-update-item', '"33333333-3333-3333-3333-333333333333"'),
      ('review-update-account', '"11111111-1111-1111-1111-111111111111"'),
      ('review-update-folder', '"homelab/production"'),
      ('review-update-reference', '"homelab/production/github/token"'),
      ('review-update-field-0', '"password"'),
      ('review-update-field-1', '"custom:api-key"'),
      ('review-update-revision', '"2026-11-21T10:00:00.000000Z"'),
    ]) {
      final text = key.startsWith('review-update-field-')
          ? tester.widget<SelectableText>(find.byKey(Key(key))).data
          : reviewFact(tester, key);
      expect(text, value, reason: key);
    }
    expect(find.text('Fields replaced (2)'), findsOneWidget);
    expect(find.textContaining('"https://vault.example"'), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('other reviews show no update block', (tester) async {
    final native = FixtureProviderPlatform();
    await showPage(tester, native);
    await open(tester, providerId);
    expect(find.byKey(const Key('review-update')), findsNothing);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('approving an update asserts the update-review capability', (
    tester,
  ) async {
    final native = FixtureProviderPlatform()..reviewReply = updateReview();
    await showPage(tester, native);
    await open(tester, providerId);
    await startAuthorization(tester);
    await typePassword(tester);
    await tester.ensureVisible(find.byKey(const Key('approve-password')));
    await tester.tap(find.byKey(const Key('approve-password')));
    await tester.pumpAndSettle();
    final decision = decisions(native).single;
    expect(decision['decision'], 'approve');
    expect(decision['version'], 2);
    expect(decision['capabilities'], ['update-review.v1']);
    await tester.pumpWidget(const SizedBox.shrink());
  });
}
