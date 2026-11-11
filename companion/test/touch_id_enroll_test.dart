import 'dart:typed_data';

import 'package:companion_slice/platform/approval_key.dart';
import 'package:companion_slice/provider/controller.dart';
import 'package:companion_slice/provider/touch_id.dart';
import 'package:companion_slice/provider/touch_id_views.dart';
import 'package:companion_slice/src/rust/frb_generated.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'provider_support.dart';
import 'touch_id_support.dart';

/// Enrollment never deletes a local key it cannot identify, and an
/// unreadable local key is replaced only after an explicit confirmation
/// (review round 2, L1 and L3).
void main() {
  setUpAll(() async => RustLib.init());
  setUp(resetProvider);

  final g = golden['enroll'] as Map<String, dynamic>;
  final providerPin = golden['approval']['provider_identity'] as String;
  final client = golden['approval']['approval_client'] as String;

  Future<(KeyFixture, FakeKeys, ProviderController, TouchIdController)> setup(
    void Function(KeyFixture, FakeKeys) arrange,
  ) async {
    final native = KeyFixture(g, providerPin, client);
    final keys = FakeKeys()..signature = b64(g['signature'] as String);
    arrange(native, keys);
    final controller = ProviderController(native);
    await controller.initialize();
    final touchId = TouchIdController(controller, keys);
    await touchId.refreshLocal();
    return (native, keys, controller, touchId);
  }

  List<Map<String, dynamic>> enrolls(KeyFixture n) =>
      n.commands.where((c) => c['command'] == 'biometric_enroll').toList();

  test('a local key whose id cannot be computed is never deleted', () async {
    final (native, keys, controller, touchId) = await setup((n, k) {
      n.keyId = goldenKeyId; // the provider holds a current key
      k.readKey = Uint8List(10); // the id of this key cannot be computed
    });
    await touchId.enroll('fresh');
    expect(keys.deleted, isEmpty, reason: 'unknown id: never delete');
    expect(keys.created, isEmpty);
    expect(keys.signed, isEmpty);
    expect(enrolls(native), isEmpty);
    expect(touchId.message, contains('Nothing was sent; try again'));
    touchId.dispose();
    controller.dispose();
  });

  for (final outcome in [KeyOutcome.unsafe, KeyOutcome.failed]) {
    test(
      'an unreadable ($outcome) key is replaced only when confirmed',
      () async {
        final (native, keys, controller, touchId) = await setup(
          (n, k) => k.readOutcome = outcome,
        );
        expect(touchId.local, outcome);
        expect(touchId.localUnreadable, isTrue);
        await touchId.enroll('fresh');
        expect(keys.deleted, isEmpty, reason: 'no confirmation: no delete');
        expect(keys.created, isEmpty);
        expect(enrolls(native), isEmpty);
        expect(touchId.message, contains('Replace'));
        expect(touchId.message, contains('Nothing was sent'));
        await touchId.enroll('fresh', replaceUnreadable: true);
        expect(keys.deleted, hasLength(1));
        expect(keys.created, hasLength(1));
        expect(enrolls(native), hasLength(1));
        expect(touchId.local, KeyOutcome.present);
        expect(touchId.localUnreadable, isFalse);
        touchId.dispose();
        controller.dispose();
      },
    );
  }

  testWidgets('the key panel asks before replacing an unreadable key', (
    tester,
  ) async {
    late final FakeKeys keys;
    late final ProviderController controller;
    late final TouchIdController touchId;
    await tester.runAsync(() async {
      final r = await setup((n, k) => k.readOutcome = KeyOutcome.unsafe);
      (keys, controller, touchId) = (r.$2, r.$3, r.$4);
    });
    final password = TextEditingController();
    Widget panel() => MaterialApp(
      home: Scaffold(
        body: SingleChildScrollView(
          child: ListenableBuilder(
            listenable: touchId,
            builder: (_, _) => TouchIdKeyPanel(
              touchId: touchId,
              keys: controller.keys,
              password: password,
              enabled: true,
            ),
          ),
        ),
      ),
    );
    await tester.pumpWidget(panel());
    expect(find.textContaining('could not be read'), findsOneWidget);
    expect(find.text('Replace key and enroll'), findsOneWidget);
    password.text = 'fresh';
    await tester.tap(find.byKey(const Key('touch-id-enroll')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('touch-id-replace-confirm')), findsOneWidget);
    await tester.tap(find.text('Cancel'));
    await tester.pumpAndSettle();
    expect(keys.deleted, isEmpty, reason: 'declined: nothing deleted');
    expect(password.text, 'fresh', reason: 'declined: password kept');
    await tester.tap(find.byKey(const Key('touch-id-enroll')));
    await tester.pumpAndSettle();
    await tester.runAsync(() async {
      await tester.tap(find.byKey(const Key('touch-id-replace-confirm')));
      await Future<void>.delayed(const Duration(milliseconds: 200));
    });
    await tester.pumpAndSettle();
    expect(keys.deleted, hasLength(1));
    expect(keys.created, hasLength(1));
    await tester.pumpWidget(const SizedBox.shrink());
    touchId.dispose();
    controller.dispose();
    password.dispose();
  });
}
