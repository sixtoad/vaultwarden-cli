import 'dart:async';

import 'package:companion_slice/platform/approval_client.dart';
import 'package:companion_slice/platform/approval_key.dart';
import 'package:companion_slice/provider/page.dart';
import 'package:companion_slice/src/rust/frb_generated.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'installation_settings_test.dart' show FakeInstallation;
import 'provider_support.dart';
import 'touch_id_support.dart';

const secondId = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';
const thirdId = 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC';

/// A key that also reports which verification it uses, as the native one.
class VerifyingKeys extends FakeKeys implements UserVerificationPlatform {
  VerifyingKeys(this.kind);
  UserVerification kind;
  @override
  Future<UserVerification> verification() async =>
      available ? kind : UserVerification.unavailable;
}

/// What each system's key reports in these tests, and how it is named.
const kinds = {
  'macos': (UserVerification.touchId, 'Touch ID'),
  'android': (UserVerification.biometric, 'biometrics'),
  'ios': (UserVerification.faceId, 'Face ID'),
};

class FakeSignals implements DeviceSignalPlatform {
  void Function(DeviceSignal)? callback;
  @override
  bool get available => true;
  @override
  void Function() listen(void Function(DeviceSignal signal) onSignal) {
    callback = onSignal;
    return () => callback = null;
  }
}

/// Lifecycle safety shared by every approval client (#60): backgrounding,
/// locking or an app switch never approves the wrong request.
void main() {
  setUpAll(() async => RustLib.init());
  setUp(resetProvider);

  test(
    'a late signature is never sent after the same request was reopened',
    () async {
      final native = FixtureProviderPlatform()..approvalBinding = binding;
      final keys = FakeKeys()..prompt = Completer();
      final (provider, touchId) = await reviewed(native, keys);
      final approving = touchId.approve();
      await pumpEventQueue();
      provider.invalidate(); // background, lock or navigation retired it
      await provider.review(providerId); // the user reopened the same request
      expect(provider.state.reviewId, providerId);
      keys.prompt!.complete(); // the platform ignored the cancel
      await approving;
      expect(decisions(native), isEmpty);
      touchId.dispose();
      provider.dispose();
    },
  );

  // The Dart gate alone (#60): the review is unchanged, so Rust would accept
  // the prepared handle and the provider fake would record a decision.
  test(
    'a retired attempt sends nothing although the review is unchanged',
    () async {
      final native = FixtureProviderPlatform()..approvalBinding = binding;
      final keys = FakeKeys()..prompt = Completer();
      final (provider, touchId) = await reviewed(native, keys);
      final approving = touchId.approve();
      await pumpEventQueue();
      expect(keys.signed, hasLength(1), reason: 'the prompt is open');
      await touchId.retire(); // background, lock or interruption
      expect(provider.state.reviewId, providerId, reason: 'review unchanged');
      final sent = native.commands.length;
      keys.prompt!.complete(); // the platform ignored the cancel
      await approving;
      expect(native.commands, hasLength(sent), reason: 'nothing was performed');
      expect(decisions(native), isEmpty);
      expect(touchId.message, touchId.notSent);
      touchId.dispose();
      provider.dispose();
    },
  );

  test(
    'a retirement while the fresh review loads never opens the prompt',
    () async {
      final native = FixtureProviderPlatform()..approvalBinding = binding;
      final keys = FakeKeys();
      final (provider, touchId) = await reviewed(native, keys);
      native.heldReview = Completer();
      final approving = touchId.approve();
      await pumpEventQueue();
      await touchId.retire();
      final reply = Map<String, dynamic>.of(providerReview())..['version'] = 2;
      reply['approval_binding'] = binding(reply);
      native.heldReview!.complete(encoded(reply)); // the same review again
      await approving;
      expect(provider.state.reviewId, providerId);
      expect(keys.signed, isEmpty, reason: 'no prompt after a retirement');
      expect(decisions(native), isEmpty);
      touchId.dispose();
      provider.dispose();
    },
  );

  Widget page(
    FixtureProviderPlatform native,
    FakeKeys keys, {
    String? os,
    FakeSignals? signals,
  }) => MaterialApp(
    home: ProviderPage(
      platform: native,
      syntheticBuilder: (_) => const SizedBox(),
      approvalKeys: keys,
      operatingSystem: os,
      deviceSignals: signals,
      installation: FakeInstallation(),
    ),
  );

  Future<void> open(WidgetTester tester, String id) async {
    await tester.pumpAndSettle();
    await tester.ensureVisible(requestRow(id));
    await tester.tap(requestRow(id));
    await tester.pumpAndSettle();
  }

  Future<void> touchIdTap(WidgetTester tester) async {
    await startAuthorization(tester);
    await tester.ensureVisible(find.byKey(const Key('approve-touch-id')));
    await tester.tap(find.byKey(const Key('approve-touch-id')));
    await tester.pump();
  }

  void wide(WidgetTester tester) {
    tester.view.physicalSize = const Size(1600, 1200);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.reset);
  }

  Map<String, dynamic> reviewOf(String id) {
    final reply = providerReview();
    reply['review']['id'] = id;
    return reply;
  }

  for (final os in ['macos', 'android', 'ios']) {
    group('on $os', () {
      testWidgets('a Touch ID result is never presented as another request', (
        tester,
      ) async {
        wide(tester);
        final native = FixtureProviderPlatform()
          ..approvalBinding = binding
          ..requestIds = [providerId, secondId, thirdId];
        final (kind, name) = kinds[os]!;
        final keys = VerifyingKeys(kind);
        // Foreground, so the page resumes once the approval ends and the
        // next requests' reviews really load.
        tester.binding.handleAppLifecycleStateChanged(
          AppLifecycleState.resumed,
        );
        await tester.pumpWidget(page(native, keys, os: os));
        await open(tester, providerId);
        await touchIdTap(tester);
        await tester.pumpAndSettle();
        final approved = 'Approved once with $name.';
        expect(find.text(approved), findsOneWidget);
        native.reviewReply = reviewOf(secondId);
        await open(tester, secondId);
        expect(find.text(approved), findsNothing);
        expect(
          find.text('Earlier request ("deploy", AAAAAAAA…): $approved'),
          findsOneWidget,
          reason: 'its operation and the start of its id, as the list shows',
        );
        // Shown once, with the first other review: the next load clears it.
        native.reviewReply = reviewOf(thirdId);
        await open(tester, thirdId);
        expect(find.textContaining('Earlier request'), findsNothing);
        expect(find.textContaining(approved), findsNothing);
        await tester.pumpWidget(const SizedBox.shrink());
      });

      testWidgets('a late completion names its own request, never the next', (
        tester,
      ) async {
        wide(tester);
        final native = FixtureProviderPlatform()
          ..approvalBinding = binding
          ..requestIds = [providerId, secondId];
        final keys = FakeKeys()..prompt = Completer();
        await tester.pumpWidget(page(native, keys, os: os));
        await open(tester, providerId);
        await touchIdTap(tester);
        native.reviewReply = reviewOf(secondId);
        await open(tester, secondId);
        expect(keys.cancelled, hasLength(1), reason: 'switching cancels');
        keys.prompt!.complete(); // late: the platform ignored the cancel
        await tester.pumpAndSettle();
        expect(decisions(native), isEmpty);
        final shown = tester.widget<Text>(
          find.byKey(const Key('touch-id-message')),
        );
        expect(
          shown.data,
          startsWith('Earlier request ("deploy", AAAAAAAA…): '),
        );
        expect(shown.data, contains('Nothing was sent'));
        await tester.pumpWidget(const SizedBox.shrink());
      });
    });
  }

  for (final os in ['android', 'ios']) {
    group('phone $os', () {
      for (final signal in DeviceSignal.values) {
        testWidgets('${signal.name} during the prompt cancels it; '
            'nothing is sent', (tester) async {
          final native = FixtureProviderPlatform()..approvalBinding = binding;
          final keys = FakeKeys()..prompt = Completer();
          final signals = FakeSignals();
          await tester.pumpWidget(page(native, keys, os: os, signals: signals));
          await open(tester, providerId);
          await touchIdTap(tester);
          signals.callback!(signal);
          expect(keys.cancelled, hasLength(1));
          keys.prompt!.complete(); // late signed reply
          await tester.pumpAndSettle();
          expect(decisions(native), isEmpty);
          expect(find.textContaining('Nothing was sent'), findsWidgets);
          await tester.pumpWidget(const SizedBox.shrink());
        });
      }

      testWidgets('an unlock during the prompt is not lost', (tester) async {
        final native = FixtureProviderPlatform()..approvalBinding = binding;
        final keys = FakeKeys()..prompt = Completer();
        final signals = FakeSignals();
        await tester.pumpWidget(page(native, keys, os: os, signals: signals));
        await open(tester, providerId);
        await touchIdTap(tester);
        tester.binding.handleAppLifecycleStateChanged(
          AppLifecycleState.inactive,
        );
        signals.callback!(DeviceSignal.locked); // a real lock
        // Unlocked while the prompt is still winding down: deferred.
        tester.binding.handleAppLifecycleStateChanged(
          AppLifecycleState.resumed,
        );
        keys.prompt!.complete();
        await tester.pumpAndSettle();
        expect(decisions(native), isEmpty);
        expect(
          find.byKey(const Key('approve-start')),
          findsOneWidget,
          reason: 'resumed with a fresh review, not left suspended',
        );
        await tester.pumpWidget(const SizedBox.shrink());
      });

      testWidgets('a late lock signal after an unlock never strands the '
          'phone; a real lock still suspends until resumed', (tester) async {
        final native = FixtureProviderPlatform()..approvalBinding = binding;
        final signals = FakeSignals();
        await tester.pumpWidget(
          page(native, FakeKeys(), os: os, signals: signals),
        );
        await open(tester, providerId);
        for (final s in [
          AppLifecycleState.inactive,
          AppLifecycleState.resumed,
        ]) {
          tester.binding.handleAppLifecycleStateChanged(s);
        }
        await tester.pumpAndSettle();
        signals.callback!(DeviceSignal.locked); // arrives after the unlock
        await tester.pumpAndSettle();
        expect(find.byKey(const Key('approve-start')), findsOneWidget);
        // A real lock: the lifecycle leaves `resumed` and stays suspended.
        tester.binding.handleAppLifecycleStateChanged(
          AppLifecycleState.inactive,
        );
        signals.callback!(DeviceSignal.locked);
        await tester.pumpAndSettle();
        expect(find.byKey(const Key('approve-start')), findsNothing);
        tester.binding.handleAppLifecycleStateChanged(
          AppLifecycleState.resumed,
        );
        await tester.pumpAndSettle();
        expect(find.byKey(const Key('approve-start')), findsOneWidget);
        await tester.pumpWidget(const SizedBox.shrink());
      });

      testWidgets('phone messages name its verification, not a Mac', (
        tester,
      ) async {
        final native = FixtureProviderPlatform()..approvalBinding = binding;
        final (kind, name) = kinds[os]!;
        final keys = VerifyingKeys(kind)..signOutcome = KeyOutcome.cancelled;
        await tester.pumpWidget(page(native, keys, os: os));
        await open(tester, providerId);
        await touchIdTap(tester);
        await tester.pumpAndSettle();
        final shown = tester
            .widget<Text>(find.byKey(const Key('touch-id-message')))
            .data!;
        expect(
          shown,
          startsWith(
            '${name[0].toUpperCase()}${name.substring(1)} was cancelled.',
          ),
        );
        expect(shown, isNot(contains('Touch ID')));
        expect(shown, isNot(contains('Mac')));
        await tester.pumpWidget(const SizedBox.shrink());
      });

      testWidgets('returning to the foreground re-loads the open review', (
        tester,
      ) async {
        final native = FixtureProviderPlatform()..approvalBinding = binding;
        await tester.pumpWidget(page(native, FakeKeys(), os: os));
        await open(tester, providerId);
        int reviews() =>
            native.commands.where((c) => c['command'] == 'review').length;
        final before = reviews();
        for (final s in [
          AppLifecycleState.inactive,
          AppLifecycleState.hidden,
          AppLifecycleState.paused,
          AppLifecycleState.hidden,
          AppLifecycleState.inactive,
          AppLifecycleState.resumed,
        ]) {
          tester.binding.handleAppLifecycleStateChanged(s);
        }
        await tester.pumpAndSettle();
        expect(reviews(), before + 1, reason: 'a fresh review, not the old');
        expect(find.byKey(const Key('approve-start')), findsOneWidget);
        await tester.pumpWidget(const SizedBox.shrink());
      });

      testWidgets('settings never show desktop installation controls', (
        tester,
      ) async {
        final native = FixtureProviderPlatform();
        await tester.pumpWidget(page(native, FakeKeys(), os: os));
        await tester.pumpAndSettle();
        await tester.tap(find.text('Settings').first);
        await tester.pumpAndSettle();
        expect(find.byKey(const Key('desktop-installation')), findsNothing);
        await tester.pumpWidget(const SizedBox.shrink());
      });
    });
  }

  testWidgets('desktop settings keep the installation controls', (
    tester,
  ) async {
    await tester.pumpWidget(
      page(FixtureProviderPlatform(), FakeKeys(), os: 'macos'),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.text('Settings').first);
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('desktop-installation')), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
  });
}
