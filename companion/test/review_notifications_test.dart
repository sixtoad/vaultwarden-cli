import 'dart:async';
import 'dart:convert';
import 'dart:math';

import 'package:companion_slice/platform/notifications.dart';
import 'package:companion_slice/provider/page.dart';
import 'package:companion_slice/provider/review_notifications.dart';
import 'package:companion_slice/src/rust/frb_generated.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import 'provider_support.dart';
import 'touch_id_support.dart';

/// Review-request notifications (#61).
class FakeNotifications implements ReviewNotificationPlatform {
  FakeNotifications({
    this.status = NotificationPermission.authorized,
    this.saved = true,
  });
  @override
  bool available = true;
  NotificationPermission status;
  NotificationPermission answer = NotificationPermission.authorized;
  bool saved;
  int prompts = 0;
  final List<String> posted = [];
  void Function(String token)? onOpen;
  String? launched;

  @override
  Future<NotificationPermission> permission() async => status;
  @override
  Future<NotificationPermission> requestPermission() async {
    prompts++;
    return status = answer;
  }

  @override
  Future<bool> enabled() async => saved;
  @override
  Future<void> setEnabled(bool value) async => saved = value;
  @override
  Future<void> post(String token) async => posted.add(token);
  @override
  Future<String?> listen(void Function(String token) onOpen) async {
    this.onOpen = onOpen;
    return launched;
  }
}

const secondId = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB';
final tokenShape = RegExp(r'^[A-Za-z0-9_-]{22}$');

Map<String, dynamic> reviewOf(String id, Map<String, dynamic> status) {
  final reply = providerReview();
  reply['review']['id'] = id;
  reply['review']['status'] = status;
  if (status['status'] != 'pending') reply['ticket'] = null;
  return reply;
}

void main() {
  setUpAll(() async => RustLib.init());
  setUp(resetProvider);

  group('ReviewNotifier', () {
    test('announces a request once, only while away and active', () async {
      final fake = FakeNotifications();
      final n = ReviewNotifier(fake, random: Random(1));
      await n.load();
      n.observe([providerId], foreground: true);
      expect(fake.posted, isEmpty, reason: 'seen on screen');
      n.observe([providerId, secondId], foreground: false);
      expect(fake.posted, hasLength(1));
      expect(n.resolve(fake.posted.single), secondId);
      for (var i = 0; i < 3; i++) {
        n.observe([providerId, secondId], foreground: false);
      }
      expect(fake.posted, hasLength(1), reason: 'no duplicate across polls');
      n.observe([providerId], foreground: false);
      n.observe([providerId, secondId], foreground: false);
      expect(fake.posted, hasLength(1), reason: 'announced once per id');
      n.reset();
      expect(n.resolve(fake.posted.single), isNull);
    });

    test('the first read after launch is a baseline: no burst', () async {
      final fake = FakeNotifications();
      final n = ReviewNotifier(fake);
      await n.load();
      n.observe([providerId, secondId], foreground: false);
      expect(fake.posted, isEmpty, reason: 'already pending at launch');
      n.reset(); // another provider: a new baseline
      n.observe([providerId], foreground: false);
      expect(fake.posted, isEmpty);
      n.observe([providerId, secondId], foreground: false);
      expect(fake.posted, hasLength(1));
    });

    test('a post that fails is announced again on the next read', () async {
      final fake = _FailingOnce();
      final n = ReviewNotifier(fake);
      await n.load();
      n.observe([], foreground: true);
      n.observe([secondId], foreground: false);
      await Future<void>.delayed(Duration.zero);
      expect(fake.posted, isEmpty);
      n.observe([], foreground: false);
      n.observe([secondId], foreground: false);
      expect(fake.posted, hasLength(1));
    });

    test('the token carries nothing from the request', () async {
      final fake = FakeNotifications();
      final n = ReviewNotifier(fake);
      await n.load();
      n.observe([], foreground: true);
      n.observe([secondId], foreground: false);
      final token = fake.posted.single;
      expect(token, matches(tokenShape));
      expect(token, isNot(contains(secondId.substring(0, 8))));
      expect(token.length, isNot(secondId.length));
    });

    test('off in Settings: nothing is posted', () async {
      final fake = FakeNotifications(saved: false);
      final n = ReviewNotifier(fake);
      await n.load();
      n.observe([secondId], foreground: false);
      expect(fake.posted, isEmpty);
      expect(n.active, isFalse);
    });

    test(
      'loading never prompts; only the toggle asks for permission',
      () async {
        final fake = FakeNotifications(
          status: NotificationPermission.notDetermined,
          saved: false,
        );
        final n = ReviewNotifier(fake);
        await n.load();
        expect(fake.prompts, 0);
        await n.setEnabled(true);
        expect(fake.prompts, 1);
        expect(n.active, isTrue);
        expect(fake.saved, isTrue);
        await n.setEnabled(false);
        expect(fake.saved, isFalse);
        expect(n.active, isFalse);
      },
    );

    test('permission denied: stays off, explains, posts nothing', () async {
      final fake = FakeNotifications(
        status: NotificationPermission.notDetermined,
        saved: false,
      )..answer = NotificationPermission.denied;
      final n = ReviewNotifier(fake);
      await n.load();
      await n.setEnabled(true);
      expect(n.enabled, isFalse);
      expect(fake.saved, isFalse);
      expect(n.message, ReviewNotifier.deniedText);
      n.observe([secondId], foreground: false);
      expect(fake.posted, isEmpty);
      // Saved on, but denied in System Settings before launch.
      final later = FakeNotifications(status: NotificationPermission.denied);
      final m = ReviewNotifier(later);
      await m.load();
      expect(m.message, ReviewNotifier.deniedText);
      expect(m.switchedOn, isFalse);
      m.observe([], foreground: true);
      m.observe([secondId], foreground: false);
      expect(later.posted, isEmpty);
    });

    test('revoked while away: the switch reads off and explains', () async {
      final fake = FakeNotifications();
      final n = ReviewNotifier(fake);
      await n.load();
      expect(n.switchedOn, isTrue);
      fake.status = NotificationPermission.denied;
      await n.refreshPermission();
      expect(n.switchedOn, isFalse);
      expect(n.message, ReviewNotifier.deniedText);
      n.observe([], foreground: true);
      n.observe([secondId], foreground: false);
      expect(fake.posted, isEmpty);
    });
  });

  group('native channel payload', () {
    const channel = MethodChannel('test/notifications');
    final calls = <MethodCall>[];
    setUp(() {
      calls.clear();
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
            calls.add(call);
            return null;
          });
    });
    tearDown(
      () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, null),
    );

    test('post sends only the opaque token; never text or an id', () async {
      final native = NativeReviewNotificationPlatform(
        macOS: true,
        channel: channel,
      );
      final n = ReviewNotifier(_Authorized(native));
      await n.load();
      n.observe([], foreground: true);
      n.observe([secondId], foreground: false);
      await Future<void>.delayed(Duration.zero);
      final post = calls.singleWhere((c) => c.method == 'post');
      final args = post.arguments as Map;
      expect(args.keys, ['token']);
      expect(args['token'], matches(tokenShape));
      final wire = jsonEncode(args);
      final review = providerReview()['review'] as Map<String, dynamic>;
      for (final secret in [
        secondId,
        review['requester'],
        review['target'],
        review['operation'],
        'Synthetic login',
      ]) {
        expect(wire, isNot(contains(secret as String)));
      }
      await expectLater(native.post(secondId), throwsFormatException);
    });
  });

  group('the page', () {
    late FakeNotifications notes;
    late FixtureProviderPlatform native;

    Widget page() => MaterialApp(
      home: ProviderPage(
        platform: native,
        syntheticBuilder: (_) => const SizedBox(),
        approvalKeys: FakeKeys(),
        notifications: notes,
      ),
    );

    void lifecycle(WidgetTester tester, List<AppLifecycleState> states) {
      for (final s in states) {
        tester.binding.handleAppLifecycleStateChanged(s);
      }
    }

    Future<void> away(WidgetTester tester) async {
      lifecycle(tester, [AppLifecycleState.inactive]);
      await tester.pump(const Duration(seconds: 16));
      for (var i = 0; i < 6; i++) {
        await tester.pump();
      }
    }

    Future<void> back(WidgetTester tester) async {
      lifecycle(tester, [AppLifecycleState.resumed]);
      await tester.pumpAndSettle();
      await tester.pump(const Duration(milliseconds: 300));
      await tester.pumpAndSettle();
    }

    List<String> reviews() => [
      for (final c in native.commands)
        if (c['command'] == 'review') c['request_id'] as String,
    ];

    setUp(() {
      notes = FakeNotifications();
      native = FixtureProviderPlatform();
    });

    testWidgets('a request arriving while away is announced once and the '
        'watch only reads', (tester) async {
      await tester.pumpWidget(page());
      await tester.pumpAndSettle();
      expect(notes.posted, isEmpty, reason: 'foreground: already on screen');
      native.requestIds = [providerId, secondId];
      final before = native.commands.length;
      await away(tester);
      expect(notes.posted, hasLength(1));
      await tester.pump(const Duration(seconds: 16));
      await tester.pump();
      await tester.pump(const Duration(seconds: 16));
      await tester.pump();
      expect(notes.posted, hasLength(1), reason: 'no duplicate across polls');
      final watched = native.commands
          .skip(before)
          .map((c) => c['command'])
          .toSet();
      expect(watched, {'session', 'list'});
      await tester.pumpWidget(const SizedBox.shrink());
    });

    testWidgets('a watch read that lands after the window came back is not '
        'announced', (tester) async {
      final held = _HeldList();
      native = held;
      await tester.pumpWidget(page());
      await tester.pumpAndSettle();
      held.requestIds = [providerId, secondId];
      held.hold = Completer<void>();
      lifecycle(tester, [AppLifecycleState.inactive]);
      await tester.pump(const Duration(seconds: 16));
      for (var i = 0; i < 4; i++) {
        await tester.pump();
      }
      expect(held.commands.last['command'], 'list', reason: 'list in flight');
      lifecycle(tester, [AppLifecycleState.resumed]);
      held.hold!.complete();
      held.hold = null;
      await tester.pumpAndSettle();
      await tester.pump(const Duration(seconds: 6));
      await tester.pumpAndSettle();
      expect(notes.posted, isEmpty, reason: 'the window is in front');
      await tester.pumpWidget(const SizedBox.shrink());
    });

    testWidgets('opening it loads a fresh review of that exact request', (
      tester,
    ) async {
      native.reviewReply = reviewOf(secondId, {'status': 'pending'});
      await tester.pumpWidget(page());
      await tester.pumpAndSettle();
      native.requestIds = [providerId, secondId];
      await away(tester);
      expect(reviews(), isEmpty);
      notes.onOpen!(notes.posted.single);
      await tester.pump();
      expect(reviews(), isEmpty, reason: 'not before the window is in front');
      await back(tester);
      expect(reviews(), [secondId]);
      expect(find.byKey(const Key('provider-review')), findsOneWidget);
      expect(reviewFact(tester, 'review-id'), '"$secondId"');
      expect(native.commands.where((c) => c['command'] == 'decision'), isEmpty);
      await tester.pumpWidget(const SizedBox.shrink());
    });

    for (final status in <Map<String, dynamic>>[
      {'status': 'approved'},
      {'status': 'expired'},
      {'status': 'denied'},
    ]) {
      testWidgets('a request ${status['status']} after the notification fired '
          'opens its final state', (tester) async {
        native.reviewReply = reviewOf(secondId, {'status': 'pending'});
        await tester.pumpWidget(page());
        await tester.pumpAndSettle();
        native.requestIds = [providerId, secondId];
        await away(tester);
        // Decided elsewhere (or expired) before the operator clicks.
        native.requestIds = [providerId];
        native.reviewReply = reviewOf(secondId, status);
        notes.onOpen!(notes.posted.single);
        await back(tester);
        expect(reviews(), [secondId], reason: 'fetched fresh, not cached');
        expect(find.byKey(const Key('review-final')), findsOneWidget);
        expect(find.byType(TextField), findsNothing);
        expect(find.text('Approve once with password'), findsNothing);
        await tester.pumpWidget(const SizedBox.shrink());
      });
    }

    testWidgets('a request the provider no longer knows says so', (
      tester,
    ) async {
      await tester.pumpWidget(page());
      await tester.pumpAndSettle();
      native.requestIds = [providerId, secondId];
      await away(tester);
      native.reviewReply = {'version': 1, 'error': 'not_found'};
      notes.onOpen!(notes.posted.single);
      await back(tester);
      expect(reviews(), [secondId]);
      expect(find.byKey(const Key('notification-unavailable')), findsOneWidget);
      await tester.pumpWidget(const SizedBox.shrink());
    });

    testWidgets('a token from an earlier session opens the request list', (
      tester,
    ) async {
      notes.launched = 'AAAAAAAAAAAAAAAAAAAAAA';
      await tester.pumpWidget(page());
      await tester.pumpAndSettle();
      expect(reviews(), isEmpty);
      expect(find.byKey(const Key('notification-note')), findsOneWidget);
      await tester.pumpWidget(const SizedBox.shrink());
    });

    testWidgets('off in Settings: nothing is read or posted while away', (
      tester,
    ) async {
      notes = FakeNotifications(saved: false);
      await tester.pumpWidget(page());
      await tester.pumpAndSettle();
      native.requestIds = [providerId, secondId];
      final before = native.commands.length;
      await away(tester);
      await tester.pump(const Duration(seconds: 60));
      expect(native.commands.length, before);
      expect(notes.posted, isEmpty);
      await tester.pumpWidget(const SizedBox.shrink());
    });

    testWidgets('permission denied from the Settings toggle', (tester) async {
      notes = FakeNotifications(
        status: NotificationPermission.notDetermined,
        saved: false,
      )..answer = NotificationPermission.denied;
      tester.view.physicalSize = const Size(1440, 2400);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      await tester.pumpWidget(page());
      await tester.pumpAndSettle();
      expect(notes.prompts, 0, reason: 'never asked at launch');
      await tester.tap(find.text('Settings').first);
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.byKey(const Key('review-notifications')));
      await tester.tap(find.byKey(const Key('review-notifications')));
      await tester.pumpAndSettle();
      expect(notes.prompts, 1);
      expect(find.text(ReviewNotifier.deniedText), findsOneWidget);
      final toggle = tester.widget<SwitchListTile>(
        find.byKey(const Key('review-notifications')),
      );
      expect(toggle.value, isFalse);
      await tester.pumpWidget(const SizedBox.shrink());
    });
  });
}

/// A real native platform whose permission reads are pre-answered, so the
/// test sees exactly the `post` call on the wire.
class _Authorized implements ReviewNotificationPlatform {
  _Authorized(this.native);
  final NativeReviewNotificationPlatform native;
  @override
  bool get available => true;
  @override
  Future<NotificationPermission> permission() async =>
      NotificationPermission.authorized;
  @override
  Future<NotificationPermission> requestPermission() async =>
      NotificationPermission.authorized;
  @override
  Future<bool> enabled() async => true;
  @override
  Future<void> setEnabled(bool value) async {}
  @override
  Future<void> post(String token) => native.post(token);
  @override
  Future<String?> listen(void Function(String token) onOpen) async => null;
}

class _FailingOnce extends FakeNotifications {
  bool failed = false;
  @override
  Future<void> post(String token) async {
    if (!failed) {
      failed = true;
      throw StateError('Synthetic post failure');
    }
    posted.add(token);
  }
}

class _HeldList extends FixtureProviderPlatform {
  Completer<void>? hold;
  @override
  Future<Uint8List> send(Uint8List body) async {
    final command = jsonDecode(utf8.decode(body)) as Map<String, dynamic>;
    final gate = hold;
    if (command['command'] == 'list' && gate != null) {
      final reply = super.send(body);
      await gate.future;
      return reply;
    }
    return super.send(body);
  }
}
