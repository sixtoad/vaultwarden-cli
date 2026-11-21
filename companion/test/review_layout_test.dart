import 'package:companion_slice/provider/page.dart';
import 'package:companion_slice/src/rust/frb_generated.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'golden_support.dart';
import 'provider_support.dart';

/// Where the review and the inbox put a request's state on screen (#50
/// slice 2): the opened review's "who wants what" at 200% text, and the inbox
/// row's status once the companion holds a final one.
Future<void> showLayout(
  WidgetTester tester,
  FixtureProviderPlatform native, {
  required Size size,
  double textScale = 1,
}) async {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  await tester.pumpWidget(
    MaterialApp(
      locale: const Locale('en', 'US'),
      builder: (context, child) => MediaQuery(
        data: MediaQuery.of(context)
            .copyWith(textScaler: TextScaler.linear(textScale)),
        child: child!,
      ),
      home: ProviderPage(
        platform: native,
        clock: () => DateTime.utc(2030, 1, 1, 12),
        syntheticBuilder: (_) => const SizedBox(),
      ),
    ),
  );
  await tester.pumpAndSettle();
}

Future<void> openRow(WidgetTester tester) async {
  await tester.ensureVisible(requestRow(providerId));
  await tester.tap(requestRow(providerId));
  await tester.pumpAndSettle();
}

String rowStatus(WidgetTester tester) => tester
    .widget<Text>(find.byKey(const Key('request-row-status-$providerId')))
    .data!;

void main() {
  // The bundled golden fonts give the real text metrics the layout is for.
  setUpAll(() async {
    await RustLib.init();
    await loadGoldenFonts();
  });
  setUp(resetProvider);

  testWidgets('at 200% text the opened review shows who wants what', (
    tester,
  ) async {
    await showLayout(
      tester,
      FixtureProviderPlatform(),
      size: const Size(390, 844),
      textScale: 2,
    );
    await openRow(tester);
    final viewport = tester.getRect(
      find
          .descendant(
            of: find.byType(SingleChildScrollView),
            matching: find.byType(Scrollable),
          )
          .first,
    );
    final sentence = tester.getRect(
      find.byKey(const Key('review-description')),
    );
    // Not cut by the navigation bar: the whole sentence is on screen.
    expect(sentence.top, greaterThanOrEqualTo(viewport.top));
    expect(sentence.bottom, lessThanOrEqualTo(viewport.bottom));
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  for (final (status, label) in <(Map<String, dynamic>, String)>[
    ({'status': 'running'}, 'Running · not completed'),
    ({'status': 'completed', 'exit_code': 0}, 'Completed · exit code 0'),
    ({'status': 'failed', 'reason': 'execution_rejected'}, 'Failed'),
    ({'status': 'denied'}, 'Denied'),
    ({'status': 'expired'}, 'Expired'),
  ]) {
    testWidgets('a final $status review is not listed as pending', (
      tester,
    ) async {
      final reply = providerReview();
      reply['ticket'] = null;
      reply['review']['status'] = status;
      await showLayout(
        tester,
        FixtureProviderPlatform()..reviewReply = reply,
        size: const Size(1440, 900),
      );
      expect(rowStatus(tester), 'Pending');
      await openRow(tester);
      expect(find.byKey(const Key('provider-review')), findsOneWidget);
      expect(rowStatus(tester), label);
      expect(
        find.bySemanticsLabel('Review request $providerId, pending'),
        findsNothing,
      );
      await tester.pumpWidget(const SizedBox.shrink());
    });
  }

  testWidgets('the inbox row follows the decision before the next read', (
    tester,
  ) async {
    final native = FixtureProviderPlatform();
    await showLayout(tester, native, size: const Size(1440, 900));
    await openRow(tester);
    expect(rowStatus(tester), 'Pending');
    await denyRequest(tester);
    expect(find.byKey(const Key('latest-status')), findsOneWidget);
    expect(rowStatus(tester), 'Denied');
    await tester.pumpWidget(const SizedBox.shrink());
  });
}
