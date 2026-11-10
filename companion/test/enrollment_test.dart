// Guided enrollment UI (#59 phase 2): GUI-GUI and GUI-CLI journeys, mismatch,
// expiry, revoked identities and the manual fallback, driven through the real
// Rust joiner/owner cores against an independent test provider.
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:companion_slice/provider/controller.dart';
import 'package:companion_slice/provider/devices_view.dart';
import 'package:companion_slice/provider/enrollment_flow.dart';
import 'package:companion_slice/provider/enrollment_view.dart';
import 'package:companion_slice/src/rust/api/enrollment.dart' as enroll;
import 'package:companion_slice/src/rust/frb_generated.dart';

import 'enrollment_support.dart';
import 'provider_support.dart';

class Harness {
  Harness(this.platform)
    : controller = ProviderController(platform),
      password = TextEditingController(); // secrets-ignore: test UI controller
  final EnrollmentPlatform platform;
  final ProviderController controller;
  final TextEditingController password;
  late final EnrollmentFlow flow = EnrollmentFlow(
    controller,
    tick: const Duration(days: 1),
  );
  Future<void> start() => controller.initialize();
  Widget app({EnrollmentMode? only}) => MaterialApp(
    home: Scaffold(
      body: SingleChildScrollView(
        child: ListenableBuilder(
          listenable: flow,
          builder: (context, _) => switch (only) {
            EnrollmentMode.add => EnrollmentAddPanel(
              flow: flow,
              password: password,
            ),
            EnrollmentMode.join => EnrollmentJoinPanel(flow: flow),
            _ => ProviderDevices(
              controller: controller,
              password: password,
              enrollment: flow,
              enrollmentPassword: password,
            ),
          },
        ),
      ),
    ),
  );
  void dispose() {
    flow.dispose();
    controller.dispose();
    password.dispose();
  }
}

void resetEnrollment() {
  enroll.enrollmentJoinerReset();
  enroll.enrollmentAdminInvalidate();
}

Future<void> tapText(WidgetTester tester, String text) async {
  await tester.ensureVisible(find.text(text));
  await tester.tap(find.text(text));
  await tester.pump();
}

/// Every 8-digit comparison-code spelling, anywhere in the widget subtree.
bool showsAnyCode(WidgetTester tester, Finder root) {
  final pattern = RegExp(r'\b\d{4}[- ]?\d{4}\b');
  for (final element
      in find
          .descendant(of: root, matching: find.byWidgetPredicate((_) => true))
          .evaluate()) {
    final widget = element.widget;
    final text = widget is Text
        ? widget.data ?? ''
        : widget is SelectableText
        ? widget.data ?? ''
        : widget is EditableText
        ? widget.controller.text
        : '';
    if (pattern.hasMatch(text)) return true;
  }
  return false;
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async {
    await RustLib.init();
  });
  setUp(() {
    resetProvider();
    resetEnrollment();
  });

  test('the test provider reproduces the frozen enrollment vector', () {
    final v = enrollmentVector();
    final parts = (v['invitation_code'] as String).split('.');
    final invitation = FixtureInvitation(
      unb64(parts[1]),
      unb64(parts[2]),
      (v['joined'] as Map<String, dynamic>)['kind'] as Map<String, dynamic>,
    );
    final joined = invitation.joined(
      v['join'] as Map<String, dynamic>,
      unb64((v['joined'] as Map<String, dynamic>)['provider_nonce'] as String),
    )!;
    expect(joined['provider_mac'], (v['joined'] as Map)['provider_mac']);
    expect(invitation.comparisonCode, v['comparison_code']);
  });

  testWidgets('device to device: invite, compare, approve at both ends', (
    tester,
  ) async {
    final h = Harness(EnrollmentPlatform());
    await h.start();
    await tester.pumpWidget(h.app());
    expect(find.text('Guided enrollment'), findsOneWidget);
    await tapText(tester, 'Add a device or agent');
    await tester.pump();
    await tester.enterText(find.byKey(const Key('enroll-label')), 'Studio Mac');
    await tapText(tester, 'Create invitation');
    await tester.pump();
    final code = tester
        .widget<SelectableText>(find.byKey(const Key('invitation-code')))
        .data!;
    expect(code, startsWith('vwe1.'));
    expect(
      h.platform.enrollCommands.firstWhere(
        (c) => c['command'] == 'enroll_invite',
      ),
      {
        'version': 1,
        'command': 'enroll_invite',
        'kind': {'role': 'companion', 'label': 'Studio Mac'},
      },
    );
    await tapText(tester, 'Hide invitation');
    expect(find.byKey(const Key('invitation-code')), findsNothing);
    expect(find.text('Waiting for the device to join'), findsOneWidget);

    // The joining device (the same process plays both humans here).
    await tester.pumpWidget(h.app(only: EnrollmentMode.join));
    await tester.enterText(find.byKey(const Key('invitation-input')), code);
    await tapText(tester, 'Join');
    await tester.pump();
    final shown = tester
        .widget<SelectableText>(find.byKey(const Key('comparison-code')))
        .data!;
    expect(shown, h.platform.invitations.single.comparisonCode);
    expect(
      find.text('Joining as approval client "Studio Mac"'),
      findsOneWidget,
    );
    await tapText(tester, 'Yes, enroll this device');
    await tester.pump();
    expect(
      find.text(
        'Confirmed here. Waiting for the provider owner to type the code.',
      ),
      findsOneWidget,
    );

    // Back at the owner: the provider never shows the code.
    await tester.pumpWidget(h.app(only: EnrollmentMode.add));
    await h.flow.list();
    await tester.pump();
    expect(
      find.text('Joined and confirmed there · type the code it shows'),
      findsOneWidget,
    );
    expect(showsAnyCode(tester, find.byType(EnrollmentAddPanel)), false);
    expect(jsonEncode(h.platform.enrollCommands).contains(shown), false);
    await tapText(tester, 'Type code to approve');
    await tester.enterText(find.byKey(const Key('approve-code')), shown);
    await tester.enterText(
      find.byKey(const ValueKey('Provider password')),
      'synthetic-password',
    );
    await tapText(tester, 'Approve enrollment');
    await tester.pump();
    final approve = h.platform.enrollCommands.lastWhere(
      (c) => c['command'] == 'enroll_approve',
    );
    expect(approve['code'], shown);
    expect(h.password.text, isEmpty);
    expect(
      find.text(
        'Approved. The enrollment completes when the joining device confirms.',
      ),
      findsOneWidget,
    );

    // The joiner's next confirmation commits on its own channel.
    await tester.pumpWidget(h.app(only: EnrollmentMode.join));
    h.flow.mode = EnrollmentMode.join;
    await h.flow.poll();
    await tester.pump();
    expect(
      find.text(
        'Enrolled as an approval client. This device is not an administrator.',
      ),
      findsOneWidget,
    );
    expect(find.byKey(const Key('comparison-code')), findsNothing);
    h.dispose();
  });

  testWidgets('a code mismatch typed at the provider ends both sides', (
    tester,
  ) async {
    final h = Harness(EnrollmentPlatform());
    await h.start();
    await h.flow.open(EnrollmentMode.add);
    await h.flow.invite(role: enroll.EnrolleeRole.companion, label: 'Mac');
    final code = h.flow.admin.issued!.invitationCode;
    await h.flow.join(code);
    final shown = h.flow.joiner.comparisonCode;
    final wrong = shown == '0000-0000' ? '1111-1111' : '0000-0000';
    await tester.pumpWidget(h.app(only: EnrollmentMode.add));
    await h.flow.list();
    await tester.pump();
    await tapText(tester, 'Type code to approve');
    await tester.enterText(find.byKey(const Key('approve-code')), wrong);
    await tester.enterText(
      find.byKey(const ValueKey('Provider password')),
      'synthetic-password',
    );
    await tapText(tester, 'Approve enrollment');
    await tester.pump();
    expect(
      find.textContaining('That code does not match the joining device.'),
      findsOneWidget,
    );
    await tester.pumpWidget(h.app(only: EnrollmentMode.join));
    h.flow.mode = EnrollmentMode.join;
    await h.flow.poll();
    await tester.pump();
    expect(
      find.text(joinerEndText(enroll.JoinerEnd.codeMismatch)),
      findsOneWidget,
    );
    expect(find.byKey(const Key('comparison-code')), findsNothing);
    h.dispose();
  });

  testWidgets('the joining human declines when something is wrong', (
    tester,
  ) async {
    final h = Harness(EnrollmentPlatform());
    await h.start();
    final i = h.platform.issue({'role': 'companion', 'label': 'Mac'});
    h.flow.open(EnrollmentMode.join);
    await tester.pumpWidget(h.app(only: EnrollmentMode.join));
    await tester.enterText(find.byKey(const Key('invitation-input')), i.code);
    await tapText(tester, 'Join');
    await tester.pump();
    await tapText(tester, 'No, something is wrong');
    await tester.pump();
    expect(
      h.platform.enrollCommands.last['message']['reason'],
      'code_mismatch',
    );
    expect(find.text(joinerEndText(enroll.JoinerEnd.declined)), findsOneWidget);
    expect(find.byKey(const Key('comparison-code')), findsNothing);
    await tapText(tester, 'Start over');
    expect(find.byKey(const Key('invitation-input')), findsOneWidget);
    h.dispose();
  });

  testWidgets('expiry and a revoked identity end without a code', (
    tester,
  ) async {
    final h = Harness(EnrollmentPlatform());
    await h.start();
    final i = h.platform.issue({'role': 'companion', 'label': 'Mac'});
    h.flow.open(EnrollmentMode.join);
    await tester.pumpWidget(h.app(only: EnrollmentMode.join));
    // A known (enabled or revoked) certificate is refused at join.
    h.platform.joinRejection = 'identity_refused';
    await h.flow.join(i.code);
    await tester.pump();
    expect(
      find.text(joinerEndText(enroll.JoinerEnd.identityRefused)),
      findsOneWidget,
    );
    expect(find.byKey(const Key('comparison-code')), findsNothing);
    // An invitation that expires while the code is shown.
    h.flow.reset();
    h.platform.joinRejection = null;
    await h.flow.join(i.code);
    await tester.pump();
    expect(find.byKey(const Key('comparison-code')), findsOneWidget);
    h.platform.forcedState = {'state': 'expired'};
    await h.flow.poll();
    await tester.pump();
    expect(find.text(joinerEndText(enroll.JoinerEnd.expired)), findsOneWidget);
    expect(find.byKey(const Key('comparison-code')), findsNothing);
    // A forged provider never shows a code.
    h.flow.reset();
    h.platform.forcedState = null;
    final other = h.platform.issue({'role': 'companion', 'label': 'Mac'});
    await h.flow.join('vwe1.${other.idText}.${b64(List.filled(32, 1))}');
    await tester.pump();
    expect(
      find.text(joinerEndText(enroll.JoinerEnd.invalidInvitation)),
      findsOneWidget,
    );
    h.dispose();
  });

  testWidgets('a provider that cannot be reached keeps the identical join', (
    tester,
  ) async {
    final h = Harness(EnrollmentPlatform());
    await h.start();
    final i = h.platform.issue({'role': 'companion', 'label': 'Mac'});
    h.flow.open(EnrollmentMode.join);
    await tester.pumpWidget(h.app(only: EnrollmentMode.join));
    h.platform.joinRejection = 'busy';
    await h.flow.join(i.code);
    await tester.pump();
    expect(find.text('Try again'), findsOneWidget);
    h.platform.joinRejection = null;
    await tapText(tester, 'Try again');
    await tester.pump();
    final joins = h.platform.enrollCommands
        .where((c) => c['message']?['purpose'] == 'enroll_join')
        .toList();
    expect(joins.length, 2);
    expect(joins[0], joins[1]);
    expect(find.byKey(const Key('comparison-code')), findsOneWidget);
    h.dispose();
  });

  testWidgets('an agent invitation for a terminal joiner (GUI to CLI)', (
    tester,
  ) async {
    final h = Harness(EnrollmentPlatform());
    await h.start();
    await h.flow.open(EnrollmentMode.add);
    await tester.pumpWidget(h.app(only: EnrollmentMode.add));
    await tester.pump();
    await tapText(tester, 'Agent (terminal)');
    await tester.enterText(find.byKey(const Key('enroll-label')), 'ci runner');
    await tester.enterText(find.byKey(const Key('enroll-uid')), '42001');
    await tester.enterText(find.byKey(const Key('enroll-gid')), '42003');
    await tapText(tester, 'Create invitation');
    await tester.pump();
    expect(
      h.platform.enrollCommands.firstWhere(
        (c) => c['command'] == 'enroll_invite',
      )['kind'],
      {'role': 'agent', 'label': 'ci runner', 'uid': 42001, 'gid': 42003},
    );
    expect(
      find.textContaining('agent account ("vw-access enroll join")'),
      findsOneWidget,
    );
    expect(find.text('ci runner · agent'), findsOneWidget);
    h.dispose();
  });

  testWidgets('a non-administrator gets the manual fallback', (tester) async {
    final h = Harness(EnrollmentPlatform()..admin = false);
    await h.start();
    await tester.pumpWidget(h.app());
    await tapText(tester, 'Add a device or agent');
    await tester.pump();
    expect(
      find.textContaining(
        'This approval client is not a provider administrator.',
      ),
      findsOneWidget,
    );
    expect(find.text('Create invitation'), findsNothing);
    expect(
      find.textContaining('vw-access enroll invite-companion'),
      findsOneWidget,
    );
    await tapText(tester, 'Close');
    expect(find.text('Guided enrollment'), findsOneWidget);
    h.dispose();
  });
}
