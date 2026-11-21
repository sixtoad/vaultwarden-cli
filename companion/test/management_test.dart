import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:companion_slice/platform/provider.dart';
import 'package:companion_slice/provider/controller.dart';
import 'package:companion_slice/provider/devices_view.dart';
import 'package:companion_slice/provider/support_views.dart';
import 'package:companion_slice/design/access_theme.dart';
import 'package:companion_slice/src/rust/api/management.dart' as management;
import 'package:companion_slice/src/rust/frb_generated.dart';

import 'provider_support.dart';

Map<String, dynamic> agent() => {
  'kind': 'requester_agent',
  'id': providerId,
  'label': 'Same label',
  'fingerprint': 'b' * 64,
  'roles': ['request'],
  'trust': 'enabled',
  'this_client': false,
};
const actionId = 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC';

class ManagementPlatform extends FixtureProviderPlatform {
  Completer<Uint8List>? heldManagement;
  bool lost = false, badOrigin = false, failManagementSettlement = false;
  String cleanup = 'complete';
  int lifetime = 55;
  bool paged = false;
  Map<String, dynamic> get target => {
    'kind': 'requester_agent',
    'id': providerId,
  };
  Map<String, dynamic> get action => {
    'version': 2,
    'target': target,
    'action_id': actionId,
    'owner_reconciled': false,
    'revocation': 'recorded',
    'cleanup': cleanup,
  };
  void marker(String value) {
    saved = ProviderConfiguration(
      configured: true,
      endpoint: saved.endpoint,
      pin: saved.pin,
      fingerprint: saved.fingerprint,
      managementRecovery: value,
    );
  }

  @override
  Future<Uint8List> send(Uint8List body) async {
    final c = jsonDecode(utf8.decode(body)) as Map<String, dynamic>;
    if (!(c['command'] as String).startsWith('identity_') &&
        c['command'] != 'request_origin') {
      return super.send(body);
    }
    commands.add(c);
    if (c['command'] == 'request_origin') {
      return encoded({
        'version': 2,
        'request_id': c['request_id'],
        'origin': null,
        if (badOrigin) 'unknown_security_field': true,
      });
    }
    if (c['command'] == 'identity_revoke') {
      marker(jsonEncode({'target': c['target'], 'action_id': c['action_id']}));
      if (heldManagement != null) return heldManagement!.future;
      if (lost) throw StateError('lost reply');
      return encoded(action);
    }
    if (heldManagement != null) return heldManagement!.future;
    switch (c['command']) {
      case 'identity_list':
        return encoded({
          'version': 2,
          'identities': paged && c['after'] == null
              ? List.generate(64, (index) {
                  final fingerprint = index.toRadixString(16).padLeft(64, '0');
                  return {
                    'kind': 'approval_client',
                    'id': fingerprint,
                    'label': 'Client',
                    'fingerprint': fingerprint,
                    'roles': ['approve'],
                    'trust': 'enabled',
                    'this_client': false,
                  };
                })
              : [agent()],
          'next_cursor': paged && c['after'] == null
              ? 'approval_client:${63.toRadixString(16).padLeft(64, '0')}'
              : null,
          'generation': 1,
          'provider': {
            'fingerprint': 'e' * 64,
            'execution_configured': true,
            'execution_available': false,
          },
        });
      case 'identity_detail':
        return encoded({'version': 2, 'identity': agent(), 'generation': 1});
      case 'identity_prepare':
        return encoded({
          'version': 2,
          'identity': agent(),
          'generation': 1,
          'action_id': actionId,
          'ticket': 'd' * 64,
          'valid_for_seconds': lifetime,
        });
      case 'identity_status':
        return encoded(action);
    }
    throw StateError('unknown fixture command');
  }

  @override
  Future<void> settle(String id) async {
    if (saved.managementRecovery.isEmpty) return super.settle(id);
    settlementAttempts.add(id);
    if (failManagementSettlement) throw StateError('storage unavailable');
    expect(id, actionId);
    marker('');
    settled.add(id);
  }
}

void resetManagement() {
  final s = management.managementSnapshot();
  if (s.recovery.isNotEmpty) {
    final r = jsonDecode(s.recovery) as Map<String, dynamic>;
    final w = management.managementBegin(
      command: management.ManagementCommand.status,
      kind: management.IdentityKind.requesterAgent,
      id: '',
      password: '',
    );
    management.managementFinish(
      token: w.token,
      response: encoded({
        'version': 2,
        ...r,
        'owner_reconciled': false,
        'revocation': 'recorded',
        'cleanup': 'complete',
      }),
    );
  }
  management.managementConfigure(recovery: '');
}

Future<void> prepare(ProviderController c) async {
  await c.performManagement(management.ManagementCommand.list);
  await c.selectIdentity(c.management.identities.single, prepare: true);
  expect(c.management.canRevoke, true);
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async {
    await RustLib.init();
    for (final family in [
      'Roboto',
      '.SF UI Text',
      '.SF UI Display',
      '.AppleSystemUIFont',
    ]) {
      final loader = FontLoader(family)
        ..addFont(
          Future.value(
            ByteData.sublistView(
              File('test/fonts/Roboto-Regular.ttf').readAsBytesSync(),
            ),
          ),
        );
      await loader.load();
    }
  });
  setUp(() {
    resetProvider();
    resetManagement();
  });
  test('automatic refresh preserves the selected inventory page', () async {
    final p = ManagementPlatform()..paged = true;
    final c = ProviderController(p)..devicesVisible = true;
    await c.initialize();
    expect(c.management.identities.length, 64);
    expect(c.management.hasNext, true);
    await c.performManagement(management.ManagementCommand.next);
    expect(c.management.identities.single.id, providerId);
    final reads = p.commands.length;
    await c.refresh(automatic: true);
    expect(p.commands.length, reads);
    expect(c.management.identities.single.id, providerId);
    await c.refresh(); // Explicit refresh returns to the first fresh page.
    expect(c.management.identities.length, 64);
    c.dispose();
  });
  test(
    'real bridge inventory and exact target revoke never unlock or approve',
    () async {
      final p = ManagementPlatform();
      final c = ProviderController(p);
      await c.initialize();
      await prepare(c);
      await c.revokeIdentity('synthetic');
      expect(c.management.revocation, 'recorded');
      expect(c.management.cleanup, 'complete');
      expect(c.managementPending, false);
      expect(p.settled, [actionId]);
      expect(
        p.commands
            .where((v) => v['command'] == 'identity_revoke')
            .single['target'],
        p.target,
      );
      expect(
        p.commands.where((v) => ['decision', 'unlock'].contains(v['command'])),
        isEmpty,
      );
      c.dispose();
    },
  );
  testWidgets(
    'Activity explains administrative recovery and sends only status',
    (tester) async {
      final p = ManagementPlatform()
        ..lost = true
        ..cleanup = 'unknown';
      final c = ProviderController(p);
      await c.initialize();
      await prepare(c);
      await c.revokeIdentity('synthetic');
      c.setActivityCurrent(true);
      c.invalidate();
      final before = p.commands.length;
      await c.refresh();
      expect(p.commands.skip(before).map((v) => v['command']), [
        'identity_status',
      ]);
      expect(c.managementPending, true);
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: ProviderActivity(
              state: c.state,
              connected: c.connected,
              configured: true,
              recoveryPending: false,
              managementPending: c.managementPending,
              onRefresh: null,
              onReopen: null,
            ),
          ),
        ),
      );
      expect(
        find.textContaining('original administrative action is unresolved'),
        findsOneWidget,
      );
      expect(find.text('Open request with fresh review'), findsNothing);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
      c.dispose();
    },
  );
  test(
    'lost reply and relaunch recover original action without replay',
    () async {
      final p = ManagementPlatform()
        ..lost = true
        ..cleanup = 'unknown';
      var c = ProviderController(p);
      await c.initialize();
      await prepare(c);
      await c.revokeIdentity('synthetic');
      expect(c.managementPending, true);
      expect(c.canSetup, false);
      await c.unlock('never-send');
      await c.review(providerId);
      expect(p.commands.where((v) => v['command'] == 'unlock'), isEmpty);
      expect(c.managementPending, true);
      c.dispose();
      p.cleanup = 'complete';
      c = ProviderController(p);
      await c.initialize();
      expect(c.managementPending, false);
      expect(
        p.commands.where((v) => v['command'] == 'identity_revoke'),
        hasLength(1),
      );
      expect(p.commands.last['command'], 'identity_status');
      expect(p.settled, [actionId]);
      c.dispose();
    },
  );
  test(
    'cleanup unknown retains action and provider switch cannot steal recovery',
    () async {
      final p = ManagementPlatform()..cleanup = 'unknown';
      final c = ProviderController(p);
      await c.initialize();
      await prepare(c);
      await c.revokeIdentity('synthetic');
      expect(c.management.revocation, 'recorded');
      expect(c.managementPending, true);
      final saved = p.saved;
      final count = p.commands.length;
      p.saved = ProviderConfiguration(
        configured: true,
        endpoint: 'https://other.example',
        pin: 'c' * 64,
        fingerprint: 'd' * 64,
      );
      c.suspend();
      c.resume();
      await Future<void>.delayed(Duration.zero);
      await c.refresh();
      expect(p.commands.length, count);
      expect(c.managementPending, true);
      p.saved = saved;
      p.cleanup = 'complete';
      await c.refresh();
      expect(c.managementPending, false);
      c.dispose();
    },
  );
  test('expired management confirmation clears entered password', () async {
    final p = ManagementPlatform()..lifetime = 1;
    final c = ProviderController(p);
    await c.initialize();
    await prepare(c);
    var cleared = false;
    c.clearPasswords = () {
      cleared = true;
    };
    await Future<void>.delayed(const Duration(milliseconds: 1400));
    expect(c.management.canRevoke, false);
    expect(cleared, true);
    c.dispose();
  });
  test(
    'late prepare after navigation and background cannot restore authority',
    () async {
      final p = ManagementPlatform();
      final c = ProviderController(p);
      await c.initialize();
      await c.performManagement(management.ManagementCommand.list);
      final row = c.management.identities.single;
      p.heldManagement = Completer<Uint8List>();
      final pending = c.selectIdentity(row, prepare: true);
      c.suspend();
      p.heldManagement!.complete(
        encoded({
          'version': 2,
          'identity': agent(),
          'generation': 1,
          'action_id': actionId,
          'ticket': 'd' * 64,
          'valid_for_seconds': 55,
        }),
      );
      await pending;
      expect(c.management.canRevoke, false);
      expect(c.management.detail, isNull);
      await c.revokeIdentity('never-send');
      expect(
        p.commands.where((v) => v['command'] == 'identity_revoke'),
        isEmpty,
      );
      c.dispose();
    },
  );
  test('late revoke completion settles original action without restoring selected trust', () async {
    final p = ManagementPlatform();
    final c = ProviderController(p);
    await c.initialize();
    await prepare(c);
    p.heldManagement = Completer<Uint8List>();
    final pending = c.revokeIdentity('synthetic');
    c.invalidate();
    p.heldManagement!.complete(encoded(p.action));
    await pending;
    expect(p.settled, [actionId]);
    expect(c.management.detail, isNull);
    expect(c.management.canRevoke, false);
    expect(c.management.actionId, actionId);
    c.dispose();
  });
  test('failed native settlement retries settlement without another privileged send', () async {
    final p = ManagementPlatform()..failManagementSettlement = true;
    final c = ProviderController(p);
    await c.initialize();
    await prepare(c);
    await c.revokeIdentity('synthetic');
    expect(c.managementPending, true);
    expect(c.canSetup, false);
    final count = p.commands.length;
    p.failManagementSettlement = false;
    await c.refresh();
    expect(p.commands.length, count);
    expect(c.managementPending, false);
    c.dispose();
  });
  test('malformed origin retires review; legitimate missing origin remains explicit', () async {
    final p = ManagementPlatform();
    final c = ProviderController(p);
    await c.initialize();
    await c.review(providerId);
    expect(c.state.canDecide, true);
    expect(c.management.originText, contains('Unavailable'));
    p.badOrigin = true;
    await c.review(providerId);
    expect(c.state.canDecide, false);
    expect(c.state.review, isNull);
    c.dispose();
  });
  for (final brightness in Brightness.values) {
    testWidgets(
      'management controls remain reachable at 200% ${brightness.name}',
      (tester) async {
        final p = ManagementPlatform();
        final c = ProviderController(p);
        await c.initialize();
        await prepare(c);
        final password = TextEditingController(); // secrets-ignore: test UI controller
        await tester.pumpWidget(
          MaterialApp(
            theme: accessTheme(brightness),
            home: MediaQuery(
              data: const MediaQueryData(textScaler: TextScaler.linear(2)),
              child: RepaintBoundary(
                key: const Key('management-capture'),
                child: Scaffold(
                  body: SingleChildScrollView(
                    child: ProviderDevices(controller: c, password: password),
                  ),
                ),
              ),
            ),
          ),
        );
        await captureManagement(tester, '${brightness.name}-review');
        expect(find.text(providerId), findsOneWidget);
        expect(find.textContaining('Consumer programs'), findsOneWidget);
        await tester.ensureVisible(find.text('Confirm permanent revocation'));
        await captureManagement(tester, '${brightness.name}-confirmation');
        expect(tester.takeException(), isNull);
        await tester.pumpWidget(const SizedBox.shrink());
        password.dispose();
        c.dispose();
      },
    );
  }
}

Future<void> captureManagement(WidgetTester tester, String name) async {
  final directory = Platform.environment['MANAGEMENT_CAPTURE_DIR'];
  if (directory == null) return;
  await tester.pump();
  final boundary = tester.renderObject<RenderRepaintBoundary>(
    find.byKey(const Key('management-capture')),
  );
  await tester.runAsync(() async {
    final image = await boundary.toImage(pixelRatio: 1);
    final data = await image.toByteData(format: ui.ImageByteFormat.png);
    await Directory(directory).create(recursive: true);
    await File('$directory/$name.png').writeAsBytes(data!.buffer.asUint8List());
    image.dispose();
  });
}
