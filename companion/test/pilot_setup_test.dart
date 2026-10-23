import 'dart:async';
import 'dart:convert';

import 'package:companion_slice/platform/provider.dart';
import 'package:companion_slice/provider/controller.dart';
import 'package:companion_slice/provider/page.dart';
import 'package:companion_slice/provider/pilot_bundle.dart';
import 'package:companion_slice/src/rust/frb_generated.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

import 'provider_support.dart';

Map<String, Object> fixtureBundle() => {
  'version': 1,
  'kind': 'disposable-companion-pilot',
  'endpoint': 'https://fixture.example/v1/companion',
  'leaf_sha256': 'a' * 64,
  'client_sha256': 'b' * 64,
  'ca_der': base64Encode([1, 2, 3]),
  'pkcs12': base64Encode([4, 5, 6]),
  'import_passphrase': 'synthetic-import-only',
  'unlock_password': 'synthetic-unlock-only',
};

class PilotFixture extends FixtureProviderPlatform
    implements PilotProviderPlatform {
  int imports = 0;
  bool failImport = false, mismatch = false;
  Completer<void>? heldImport;
  @override
  Future<ProviderConfiguration> setupPilot(PilotBundle bundle) async {
    imports++;
    if (heldImport != null) await heldImport!.future;
    if (failImport) throw StateError('secret must never reach UI');
    return ProviderConfiguration(
      configured: true,
      endpoint: bundle.endpoint,
      pin: bundle.pin,
      fingerprint: mismatch ? 'c' * 64 : bundle.fingerprint,
    );
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(() async => RustLib.init());
  setUp(resetProvider);

  test(
    'bounded versioned parser rejects malformed and secret-bearing errors',
    () {
      final valid = fixtureBundle();
      expect(
        PilotBundle.parse(jsonEncode(valid)).unlockPassword,
        'synthetic-unlock-only',
      );
      expect(
        PilotBundle.parse(
          jsonEncode({...valid, 'endpoint': 'https://fixture.example'}),
        ).endpoint,
        'https://fixture.example/v1/companion',
      );
      final invalid = <String>[
        '{private-secret',
        '[]',
        'x' * (PilotBundle.maximumLength + 1),
        for (final update in <Map<String, Object>>[
          {'version': 2},
          {'version': 1.0},
          {'version': true},
          {'kind': 'production'},
          {'extra': 'secret'},
          {'leaf_sha256': 'A' * 64},
          {'client_sha256': 'b' * 63},
          {'ca_der': ''},
          {'ca_der': '!!!!'},
          {'pkcs12': 'BAUG\n'},
          {'ca_der': base64Encode(List.filled(65537, 1))},
          {'pkcs12': base64Encode(List.filled(1048577, 1))},
          {'import_passphrase': ''},
          {'unlock_password': 'é' * 2049},
          for (final url in [
            'http://fixture.example',
            'https://user@fixture.example',
            'https://fixture.example?x',
            'https://fixture.example#x',
            'https://fixture.example/other',
            'https://fixture.example:0',
            'https://fixture.example:65536',
            'https://fixture.example/\\x',
          ])
            {'endpoint': url},
        ])
          jsonEncode({...valid, ...update}),
        jsonEncode({...valid}..remove('pkcs12')),
      ];
      for (final input in invalid) {
        expect(
          () => PilotBundle.parse(input),
          throwsA(
            isA<FormatException>()
                .having(
                  (e) => e.message,
                  'fixed error',
                  'Invalid disposable pilot bundle',
                )
                .having((e) => e.source, 'no retained source', isNull),
          ),
        );
      }
    },
  );

  test('native channel gate and payload omit the unlock password', () async {
    const channel = MethodChannel('test/pilot-channel');
    final calls = <MethodCall>[];
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          calls.add(call);
          return {
            'configured': true,
            'endpoint': 'https://fixture.example/v1/companion',
            'pin': 'a' * 64,
            'fingerprint': 'b' * 64,
            'uncertainId': '',
          };
        });
    final native = NativeProviderPlatform(macOS: true, channel: channel);
    final bundle = PilotBundle.parse(jsonEncode(fixtureBundle()));
    if (!disposablePilotEnabled) {
      await expectLater(native.setupPilot(bundle), throwsUnsupportedError);
      expect(calls, isEmpty);
    } else {
      await native.setupPilot(bundle);
      expect(calls.single.method, 'setupDisposablePilotV1');
      expect(
        (calls.single.arguments as Map).containsKey('unlock_password'),
        false,
      );
      expect(
        (calls.single.arguments as Map)['import_passphrase'],
        'synthetic-import-only',
      );
    }
    await expectLater(
      NativeProviderPlatform(macOS: false, channel: channel).setupPilot(bundle),
      throwsUnsupportedError,
    );
  });

  test(
    'explicit setup imports once then unlocks once; normal build never imports',
    () async {
      final native = PilotFixture()..heldImport = Completer<void>();
      final controller = ProviderController(native);
      await controller.initialize();
      native.commands.clear();
      final operation = controller.setupPilot(jsonEncode(fixtureBundle()));
      await controller.setupPilot(jsonEncode(fixtureBundle()));
      expect(native.imports, disposablePilotEnabled ? 1 : 0);
      expect(native.commands, isEmpty);
      native.heldImport!.complete();
      await operation;
      expect(
        native.commands.where((c) => c['command'] == 'unlock').length,
        disposablePilotEnabled ? 1 : 0,
      );
      if (disposablePilotEnabled) {
        expect(native.commands.first, {
          'version': 1,
          'command': 'unlock',
          'password': 'synthetic-unlock-only',
        });
      }
      expect(
        native.commands.where(
          (c) => ['decision', 'review'].contains(c['command']),
        ),
        isEmpty,
      );
      controller.dispose();
    },
  );

  test(
    'failed import or mismatched identity never sends any follow-on command',
    () async {
      for (final mismatch in [false, true]) {
        final native = PilotFixture()
          ..mismatch = mismatch
          ..failImport = !mismatch;
        final controller = ProviderController(native);
        await controller.initialize();
        native.commands.clear();
        await controller.setupPilot(jsonEncode(fixtureBundle()));
        expect(native.commands, isEmpty);
        expect(controller.diagnostic, isNot(contains('secret must')));
        controller.dispose();
      }
    },
  );

  test('invalid bundle fails before import', () async {
    final native = PilotFixture();
    final controller = ProviderController(native);
    await controller.initialize();
    native.commands.clear();
    await controller.setupPilot('{secret-invalid');
    expect(native.imports, 0);
    expect(native.commands, isEmpty);
    controller.dispose();
  });

  test('unresolved decision, committed request and busy operation block replacement', () async {
    for (final mode in ['uncertain', 'committed', 'busy']) {
      resetProvider();
      final native = PilotFixture()..loseDecision = mode == 'uncertain';
      final controller = ProviderController(native);
      await controller.initialize();
      await controller.review(providerId);
      Future<void>? held;
      if (mode == 'busy') {
        native.heldDecision = Completer<Uint8List>();
        held = controller.decide(false, '');
      } else {
        await controller.decide(true, 'synthetic');
      }
      final count = native.commands.length;
      await controller.setupPilot(jsonEncode(fixtureBundle()));
      expect(native.imports, 0);
      expect(native.commands.length, count);
      if (held != null) {
        native.heldDecision!.complete(
          encoded({
            'version': 1,
            'status': {'status': 'denied'},
          }),
        );
        await held;
      }
      controller.dispose();
    }
  });

  test('lifecycle, route and disposal invalidate import continuation without automatic unlock', () async {
    for (final mode in ['sleep', 'route', 'dispose']) {
      final native = PilotFixture()..heldImport = Completer<void>();
      final controller = ProviderController(native);
      await controller.initialize();
      native.commands.clear();
      final operation = controller.setupPilot(jsonEncode(fixtureBundle()));
      if (mode == 'sleep') controller.suspend();
      if (mode == 'route') controller.setRouteCurrent(false);
      if (mode == 'dispose') controller.dispose();
      native.heldImport!.complete();
      await operation;
      expect(native.commands, isEmpty);
      if (mode != 'dispose') {
        if (mode == 'sleep') controller.resume();
        if (mode == 'route') controller.setRouteCurrent(true);
        await Future<void>.delayed(Duration.zero);
        expect(native.commands.where((c) => c['command'] == 'unlock'), isEmpty);
        controller.dispose();
      }
    }
  });

  testWidgets(
    'pilot UI is gated, explicit and clears pasted input on lifecycle and use',
    (tester) async {
      tester.view.physicalSize = const Size(1200, 2400);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final native = PilotFixture();
      await tester.pumpWidget(
        MaterialApp(
          home: ProviderPage(
            platform: native,
            syntheticBuilder: (_) => const Text('synthetic'),
          ),
        ),
      );
      await tester.pumpAndSettle();
      final field = find.byKey(const Key('pilot-bundle'));
      if (!disposablePilotEnabled) {
        expect(field, findsNothing);
        expect(find.text('Configure and unlock'), findsNothing);
      } else {
        expect(field, findsOneWidget);
        await tester.enterText(field, jsonEncode(fixtureBundle()));
        expect(native.imports, 0);
        tester.binding.handleAppLifecycleStateChanged(
          AppLifecycleState.inactive,
        );
        await tester.pump();
        expect(tester.widget<TextField>(field).controller!.text, isEmpty);
        tester.binding.handleAppLifecycleStateChanged(
          AppLifecycleState.resumed,
        );
        await tester.pumpAndSettle();
        await tester.enterText(field, jsonEncode(fixtureBundle()));
        await tester.tap(find.text('Configure and unlock'));
        await tester.pumpAndSettle();
        expect(tester.widget<TextField>(field).controller!.text, isEmpty);
        expect(native.imports, 1);
        expect(
          native.commands.where((c) => c['command'] == 'unlock'),
          hasLength(1),
        );
      }
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );
}
