import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:companion_slice/platform/core_provider.dart';
import 'package:companion_slice/platform/provider.dart';
import 'package:companion_slice/provider/page.dart';
import 'package:companion_slice/src/rust/frb_generated.dart';

import 'golden_support.dart';
import 'installation_settings_test.dart' show FakeInstallation;
import 'provider_support.dart';

/// Answers the identity list with this approval client and one requester
/// agent, so Devices shows a populated inventory.
class InventoryProvider extends FixtureProviderPlatform {
  Map<String, dynamic> identity(String kind, String id, String label) => {
    'kind': kind,
    'id': id,
    'label': label,
    'fingerprint': (kind == 'approval_client' ? 'd' : 'e') * 64,
    'roles': [kind == 'approval_client' ? 'approve' : 'request'],
    'trust': 'enabled',
    'this_client': kind == 'approval_client',
  };

  @override
  Future<Uint8List> send(Uint8List body) async {
    final command = jsonDecode(utf8.decode(body)) as Map<String, dynamic>;
    if (command['command'] != 'identity_list') return super.send(body);
    commands.add(command);
    return encoded({
      'version': 2,
      'identities': [
        identity('approval_client', 'd' * 64, 'Synthetic desktop'),
        identity('requester_agent', providerId, 'agent synthetic'),
      ],
      'next_cursor': null,
      'generation': 1,
      'provider': {
        'fingerprint': 'f' * 64,
        'execution_configured': true,
        'execution_available': true,
      },
    });
  }
}

/// Windows and Linux setup (desktop-approval-spec D-4): an unconfigured
/// transport that reads the CA and PKCS#12 by path.
class PathSetupProvider extends FixtureProviderPlatform
    implements PathSetupPlatform {
  PathSetupProvider() {
    saved = const ProviderConfiguration(configured: false);
  }
  @override
  Future<ProviderConfiguration> setupFromFiles(
    String endpoint,
    String pin,
    String caPath,
    String identityPath,
    String passphrase,
  ) async => saved;
}

/// Shell captures (#50 slice 1, cleanup): the Requests list in five states
/// (disconnected included), Devices (unavailable and populated inventory)
/// and Settings, light/dark, desktop/compact; Devices and Settings also at
/// 200% text. Only the synthetic provider fixture is rendered.
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final host = goldenHost();
  final comparator = goldenFileComparator;
  goldenFileComparator = CaptureComparator(comparator);
  tearDownAll(() => goldenFileComparator = comparator);
  setUpAll(() async {
    await RustLib.init();
    await loadGoldenFonts();
  });
  setUp(resetProvider);

  final secondId = base64Url
      .encode(List<int>.filled(32, 7))
      .replaceAll('=', '');
  final scenes = <String, (String, FixtureProviderPlatform Function())>{
    'empty': ('requests', () => FixtureProviderPlatform()..requestIds = []),
    'two': (
      'requests',
      () => FixtureProviderPlatform()..requestIds = [providerId, secondId],
    ),
    'locked': (
      'requests',
      () => FixtureProviderPlatform()
        ..sessionReply = encoded({
          'version': 1,
          'state': 'locked',
          'generation': 1,
        }),
    ),
    'recovery': (
      'requests',
      () => FixtureProviderPlatform()..savePending(providerId),
    ),
    'disconnected': ('requests', UnreachableProvider.new),
    'devices': ('devices', FixtureProviderPlatform.new),
    'inventory': ('devices', InventoryProvider.new),
    'settings': ('settings', FixtureProviderPlatform.new),
    'filesetup': ('settings', PathSetupProvider.new),
  };
  // 200% text (compact window) for the workpages only.
  const largeScenes = {'devices', 'inventory', 'settings'};

  for (final brightness in Brightness.values) {
    for (final layout in ['desktop', 'compact', 'large']) {
      for (final scene in scenes.entries) {
        if (layout == 'large' && !largeScenes.contains(scene.key)) continue;
        testWidgets('shell ${scene.key} ${brightness.name} $layout', (
          tester,
        ) async {
          tester.view.physicalSize = layout == 'desktop'
              ? const Size(1440, 900)
              : const Size(390, 844);
          tester.view.devicePixelRatio = 1;
          tester.platformDispatcher.platformBrightnessTestValue = brightness;
          addTearDown(tester.view.resetPhysicalSize);
          addTearDown(tester.view.resetDevicePixelRatio);
          addTearDown(
            tester.platformDispatcher.clearPlatformBrightnessTestValue,
          );
          await tester.pumpWidget(
            MaterialApp(
              locale: const Locale('en', 'US'),
              builder: (context, child) => MediaQuery(
                data: MediaQuery.of(context).copyWith(
                  textScaler: TextScaler.linear(layout == 'large' ? 2 : 1),
                ),
                child: child!,
              ),
              home: RepaintBoundary(
                key: const Key('golden'),
                child: ProviderPage(
                  platform: scene.value.$2(),
                  installation: FakeInstallation(),
                  syntheticBuilder: (_) => const Text('Synthetic only'),
                ),
              ),
            ),
          );
          await tester.pumpAndSettle();
          final destination = scene.value.$1;
          if (destination != 'requests') {
            await tester.tap(find.byKey(Key('destination-$destination')));
            await tester.pumpAndSettle();
          }
          if (scene.key == 'filesetup') {
            await Scrollable.ensureVisible(
              tester.element(find.byKey(const Key('setup-ca-path'))),
              alignment: 0.2,
            );
            await tester.pumpAndSettle();
          }
          if (scene.key == 'inventory') {
            // Bring the identity list itself into view.
            await Scrollable.ensureVisible(
              tester.element(find.text('Refresh provider identities')),
              alignment: 0.05,
            );
            await tester.pumpAndSettle();
          }
          // Hide the text caret of any focused field.
          FocusManager.instance.primaryFocus?.unfocus();
          await tester.pump(const Duration(milliseconds: 400));
          await expectLater(
            find.byKey(const Key('golden')),
            matchesGoldenFile(
              'goldens/$host/${brightness.name}_${layout}_shell_${scene.key}.png',
            ),
          );
          expect(tester.takeException(), isNull);
          await tester.pumpWidget(const SizedBox.shrink());
        }, variant: TargetPlatformVariant.only(TargetPlatform.android));
      }
    }
  }
}
