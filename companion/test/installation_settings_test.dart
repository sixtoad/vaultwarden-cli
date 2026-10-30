import 'dart:io';
import 'dart:ui' as ui;

import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:companion_slice/design/access_theme.dart';
import 'package:companion_slice/platform/installation.dart';
import 'package:companion_slice/provider/installation_settings.dart';
import 'package:companion_slice/provider/support_views.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

class FakeInstallation implements InstallationPlatform {
  FakeInstallation({
    this.desktop = true,
    this.state = 'compatible',
    this.protected = false,
  });
  @override
  final bool desktop;
  final String state;
  final bool protected;
  int inspections = 0, enables = 0;
  @override
  bool get usesDirectoryPicker => false;
  @override
  String get suggestedDirectory => '/home/operator/user bin';
  @override
  Future<InstallationStatus> inspect() async {
    inspections++;
    return InstallationStatus({
      'state': state,
      'detail': 'Bundle compatibility is independent of version equality.',
      'app_version': '0.1.0+1',
      'cli_version': '0.5.4',
      'bundle': '/home/operator/Applications/companion_slice',
      'manifest_sha256': 'a' * 64,
      'commands': {
        'vaultwarden-cli': '/home/operator/Applications/companion_slice/commands/vaultwarden-cli',
      },
      'resolved': <String, String>{},
      'roles': {
        'protected_requesting': protected,
        'desktop_approval': false,
        'protected_provider': protected,
        'vault_cli': true,
      },
    });
  }

  @override
  Future<String?> enable(String directory) async {
    enables++;
    return 'Commands enabled in $directory. Add this directory to your user PATH.';
  }
}

Future<void> show(
  WidgetTester tester,
  FakeInstallation platform, {
  Size size = const Size(1000, 1600),
  bool dark = false,
  double scale = 1,
}) async {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  await tester.pumpWidget(
    MaterialApp(
      builder: (context, child) => MediaQuery(
        data: MediaQuery.of(context)
            .copyWith(textScaler: TextScaler.linear(scale)),
        child: child!,
      ),
      theme: accessTheme(dark ? Brightness.dark : Brightness.light),
      home: RepaintBoundary(
        key: const Key('installation-capture'),
        child: Scaffold(
          body: SingleChildScrollView(
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: InstallationSettings(platform: platform),
            ),
          ),
        ),
      ),
    ),
  );
  await tester.pumpAndSettle();
}

void main() {
  setUpAll(() async {
    final fonts = [
      for (final weight in ['Regular', 'Medium', 'Bold'])
        ByteData.sublistView(
          File('test/fonts/Roboto-$weight.ttf').readAsBytesSync(),
        ),
    ];
    for (final family in [
      'Roboto',
      '.SF UI Text',
      '.SF UI Display',
      '.AppleSystemUIFont',
      'CupertinoSystemText',
      'CupertinoSystemDisplay',
      'Segoe UI',
    ]) {
      final loader = FontLoader(family);
      for (final bytes in fonts) {
        loader.addFont(Future.value(bytes));
      }
      await loader.load();
    }
  });
  final captureDirectory = Platform.environment['INSTALLATION_CAPTURE_DIR'];
  if (captureDirectory != null) {
    for (final dark in [false, true]) {
      for (final layout in ['desktop', 'compact', 'large']) {
        testWidgets('installation capture ${dark ? 'dark' : 'light'} $layout', (
          tester,
        ) async {
          await show(
            tester,
            FakeInstallation(),
            size: layout == 'desktop'
                ? const Size(1200, 1600)
                : const Size(390, 1000),
            dark: dark,
            scale: layout == 'large' ? 2 : 1,
          );
          Future<void> capture(String suffix) async {
            final boundary = tester.renderObject<RenderRepaintBoundary>(
              find.byKey(const Key('installation-capture')),
            );
            await tester.runAsync(() async {
              final image = await boundary.toImage();
              final bytes = await image.toByteData(
                format: ui.ImageByteFormat.png,
              );
              final destination = Directory(captureDirectory);
              destination.createSync(recursive: true);
              File(
                '${destination.path}/${dark ? 'dark' : 'light'}_${layout}_$suffix.png',
              ).writeAsBytesSync(bytes!.buffer.asUint8List());
              image.dispose();
            });
          }

          await capture('top');
          await tester.ensureVisible(find.byKey(const Key('enable-commands')));
          await tester.pumpAndSettle();
          await capture('controls');
          expect(tester.takeException(), isNull);
        });
      }
    }
  }

  testWidgets(
    'actual mobile excludes inspection and installation even in wide layout',
    (tester) async {
      final platform = FakeInstallation(desktop: false);
      await show(tester, platform);
      expect(find.byKey(const Key('desktop-installation')), findsNothing);
      expect(platform.inspections, 0);
      expect(platform.enables, 0);
    },
  );
  testWidgets(
    'compact desktop retains real controls and truthful unsupported roles',
    (tester) async {
      final platform = FakeInstallation();
      await show(tester, platform, size: const Size(390, 1200));
      expect(find.byKey(const Key('desktop-installation')), findsOneWidget);
      expect(
        find.textContaining(
          'Protected requesting and provider execution with vw-access are unavailable',
        ),
        findsOneWidget,
      );
      expect(find.text('0.1.0+1'), findsOneWidget);
      expect(find.text('0.5.4'), findsOneWidget);
      expect(find.text('Not found on the application PATH'), findsOneWidget);
      await tester.ensureVisible(find.byKey(const Key('enable-commands')));
      await tester.tap(find.byKey(const Key('enable-commands')));
      await tester.pumpAndSettle();
      expect(platform.enables, 1);
      expect(
        find.textContaining('Add this directory to your user PATH.'),
        findsOneWidget,
      );
      expect(tester.takeException(), isNull);
    },
  );
  testWidgets(
    'protected roles describe the bundled provider without claiming installation',
    (tester) async {
      await show(tester, FakeInstallation(protected: true));
      expect(
        find.textContaining(
          'The bundled provider (Linux, or macOS on Apple Silicon) requires separate reviewed installation',
        ),
        findsOneWidget,
      );
      expect(
        find.textContaining('does not install or start a service'),
        findsOneWidget,
      );
      expect(
        find.textContaining('Protected requesting and provider execution'),
        findsNothing,
      );
    },
  );
  testWidgets(
    'native capabilities state macOS arm64 packaging limits truthfully',
    (tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: SingleChildScrollView(child: ProviderCapabilities()),
          ),
        ),
      );
      expect(
        find.textContaining(
          'macOS on Apple Silicon (arm64): the desktop bundle includes vw-access and the native vaultwarden-accessd provider.',
        ),
        findsOneWidget,
      );
      expect(find.textContaining('nothing installs them yet'), findsOneWidget);
      expect(find.textContaining('Development signing only.'), findsOneWidget);
      expect(
        find.textContaining('Intel Macs and Rosetta are unsupported.'),
        findsOneWidget,
      );
      expect(
        find.textContaining(
          'Guided enrollment and notifications are not available.',
        ),
        findsOneWidget,
      );
    },
  );
  for (final state in ['missing', 'damaged', 'incompatible']) {
    testWidgets('$state bundle cannot activate', (tester) async {
      final platform = FakeInstallation(state: state);
      await show(tester, platform);
      final button = tester.widget<FilledButton>(
        find.byKey(const Key('enable-commands')),
      );
      expect(button.onPressed, isNull);
      expect(platform.enables, 0);
    });
  }
}
