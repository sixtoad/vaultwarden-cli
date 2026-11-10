// Exact visual baselines for guided enrollment (#59 phase 2): the joining
// device's comparison step and the owner's approval form, light and dark.
// Same host selection, fonts and no-tolerance rule as access_golden_test.dart
// (see goldens/README.md). Synthetic fixture data only.
import 'dart:ffi' show Abi;
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:companion_slice/design/access_theme.dart';
import 'package:companion_slice/design/components.dart';
import 'package:companion_slice/provider/controller.dart';
import 'package:companion_slice/provider/enrollment_flow.dart';
import 'package:companion_slice/provider/enrollment_view.dart';
import 'package:companion_slice/src/rust/api/enrollment.dart' as enroll;
import 'package:companion_slice/src/rust/frb_generated.dart';

import 'enrollment_support.dart';
import 'provider_support.dart';

/// Keep the actual pixels of every enrollment capture, also when the host
/// has no reference yet. The exact comparison still decides; captures are
/// review evidence and never become references automatically.
class EnrollmentCaptureComparator extends GoldenFileComparator {
  EnrollmentCaptureComparator(this.delegate);
  final GoldenFileComparator delegate;
  @override
  Future<bool> compare(Uint8List imageBytes, Uri golden) async {
    final parts = golden.pathSegments;
    final directory = Directory('test/failures')..createSync(recursive: true);
    File('${directory.path}/${parts[parts.length - 2]}_${parts.last}')
        .writeAsBytesSync(imageBytes);
    return delegate.compare(imageBytes, golden);
  }

  @override
  Future<void> update(Uri golden, Uint8List imageBytes) =>
      delegate.update(golden, imageBytes);
  @override
  Uri getTestUri(Uri key, int? version) => delegate.getTestUri(key, version);
}

String goldenHost() {
  if (!Platform.isMacOS) return Platform.operatingSystem;
  final result = Process.runSync('/usr/bin/sw_vers', ['-productVersion']);
  final version = (result.stdout as String).trim();
  if (result.exitCode != 0 ||
      !RegExp(r'^[0-9]+(?:\.[0-9]+){1,2}$').hasMatch(version)) {
    throw StateError('Cannot identify the macOS golden renderer version');
  }
  final architecture = switch (Abi.current()) {
    Abi.macosArm64 => 'arm64',
    Abi.macosX64 => 'x64',
    _ => throw StateError('Unrecognized macOS golden renderer ABI'),
  };
  return 'macos-${version.split('.').first}-$architecture';
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final host = goldenHost();
  final comparator = goldenFileComparator;
  goldenFileComparator = EnrollmentCaptureComparator(comparator);
  tearDownAll(() => goldenFileComparator = comparator);
  setUpAll(() async {
    await RustLib.init();
    final fonts = [
      for (final weight in ['Regular', 'Medium', 'Bold'])
        ByteData.sublistView(
          File('test/fonts/Roboto-$weight.ttf').readAsBytesSync(),
        ),
    ];
    for (final family in [
      'Roboto',
      'monospace',
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
    await (FontLoader('MaterialIcons')..addFont(
          Future.value(
            ByteData.sublistView(
              File('test/fonts/MaterialIcons-Regular.otf').readAsBytesSync(),
            ),
          ),
        ))
        .load();
  });
  setUp(() {
    resetProvider();
    enroll.enrollmentJoinerReset();
    enroll.enrollmentAdminInvalidate();
  });

  Future<void> frame(
    WidgetTester tester,
    Brightness brightness,
    Widget child, {
    double height = 760,
  }) async {
    tester.view.physicalSize = Size(900, height);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(
      MaterialApp(
        locale: const Locale('en', 'US'),
        theme: accessTheme(brightness),
        home: RepaintBoundary(
          key: const Key('golden'),
          child: Scaffold(
            body: SingleChildScrollView(
              padding: const EdgeInsets.all(24),
              child: child,
            ),
          ),
        ),
      ),
    );
    await tester.pump();
  }

  for (final brightness in Brightness.values) {
    testWidgets('joining device comparison ${brightness.name}', (tester) async {
      await frame(
        tester,
        brightness,
        AccessPanel(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const AccessHeading(
                'Join this device to a provider',
                'Uses this app\'s provider connection and client certificate. Enrolling makes this device an approval client, never an administrator.',
              ),
              JoinerComparison(
                code: '4821-0937',
                label: 'Studio Mac',
                secondsRemaining: 562,
                waiting: false,
                providerApproved: false,
                onConfirm: () {},
                onDecline: () {},
                onCancel: () {},
              ),
            ],
          ),
        ),
      );
      await expectLater(
        find.byKey(const Key('golden')),
        matchesGoldenFile(
          'goldens/$host/${brightness.name}_join_enrollment.png',
        ),
      );
    }, variant: TargetPlatformVariant.only(TargetPlatform.android));

    testWidgets('owner approval form ${brightness.name}', (tester) async {
      final platform = EnrollmentPlatform();
      final controller = ProviderController(platform);
      final password =
          TextEditingController(); // secrets-ignore: test UI controller
      final flow = EnrollmentFlow(controller, tick: const Duration(days: 1));
      await controller.initialize();
      await flow.open(EnrollmentMode.add);
      await flow.invite(
        role: enroll.EnrolleeRole.companion,
        label: 'Studio Mac',
      );
      await flow.join(flow.admin.issued!.invitationCode);
      flow.dismissInvitation();
      await flow.list();
      flow.select(flow.admin.sessions.single.id);
      await frame(
        tester,
        brightness,
        ListenableBuilder(
          listenable: flow,
          builder: (context, _) =>
              EnrollmentAddPanel(flow: flow, password: password),
        ),
        height: 1320,
      );
      await tester.enterText(
        find.byKey(const Key('approve-code')),
        '4821-0937',
      );
      // Settle the floating label and hide the blinking caret.
      FocusManager.instance.primaryFocus?.unfocus();
      await tester.pump(const Duration(milliseconds: 400));
      await expectLater(
        find.byKey(const Key('golden')),
        matchesGoldenFile(
          'goldens/$host/${brightness.name}_approve_enrollment.png',
        ),
      );
      flow.dispose();
      controller.dispose();
      password.dispose();
    }, variant: TargetPlatformVariant.only(TargetPlatform.android));
  }
}
