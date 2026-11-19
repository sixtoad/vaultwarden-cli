import 'dart:ffi' show Abi;
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

/// Copies every capture to `test/failures/<host>_<name>.png` (CI archives
/// that directory), then delegates the exact comparison. A missing
/// reference still fails; a capture never becomes a reference by itself.
class CaptureComparator extends GoldenFileComparator {
  CaptureComparator(this.delegate);
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

/// The reference directory for this renderer (see goldens/README.md).
String goldenHost() {
  if (!Platform.isMacOS) return Platform.operatingSystem;
  final result = Process.runSync('/usr/bin/sw_vers', ['-productVersion']);
  final version = (result.stdout as String).trim();
  if (result.exitCode != 0 ||
      !RegExp(r'^[0-9]+(?:\.[0-9]+){1,2}$').hasMatch(version)) {
    throw StateError('Cannot identify the macOS golden renderer version');
  }
  if (Abi.current() != Abi.macosArm64) {
    throw StateError(
      'Unsupported macOS golden renderer ABI (Apple Silicon only)',
    );
  }
  return 'macos-${version.split('.').first}-arm64';
}

/// Registers the bundled Roboto weights under every family the app may ask
/// for (including the monospace face) and the bundled Material icons.
Future<void> loadGoldenFonts() async {
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
}
