import 'dart:io';

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';

import '../src/rust/frb_generated.dart';

/// Load only the library packaged with this executable. Development tests use
/// the generator's explicit rust/target/release path in their own process.
Future<void> initializePackagedCore() async {
  if (Platform.isIOS) {
    // iOS links companion_core statically into the Runner (force_load), so
    // its symbols are in this process; nothing is loaded from a path.
    await RustLib.init(
      externalLibrary: ExternalLibrary.process(iKnowHowToUseIt: true),
    );
    return;
  }
  final executable = File(Platform.resolvedExecutable).parent;
  final String path;
  if (Platform.isMacOS) {
    path = '${executable.parent.path}/Frameworks/libcompanion_core.dylib';
  } else if (Platform.isWindows) {
    path = '${executable.path}/companion_core.dll';
  } else if (Platform.isLinux) {
    path = '${executable.path}/lib/libcompanion_core.so';
  } else {
    throw UnsupportedError('Desktop companion only');
  }
  await RustLib.init(externalLibrary: ExternalLibrary.open(path));
}
