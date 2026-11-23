import 'dart:io';

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';

import '../src/rust/frb_generated.dart';

/// Where the packaged Rust core lives for [operatingSystem]; null when the
/// core is linked into the process itself (iOS: the `staticlib` is linked
/// into the Runner, so `ExternalLibrary.process` finds its symbols).
/// [executableDirectory] is the directory of `Platform.resolvedExecutable`.
String? packagedCorePath(
  String operatingSystem,
  String executableDirectory,
) => switch (operatingSystem) {
  'macos' =>
    '${Directory(executableDirectory).parent.path}/Frameworks/libcompanion_core.dylib',
  'windows' => '$executableDirectory/companion_core.dll',
  'linux' => '$executableDirectory/lib/libcompanion_core.so',
  // The APK's jniLibs/<abi>/libcompanion_core.so: the dynamic linker
  // resolves the bare name inside the app's native library directory.
  'android' => 'libcompanion_core.so',
  'ios' => null,
  _ => throw UnsupportedError('Unsupported companion platform'),
};

/// Load only the library packaged with this executable. Development tests use
/// the generator's explicit rust/target/release path in their own process.
Future<void> initializePackagedCore() async {
  final path = packagedCorePath(
    Platform.operatingSystem,
    File(Platform.resolvedExecutable).parent.path,
  );
  await RustLib.init(
    externalLibrary: path == null
        ? ExternalLibrary.process(iKnowHowToUseIt: true)
        : ExternalLibrary.open(path),
  );
}
