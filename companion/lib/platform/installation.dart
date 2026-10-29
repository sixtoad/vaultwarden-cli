import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';

import '../src/rust/api/installation.dart' as core;

class InstallationStatus {
  InstallationStatus(Map<String, dynamic> data)
    : state = data['state'] as String,
      detail = data['detail'] as String,
      appVersion = data['app_version'] as String,
      cliVersion = data['cli_version'] as String,
      bundle = data['bundle'] as String,
      identity = data['manifest_sha256'] as String,
      commands = Map<String, String>.from(data['commands'] as Map),
      resolved = Map<String, String>.from(data['resolved'] as Map),
      roles = Map<String, bool>.from(data['roles'] as Map);
  final String state, detail, appVersion, cliVersion, bundle, identity;
  final Map<String, String> commands, resolved;
  final Map<String, bool> roles;
  bool get canEnable => state == 'compatible' || state == 'conflicting';
}

abstract interface class InstallationPlatform {
  bool get desktop;
  bool get usesDirectoryPicker;
  String get suggestedDirectory;
  Future<InstallationStatus> inspect();
  Future<String?> enable(String directory);
}

class DesktopInstallation implements InstallationPlatform {
  static const channel = MethodChannel(
    'dev.vaultwarden.companionSlice/installation',
  );
  @override
  bool get desktop =>
      Platform.isMacOS || Platform.isWindows || Platform.isLinux;
  @override
  bool get usesDirectoryPicker => Platform.isMacOS;
  @override
  String get suggestedDirectory => Platform.isWindows
      ? '${Platform.environment['USERPROFILE'] ?? ''}\\AppData\\Local\\Vaultwarden\\bin'
      : '${Platform.environment['HOME'] ?? ''}/.local/bin';
  String get root {
    final executable = File(Platform.resolvedExecutable).parent;
    return Platform.isMacOS ? executable.parent.parent.path : executable.path;
  }

  @override
  Future<InstallationStatus> inspect() async => InstallationStatus(
    jsonDecode(
      await core.inspectInstallation(
        root: root,
        path: Platform.environment['PATH'] ?? '',
      ),
    ) as Map<String, dynamic>,
  );
  @override
  Future<String?> enable(String directory) async {
    if (!desktop) throw UnsupportedError('Desktop command installation only');
    if (usesDirectoryPicker) {
      final selected = await channel.invokeMethod<String>(
        'selectCommandDirectory',
      );
      if (selected == null) return null;
      try {
        return await core.enableCommands(root: root, directory: selected);
      } finally {
        await channel.invokeMethod<void>('releaseCommandDirectory');
      }
    }
    return core.enableCommands(root: root, directory: directory);
  }
}
