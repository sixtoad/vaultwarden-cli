import 'package:flutter/material.dart';

import '../design/components.dart';
import '../platform/installation.dart';

/// Runtime platform controls installation. A narrow desktop window is not a phone.
class InstallationSettings extends StatefulWidget {
  const InstallationSettings({super.key, this.platform});
  final InstallationPlatform? platform;
  @override
  State<InstallationSettings> createState() => _InstallationSettingsState();
}

class _InstallationSettingsState extends State<InstallationSettings> {
  late final platform = widget.platform ?? DesktopInstallation();
  late final directory = TextEditingController(
    text: platform.suggestedDirectory,
  );
  InstallationStatus? status;
  String? message;
  bool busy = false;
  @override
  void initState() {
    super.initState();
    if (platform.desktop) refresh();
  }

  @override
  void dispose() {
    directory.dispose();
    super.dispose();
  }

  Future<void> refresh() async {
    setState(() => busy = true);
    try {
      final value = await platform.inspect();
      if (mounted) setState(() => status = value);
    } catch (_) {
      if (mounted) {
        setState(
          () => message = 'Installation inspection failed. Obtain a complete desktop bundle or retry.',
        );
      }
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  Future<void> enable() async {
    setState(() {
      busy = true;
      message = null;
    });
    try {
      final result = await platform.enable(directory.text);
      if (mounted) {
        setState(() => message = result ?? 'Command enablement cancelled.');
      }
    } catch (error) {
      if (mounted) {
        setState(() => message = 'Commands were not enabled: $error');
      }
    } finally {
      if (mounted) await refresh();
    }
  }

  @override
  Widget build(BuildContext context) {
    if (!platform.desktop) return const SizedBox.shrink();
    final current = status;
    return Column(
      key: const Key('desktop-installation'),
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const AccessHeading(
          'Desktop installation',
          'App and terminal tools from one bundle',
        ),
        if (current != null) ...[
          FactRow('Installation', current.state),
          FactRow('App version', current.appVersion),
          FactRow(
            'Bundled CLI version',
            current.cliVersion.isEmpty ? 'Unavailable' : current.cliVersion,
          ),
          FactRow('Application bundle', current.bundle),
          if (current.identity.isNotEmpty)
            FactRow('Bundle identity (SHA-256)', current.identity),
          for (final command in current.commands.entries) ...[
            FactRow('Bundled ${command.key}', command.value),
            FactRow(
              'Terminal ${command.key}',
              current.resolved[command.key] ??
                  'Not found on the application PATH',
            ),
          ],
          Text(current.detail),
          const SizedBox(height: 12),
          Text(
            current.roles['protected_requesting'] == true
                ? 'vw-access can request approved work from a configured provider. The bundled provider (Linux, or macOS on Apple Silicon) requires separate reviewed installation and authorized configuration; enabling commands does not install or start a service.'
                : 'Protected requesting and provider execution with vw-access are unavailable on this platform. The bundled vaultwarden-cli is a vault client, not a protected approval client.',
          ),
          const SizedBox(height: 12),
          Text(
            current.roles['desktop_approval'] == true
                ? 'Desktop approval: macOS can approve through the existing pinned-TLS Linux-provider connection. Approving the native macOS provider from this app is tracked in #49.'
                : 'Desktop approval transport is not implemented on this platform.',
          ),
          const SizedBox(height: 12),
        ],
        const Text(
          'Enable or repair only a user command directory. Unrelated commands are never overwritten. PATH, credentials, enrollment and system services are not changed. A moved app needs explicit repair from its new location.',
        ),
        if (!platform.usesDirectoryPicker)
          TextField(
            key: const Key('command-directory'),
            controller: directory,
            enabled: !busy,
            decoration: const InputDecoration(labelText: 'User command folder'),
          ),
        const SizedBox(height: 12),
        Wrap(
          spacing: 12,
          runSpacing: 8,
          children: [
            FilledButton(
              key: const Key('enable-commands'),
              onPressed: !busy && current?.canEnable == true ? enable : null,
              child: Text(
                platform.usesDirectoryPicker
                    ? 'Choose user folder and enable / repair'
                    : 'Enable / repair user commands',
              ),
            ),
            OutlinedButton(
              onPressed: busy ? null : refresh,
              child: const Text('Check installation'),
            ),
          ],
        ),
        if (busy)
          const Padding(
            padding: EdgeInsets.only(top: 12),
            child: Text('Checking installation…'),
          ),
        if (message != null)
          Padding(
            padding: const EdgeInsets.only(top: 12),
            child: SelectableText(message!),
          ),
        const SizedBox(height: 12),
        const Text(
          'Upgrade: keep the previous complete bundle, extract the new bundle beside it, verify it and open the new app. Enable its commands only after inspection succeeds. If activation fails, the previous command setup stays active and a backup is kept beside the commands. Never merge files from two bundles.',
        ),
        const SizedBox(height: 24),
      ],
    );
  }
}
