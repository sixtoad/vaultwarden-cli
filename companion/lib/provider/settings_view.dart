import 'package:flutter/material.dart';

import '../design/components.dart';
import '../platform/installation.dart';
import 'controller.dart';
import 'installation_settings.dart';
import 'pilot_bundle.dart';
import 'review_notifications.dart';
import 'support_views.dart';
import 'touch_id.dart';
import 'touch_id_views.dart';

/// The Settings destination. Every action is a callback owned by the page,
/// which clears all secrets before it starts an operation.
class ProviderSettings extends StatelessWidget {
  const ProviderSettings({
    super.key,
    required this.controller,
    required this.notifier,
    required this.touchId,
    this.installation,
    this.installationControls = true,
    required this.pilotOffered,
    required this.appearance,
    required this.onAppearance,
    required this.dedicated,
    required this.onDedicated,
    required this.endpoint,
    required this.pin,
    this.caPath,
    this.identityPath,
    required this.importPassword,
    required this.pilotBundle,
    required this.touchIdPassword,
    required this.onSetupPilot,
    required this.onSetup,
    required this.onOpenSynthetic,
  });
  final ProviderController controller;
  final ReviewNotifier notifier;
  final TouchIdController touchId;
  final InstallationPlatform? installation;

  /// Desktop installation inspection/enablement; never on a phone (#60).
  final bool installationControls;

  /// The disposable pilot is compiled in and the platform supports it.
  final bool pilotOffered;
  final ThemeMode appearance;
  final ValueChanged<ThemeMode> onAppearance;
  final bool dedicated;
  final ValueChanged<bool> onDedicated;
  final TextEditingController endpoint, pin, importPassword, pilotBundle;

  /// Set on Windows and Linux: the CA and the PKCS#12 are read by absolute
  /// path (desktop-approval-spec D-4); null where native dialogs select them.
  final TextEditingController? caPath, identityPath;
  final TextEditingController touchIdPassword;
  final VoidCallback onSetupPilot, onSetup, onOpenSynthetic;

  @override
  Widget build(BuildContext context) {
    final config = controller.configuration;
    return AccessPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const AccessHeading(
            'Settings',
            'Appearance, native capabilities and advanced development setup',
          ),
          DropdownButtonFormField<ThemeMode>(
            initialValue: appearance,
            isExpanded: true,
            decoration: const InputDecoration(labelText: 'Appearance'),
            items: const [
              DropdownMenuItem(value: ThemeMode.system, child: Text('System')),
              DropdownMenuItem(value: ThemeMode.light, child: Text('Light')),
              DropdownMenuItem(value: ThemeMode.dark, child: Text('Dark')),
            ],
            onChanged: (value) {
              if (value != null) onAppearance(value);
            },
          ),
          const SizedBox(height: 24),
          ReviewNotificationSettings(notifier: notifier),
          const SizedBox(height: 24),
          if (installationControls)
            InstallationSettings(platform: installation),
          if (config.configured && touchId.operatingSystem == 'linux') ...[
            // No hardware user-verification key on Linux (spec D-9).
            const Text(
              'Approval key: none on Linux. Approve each request with your provider password.',
              key: Key('linux-password-approval'),
            ),
            const SizedBox(height: 24),
          ] else if (config.configured) ...[
            TouchIdKeyPanel(
              touchId: touchId,
              keys: controller.keys,
              password: touchIdPassword, // secrets-ignore: UI controller
              enabled: controller.canManage && !controller.managementPending,
            ),
            const SizedBox(height: 24),
          ],
          const ProviderCapabilities(),
          const SizedBox(height: 24),
          if (pilotOffered) ...[
            const Text(
              'Disposable test only. This bundle contains a private identity and test passwords. Never paste real vault credentials.',
            ),
            TextField(
              key: const Key('pilot-bundle'),
              controller: pilotBundle,
              enabled: controller.canSetupPilot,
              obscureText: true,
              maxLength: PilotBundle.maximumLength,
              enableSuggestions: false,
              autocorrect: false,
              enableIMEPersonalizedLearning: false,
              decoration: const InputDecoration(
                labelText: 'Paste disposable test bundle',
                counterText: '',
              ),
            ),
            FilledButton(
              onPressed: controller.canSetupPilot ? onSetupPilot : null,
              child: const Text('Configure and unlock'),
            ),
            const SizedBox(height: 20),
          ],
          ExpansionTile(
            title: const Text('Advanced development provider setup'),
            initiallyExpanded: !config.configured,
            children: [
              Text(
                caPath == null
                    ? 'Use a separately issued and enrolled Flutter development client certificate. Do not import the installed Swift companion identity. Select the private CA in DER format and the dedicated PKCS#12 in the native file dialogs.'
                    : 'Use a separately issued and enrolled development client certificate. Enter the absolute paths of the private CA in DER format and the dedicated PKCS#12. The files are read once; the identity is then kept for your user account only.',
              ),
              TextField(
                controller: endpoint,
                enabled: controller.canSetup,
                decoration: const InputDecoration(
                  labelText: 'HTTPS provider endpoint',
                ),
              ),
              TextField(
                controller: pin,
                enabled: controller.canSetup,
                decoration: const InputDecoration(
                  labelText: 'Trusted server leaf SHA-256 (64 lowercase hex)',
                ),
              ),
              if (caPath case final caPath?)
                TextField(
                  key: const Key('setup-ca-path'),
                  controller: caPath,
                  enabled: controller.canSetup,
                  decoration: const InputDecoration(
                    labelText: 'Provider CA path (DER)',
                  ),
                ),
              if (identityPath case final identityPath?)
                TextField(
                  key: const Key('setup-identity-path'),
                  controller: identityPath,
                  enabled: controller.canSetup,
                  decoration: const InputDecoration(
                    labelText: 'Client identity path (PKCS#12)',
                  ),
                ),
              accessPassword(importPassword, 'PKCS#12 import passphrase'),
              CheckboxListTile(
                value: dedicated,
                onChanged: controller.canSetup
                    ? (value) => onDedicated(value ?? false)
                    : null,
                title: const Text(
                  'This is a dedicated development identity, separately enrolled on Linux.',
                ),
              ),
              FilledButton(
                onPressed: controller.canSetup && dedicated ? onSetup : null,
                child: Text(
                  caPath == null
                      ? 'Select CA and import dedicated identity'
                      : 'Import CA and dedicated identity',
                ),
              ),
            ],
          ),
          if (!config.configured)
            OutlinedButton(
              onPressed: controller.busy ? null : controller.refresh,
              child: const Text('Reload saved provider setup'),
            ),
          const SizedBox(height: 24),
          OutlinedButton(
            onPressed:
                controller.busy ||
                    controller.recoveryId.isNotEmpty ||
                    controller.managementPending
                ? null
                : onOpenSynthetic,
            child: const Text('Open separate synthetic signing demonstration'),
          ),
        ],
      ),
    );
  }
}
