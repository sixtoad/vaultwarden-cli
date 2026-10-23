import 'dart:async';

import 'package:flutter/material.dart';

import '../platform/provider.dart';
import 'controller.dart';
import 'pilot_bundle.dart';

class ProviderPage extends StatefulWidget {
  const ProviderPage({
    super.key,
    required this.platform,
    required this.syntheticBuilder,
  });
  final ProviderPlatform platform;
  final WidgetBuilder syntheticBuilder;
  @override
  State<ProviderPage> createState() => _ProviderPageState();
}

class _ProviderPageState extends State<ProviderPage>
    with WidgetsBindingObserver {
  late ProviderController controller;
  final endpoint = TextEditingController(), pin = TextEditingController();
  final importPassword = TextEditingController(),
      approvalPassword = TextEditingController(),
      unlockPassword = TextEditingController();
  final pilotBundle = TextEditingController();
  bool dedicated = false;
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    controller = ProviderController(widget.platform)
      ..clearPasswords = clearPasswords;
    controller.addListener(changed);
    unawaited(controller.initialize());
  }

  void changed() {
    if (mounted) setState(() {});
  }

  void clearPasswords() {
    importPassword.clear();
    approvalPassword.clear();
    unlockPassword.clear();
    pilotBundle.clear();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) controller.resume();
    if ([
      AppLifecycleState.inactive,
      AppLifecycleState.hidden,
      AppLifecycleState.paused,
      AppLifecycleState.detached,
    ].contains(state)) {
      controller.suspend();
    }
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    controller.removeListener(changed);
    controller.dispose();
    for (final field in [
      endpoint,
      pin,
      importPassword,
      approvalPassword,
      unlockPassword,
      pilotBundle,
    ]) {
      field.dispose();
    }
    super.dispose();
  }

  Widget password(TextEditingController field, String label) => TextField(
    controller: field,
    obscureText: true,
    enableSuggestions: false,
    autocorrect: false,
    enableIMEPersonalizedLearning: false,
    decoration: InputDecoration(labelText: label),
  );
  @override
  Widget build(BuildContext context) {
    final state = controller.state, config = controller.configuration;
    final enabled = widget.platform.available;
    return Scaffold(
      appBar: AppBar(title: const Text('Companion · provider approvals')),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 900),
          child: ListView(
            padding: const EdgeInsets.all(28),
            children: [
              if (!enabled)
                const Text(
                  'Provider transport unavailable on this platform. Provider approvals require macOS.',
                  key: Key('provider-unavailable'),
                ),
              const Text(
                'Linux keeps all secrets and executes approved operations. Each approval requires a fresh password.',
              ),
              const SizedBox(height: 20),
              if (disposablePilotEnabled &&
                  widget.platform is PilotProviderPlatform) ...[
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
                  onPressed: controller.canSetupPilot
                      ? () {
                          final input = pilotBundle.text;
                          clearPasswords();
                          unawaited(controller.setupPilot(input));
                        }
                      : null,
                  child: const Text('Configure and unlock'),
                ),
                const SizedBox(height: 20),
              ],
              ExpansionTile(
                title: const Text('Development provider setup'),
                initiallyExpanded: !config.configured,
                children: [
                  const Text(
                    'Use a separately issued and enrolled Flutter development client certificate. Do not import the installed Swift companion identity. Select the private CA in DER format and the dedicated PKCS#12 in the native file dialogs.',
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
                      labelText:
                          'Trusted server leaf SHA-256 (64 lowercase hex)',
                    ),
                  ),
                  password(importPassword, 'PKCS#12 import passphrase'),
                  CheckboxListTile(
                    value: dedicated,
                    onChanged: controller.canSetup
                        ? (value) => setState(() => dedicated = value ?? false)
                        : null,
                    title: const Text(
                      'This is a dedicated development identity, separately enrolled on Linux.',
                    ),
                  ),
                  FilledButton(
                    onPressed: controller.canSetup && dedicated
                        ? () {
                            final secret = importPassword.text; // secrets-ignore: runtime input, not a credential literal
                            clearPasswords();
                            unawaited(
                              controller.setup(endpoint.text, pin.text, secret),
                            );
                          }
                        : null,
                    child: const Text(
                      'Select CA and import dedicated identity',
                    ),
                  ),
                ],
              ),
              if (config.configured) ...[
                SelectableText('Provider: ${config.endpoint}'),
                SelectableText('Pinned server leaf: ${config.pin}'),
                SelectableText(
                  'Client certificate SHA-256: ${config.fingerprint}',
                  key: const Key('provider-fingerprint'),
                ),
                const SizedBox(height: 20),
                Text(
                  state.locked
                      ? 'Provider locked or authority not refreshed'
                      : 'Provider unlocked',
                ),
                if (state.locked && state.uncertainId.isEmpty) ...[
                  const Text(
                    'Unlock is separate from approval. After unlocking, the agent must submit a new request.',
                  ),
                  password(unlockPassword, 'Provider unlock password'),
                  OutlinedButton(
                    onPressed: controller.busy
                        ? null
                        : () {
                            final secret = unlockPassword.text; // secrets-ignore: runtime input, not a credential literal
                            clearPasswords();
                            unawaited(controller.unlock(secret));
                          },
                    child: const Text('Unlock provider'),
                  ),
                ],
                OutlinedButton(
                  onPressed: controller.busy ? null : controller.refresh,
                  child: const Text('Refresh authority and inbox'),
                ),
                Text(
                  'Pending requests: ${state.requests.length} / 256 maximum. The provider caps the inbox at 256; this is not pagination.',
                ),
                for (final id in state.requests)
                  OutlinedButton(
                    onPressed:
                        controller.busy ||
                            state.locked ||
                            state.uncertainId.isNotEmpty
                        ? null
                        : () => controller.review(id),
                    child: Text('Review $id'),
                  ),
                if (state.reviewText.isNotEmpty) ...[
                  const Divider(height: 32),
                  const Text(
                    'Complete request review · quoted values preserve argument boundaries. Unicode and controls appear as explicit escapes.',
                  ),
                  SelectableText(
                    state.reviewText,
                    key: const Key('provider-review'),
                    style: const TextStyle(fontFamily: 'monospace'),
                  ),
                  const Text(
                    'Review expires within 55 seconds and at the request deadline. Every attempt consumes its ticket.',
                  ),
                  password(approvalPassword, 'Fresh approval password'),
                  Wrap(
                    spacing: 12,
                    children: [
                      FilledButton(
                        onPressed: state.canDecide
                            ? () {
                                final secret = approvalPassword.text; // secrets-ignore: runtime input, not a credential literal
                                clearPasswords();
                                unawaited(controller.decide(true, secret));
                              }
                            : null,
                        child: const Text('Approve once with password'),
                      ),
                      OutlinedButton(
                        onPressed: state.canDecide
                            ? () {
                                clearPasswords();
                                unawaited(controller.decide(false, ''));
                              }
                            : null,
                        child: const Text('Deny without password'),
                      ),
                    ],
                  ),
                ],
              ],
              const SizedBox(height: 20),
              if (controller.recoveryId.isNotEmpty) ...[
                SelectableText(
                  'Uncertain decision for request: ${controller.recoveryId}',
                  key: const Key('provider-uncertain'),
                ),
                const Text(
                  'Only the original request status will be checked. A pending or unavailable status remains uncertain; decisions and unlocks are never resent.',
                ),
                OutlinedButton(
                  onPressed: controller.busy ? null : controller.refresh,
                  child: const Text('Refresh original request status'),
                ),
              ],
              if (state.statusId.isNotEmpty)
                SelectableText(
                  'Status request: ${state.statusId}\n${state.statusText}',
                ),
              Text(state.message, key: const Key('provider-status')),
              if (controller.diagnostic.isNotEmpty) Text(controller.diagnostic),
              if (!config.configured)
                OutlinedButton(
                  onPressed: controller.busy ? null : controller.refresh,
                  child: const Text('Reload saved provider setup'),
                ),
              if (controller.busy) const LinearProgressIndicator(),
              const Divider(height: 40),
              OutlinedButton(
                onPressed: controller.busy || state.uncertainId.isNotEmpty
                    ? null
                    : () async {
                        controller.setRouteCurrent(false);
                        await Navigator.of(context).push(
                          MaterialPageRoute<void>(
                            builder: widget.syntheticBuilder,
                          ),
                        );
                        if (mounted) controller.setRouteCurrent(true);
                      },
                child: const Text(
                  'Open separate synthetic signing demonstration',
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
