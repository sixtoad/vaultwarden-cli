import 'package:flutter/material.dart';

import '../design/components.dart';
import '../src/rust/api/management.dart' as manage;
import 'controller.dart';

class ProviderDevices extends StatelessWidget {
  const ProviderDevices({
    super.key,
    required this.controller,
    required this.password,
  });
  final ProviderController controller;
  final TextEditingController password;
  String kind(manage.IdentityKind value) =>
      value == manage.IdentityKind.approvalClient
      ? 'Approval client certificate'
      : 'Requester-agent binding';
  @override
  Widget build(BuildContext context) {
    final state = controller.management, detail = controller.management.detail;
    final idle = controller.canManage && !controller.managementPending;
    return AccessPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const AccessHeading(
            'Devices & agents',
            'Authoritative provider identities · names are labels, not identity proof.',
          ),
          const Text(
            'Approval clients, requester agents and the executing provider have separate roles. Enrollment does not grant administration.',
          ),
          const SizedBox(height: 16),
          if (controller.busy) const LinearProgressIndicator(),
          if (!controller.platform.available)
            const StatusLabel(
              'Provider transport unavailable on this platform.',
            )
          else if (!controller.configuration.configured)
            const StatusLabel(
              'No provider configured. Use advanced setup in Settings.',
            )
          else if (state.state == manage.InventoryState.unauthorized)
            const StatusLabel(
              'Unauthorized: the provider owner must explicitly grant this certificate administration from the trusted console.',
            )
          else if (state.state == manage.InventoryState.stale)
            const StatusLabel(
              'Stale: refresh provider records. Local configuration does not prove current trust.',
            )
          else if (state.state == manage.InventoryState.unavailable)
            const StatusLabel(
              'Inventory unavailable. The provider may be offline or may not support management v2.',
            )
          else if (state.state == manage.InventoryState.empty)
            const StatusLabel('No identities in this provider page.'),
          const SizedBox(height: 16),
          if (state.providerFingerprint.isNotEmpty) ...[
            FactRow(
              'Executing provider · TLS leaf SHA-256',
              state.providerFingerprint,
            ),
            Text(
              'Execution configured: ${state.executionConfigured ? "yes" : "no"}. Available at last read: ${state.executionAvailable ? "yes" : "no"}.',
            ),
            const Text(
              'This provider is separate from this approval client. A TLS certificate does not identify a physical device.',
            ),
          ],
          if (controller.managementPending) ...[
            const StatusLabel(
              'Administrative outcome requires reconciliation',
              icon: Icons.help_outline,
            ),
            FactRow('Original action ID', state.actionId),
            FactRow('Original target', state.actionTarget),
            FactRow(
              'Original approval client SHA-256',
              controller.configuration.fingerprint,
            ),
            const Text(
              'Only this action is checked. Revocation is never resent. Self-revocation may remove remote access; the provider owner must inspect the durable action journal from the trusted console.',
            ),
            OutlinedButton(
              onPressed: controller.busy ? null : controller.refresh,
              child: const Text('Check original administrative action'),
            ),
          ] else ...[
            AccessActions(
              children: [
                OutlinedButton(
                  onPressed: idle
                      ? () => controller.performManagement(
                          manage.ManagementCommand.list,
                        )
                      : null,
                  child: const Text('Refresh provider identities'),
                ),
                if (state.hasNext)
                  OutlinedButton(
                    onPressed: idle
                        ? () => controller.performManagement(
                            manage.ManagementCommand.next,
                          )
                        : null,
                    child: const Text('Next page'),
                  ),
              ],
            ),
            for (final identity in state.identities)
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      identity.label,
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                    Text(
                      '${kind(identity.kind)} · ${identity.trust.name}${identity.thisClient ? " · This approval client" : ""}',
                    ),
                    FactRow('Stable identity', identity.id),
                    Text(
                      'Granted roles: ${identity.roles.isEmpty ? "none" : identity.roles.map((r) => r.name).join(", ")}',
                    ),
                    OutlinedButton(
                      onPressed: idle
                          ? () => controller.selectIdentity(identity)
                          : null,
                      child: Text('Review ${identity.label}'),
                    ),
                    const Divider(),
                  ],
                ),
              ),
            if (detail != null) ...[
              const SizedBox(height: 24),
              Text(
                'Identity details',
                style: Theme.of(context).textTheme.titleLarge,
              ),
              FactRow('Display label', detail.label),
              FactRow(kind(detail.kind), detail.id),
              FactRow('Public identity SHA-256', detail.fingerprint),
              FactRow(
                'Granted roles',
                detail.roles.isEmpty
                    ? 'None'
                    : detail.roles.map((r) => r.name).join(', '),
              ),
              StatusLabel(
                'Trust: ${detail.trust.name}${detail.thisClient ? " · This approval client" : ""}',
              ),
              const SizedBox(height: 16),
              if (detail.trust == manage.IdentityTrust.revoked)
                const Text(
                  'Permanently revoked. A matching name does not restore access. A new identity requires explicit owner enrollment or pairing.',
                )
              else ...[
                Text(
                  detail.kind == manage.IdentityKind.approvalClient
                      ? 'Revoking this certificate removes approval and administrative access. The provider locks the entire session, invalidates pending and approved delivery, and cleans up provider-owned resources. This is session-wide because older approvals do not identify their approving certificate.'
                      : 'Revoking this exact agent binding blocks future requests and secret delivery, invalidates its pending and approved work, cancels its provider-owned delivery and signing services, and waits for provider-owned cleanup.',
                ),
                const SizedBox(height: 8),
                const Text(
                  'Consumer programs and established connections are not terminated. Delivered secrets and signatures cannot be recalled. Revocation and cleanup completion are reported separately.',
                ),
                if (detail.thisClient)
                  const StatusLabel(
                    'Self-revocation removes general remote access. Only this exact action receipt remains readable while TLS authentication remains valid.',
                    icon: Icons.warning_amber,
                  ),
                const SizedBox(height: 16),
                if (!state.canRevoke)
                  OutlinedButton(
                    onPressed: idle
                        ? () => controller.selectIdentity(detail, prepare: true)
                        : null,
                    child: const Text('Prepare exact-identity revocation'),
                  )
                else ...[
                  accessPassword(password, 'Fresh administration password'),
                  const SizedBox(height: 16),
                  FilledButton(
                    onPressed: idle
                        ? () {
                            final secret = password.text;
                            password.clear();
                            controller.revokeIdentity(secret);
                          }
                        : null,
                    child: const Text('Confirm permanent revocation'),
                  ),
                ],
              ],
              TextButton(
                onPressed: controller.busy ? null : controller.invalidate,
                child: const Text('Cancel identity review'),
              ),
            ],
          ],
          const SizedBox(height: 16),
          if (state.actionId.isNotEmpty && !controller.managementPending) ...[
            FactRow('Administrative action ID', state.actionId),
            FactRow('Action target', state.actionTarget),
          ],
          if (state.revocation.isNotEmpty)
            FactRow('Revocation evidence', state.revocation),
          if (state.cleanup.isNotEmpty)
            FactRow('Provider-owned cleanup evidence', state.cleanup),
          Text(state.message, key: const Key('management-message')),
        ],
      ),
    );
  }
}
