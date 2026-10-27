import 'package:flutter/material.dart';

import '../design/components.dart';
import '../platform/provider.dart';
import '../src/rust/api/provider.dart' as core;

class ProviderDevices extends StatelessWidget {
  const ProviderDevices({super.key, required this.configuration});
  final ProviderConfiguration configuration;
  @override
  Widget build(BuildContext context) => AccessPanel(
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const AccessHeading(
          'Devices & agents',
          'Known local connection and client identity',
        ),
        if (configuration.configured) ...[
          FactRow('Provider endpoint', configuration.endpoint),
          FactRow('Pinned server leaf SHA-256', configuration.pin),
          FactRow(
            'Client certificate SHA-256',
            configuration.fingerprint,
            key: const Key('provider-fingerprint'),
          ),
        ] else
          const Text(
            'No provider connection is configured. Advanced setup is in Settings.',
          ),
        const Text(
          'This client requests password approval from the Linux provider. Linux owns secret custody and protected execution.',
        ),
        const SizedBox(height: 16),
        const Text(
          'Device enrollment, device lists and revocation are not available in this version. Advanced certificate setup is available in Settings.',
        ),
      ],
    ),
  );
}

class ProviderActivity extends StatelessWidget {
  const ProviderActivity({
    super.key,
    required this.state,
    required this.onReopen,
  });
  final core.ProviderSnapshot state;
  final VoidCallback? onReopen;
  @override
  Widget build(BuildContext context) => AccessPanel(
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const AccessHeading(
          'Activity',
          'Latest known request status · not a durable history',
        ),
        if (state.statusId.isEmpty)
          const Text('No request status has been received in this session.')
        else ...[
          FactRow('Request ID', state.statusId),
          SelectableText(state.statusText),
          const SizedBox(height: 16),
          const Text(
            'Approved and running are not completed. An accepted command reply does not prove execution completed.',
          ),
          const SizedBox(height: 16),
          OutlinedButton(
            onPressed: onReopen,
            child: const Text('Open request with fresh review'),
          ),
        ],
        const SizedBox(height: 16),
        const Text(
          'Only the latest validated request status is available in this version.',
        ),
      ],
    ),
  );
}

class ProviderCapabilities extends StatelessWidget {
  const ProviderCapabilities({super.key});
  @override
  Widget build(BuildContext context) => const Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Text('Native capabilities'),
      SizedBox(height: 8),
      Text(
        'macOS: native pinned-TLS provider transport and explicit password approval. Touch ID remains a separate synthetic signing demonstration.',
      ),
      SizedBox(height: 8),
      Text(
        'Windows and Linux: desktop shell builds; provider transport and identity integration are unavailable.',
      ),
      SizedBox(height: 8),
      Text(
        'Android and iOS approval clients: native integration pending. Phones do not install the desktop CLI.',
      ),
      SizedBox(height: 8),
      Text(
        'Guided enrollment, notifications, bundled CLI inspection and repair are not available. This development application does not replace the installed companion.',
      ),
    ],
  );
}
