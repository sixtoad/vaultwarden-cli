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
    required this.connected,
    required this.configured,
    required this.recoveryPending,
    required this.onRefresh,
    required this.onReopen,
  });
  final core.ProviderSnapshot state;
  final bool connected, configured, recoveryPending;
  final VoidCallback? onRefresh;
  final ValueChanged<String>? onReopen;

  String outcome(core.ProviderHistoryOutcome value) => switch (value) {
    core.ProviderHistoryOutcome.submitted => 'Submitted',
    core.ProviderHistoryOutcome.approved => 'Approved',
    core.ProviderHistoryOutcome.denied => 'Denied',
    core.ProviderHistoryOutcome.expired => 'Expired',
    core.ProviderHistoryOutcome.reviewUnavailable => 'Review unavailable',
    core.ProviderHistoryOutcome.executionStarted => 'Execution started',
    core.ProviderHistoryOutcome.succeeded => 'Completed successfully',
    core.ProviderHistoryOutcome.executionNonzero => 'Execution failed',
    core.ProviderHistoryOutcome.executionSignaled => 'Execution interrupted',
    core.ProviderHistoryOutcome.executionRejected => 'Execution rejected',
    core.ProviderHistoryOutcome.executionUnavailable => 'Execution unavailable',
    core.ProviderHistoryOutcome.invalidated => 'Invalidated',
    core.ProviderHistoryOutcome.recovered => 'Recovered',
    core.ProviderHistoryOutcome.legacyUnknown =>
      'Legacy event · outcome unknown',
    core.ProviderHistoryOutcome.reconciled => 'Reconciled',
    core.ProviderHistoryOutcome.observationLost => 'Result unknown',
  };

  String eventTime(BigInt? seconds) {
    if (seconds == null) return 'Unknown · legacy event';
    // DateTime supports at most 100 million days from the epoch. Keep the full
    // validated u64 visible when it lies outside that rendering range.
    if (seconds > BigInt.from(8640000000000)) return 'Unix seconds: $seconds';
    final time = DateTime.fromMillisecondsSinceEpoch(
      seconds.toInt() * 1000,
      isUtc: true,
    );
    return '${time.toIso8601String().replaceFirst('T', ' ').replaceFirst('.000Z', '')} UTC';
  }

  String get status {
    if (!configured) {
      return 'Disconnected. Configure a provider in Settings to load Activity.';
    }
    if (recoveryPending) {
      return 'Activity is paused while the original decision outcome is uncertain. Only its status can resolve recovery.';
    }
    if (state.historyState == core.ProviderHistoryState.unavailable) {
      return 'Activity unavailable. This provider may not support history, or its response could not be validated.';
    }
    if (!connected) {
      return 'Disconnected. Refresh to load current provider activity.';
    }
    if (state.locked) {
      return 'Provider locked. Unlock separately in Requests before loading Activity.';
    }
    return switch (state.historyState) {
      core.ProviderHistoryState.loading => 'Loading recent activity…',
      core.ProviderHistoryState.available =>
        state.history.isEmpty ? 'No history events are available.' : '',
      _ => 'Refresh to load recent activity.',
    };
  }

  @override
  Widget build(BuildContext context) {
    final showEvents =
        connected &&
        !state.locked &&
        !recoveryPending &&
        state.historyState == core.ProviderHistoryState.available;
    return AccessPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const AccessHeading(
            'Activity',
            'Recent redacted provider history · up to 50 events',
          ),
          const Text(
            'Newest events first. History is a record, not authorization or confirmation of an uncertain decision.',
          ),
          const SizedBox(height: 16),
          if (status.isNotEmpty) Text(status, key: const Key('activity-state')),
          if (state.historyState == core.ProviderHistoryState.loading &&
              connected)
            const LinearProgressIndicator(),
          if (showEvents)
            for (final event in state.history)
              Padding(
                key: ValueKey('activity-${event.requestId}-${event.ordinal}'),
                padding: const EdgeInsets.only(top: 16, bottom: 8),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    StatusLabel(outcome(event.outcome)),
                    FactRow('Operation', event.operation),
                    FactRow('Request ID', event.requestId),
                    FactRow('Event time', eventTime(event.atUnixSeconds)),
                    Semantics(
                      label:
                          'Request ${event.requestId}, event ${event.ordinal}',
                      child: OutlinedButton(
                        onPressed: onReopen == null
                            ? null
                            : () => onReopen!(event.requestId),
                        child: const Text('Open request with fresh review'),
                      ),
                    ),
                    const Divider(),
                  ],
                ),
              ),
          const SizedBox(height: 16),
          OutlinedButton(
            onPressed: onRefresh,
            child: const Text('Refresh activity'),
          ),
          const SizedBox(height: 16),
          const Text(
            'Approved and execution started do not mean completed. Opening an event obtains a fresh review of that exact request; expired or retired authority is never restored.',
          ),
        ],
      ),
    );
  }
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
