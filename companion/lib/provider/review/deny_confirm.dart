import 'package:flutter/material.dart';

import '../../design/components.dart';

/// Confirmation before a denial (no password: a denial sends no credential).
class DenyConfirm extends StatelessWidget {
  const DenyConfirm({
    super.key,
    required this.requestId,
    required this.enabled,
    required this.onDeny,
    required this.onKeep,
  });
  final String requestId;
  final bool enabled;
  final VoidCallback onDeny, onKeep;
  @override
  Widget build(BuildContext context) => Column(
    key: const Key('deny-confirm'),
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      AccessNotice(
        child: Text(
          'Deny $requestId? Nothing will execute. The agent receives a denial, not a credential. No password is needed.',
        ),
      ),
      const SizedBox(height: 16),
      AccessActions(
        children: [
          OutlinedButton(
            key: const Key('keep-reviewing'),
            onPressed: onKeep,
            child: const Text('Keep reviewing'),
          ),
          FilledButton(
            key: const Key('confirm-deny'),
            onPressed: enabled ? onDeny : null,
            child: const Text('Deny this request'),
          ),
        ],
      ),
    ],
  );
}
