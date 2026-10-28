import 'package:flutter/material.dart';

import '../design/components.dart';
import '../src/rust/api/provider.dart' as core;

/// Displays Rust's complete escaped projection verbatim; never parses authority
/// or reconstructs arguments, identities, credentials or deadlines from text.
class RequestReview extends StatelessWidget {
  const RequestReview({
    super.key,
    required this.state,
    required this.endpoint,
    required this.password,
    required this.onApprove,
    required this.onDeny,
    required this.onCancel,
  });
  final core.ProviderSnapshot state;
  final String endpoint;
  final TextEditingController password;
  final VoidCallback onApprove, onDeny, onCancel;
  @override
  Widget build(BuildContext context) => AccessPanel(
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const AccessHeading(
          'Review request',
          'Authorize only the exact operation below. Linux keeps secrets and executes approved operations.',
        ),
        FactRow('Request ID', state.reviewId),
        FactRow('Provider endpoint', endpoint),
        const Text(
          'Complete request review · quoted values preserve argument boundaries. Unicode and controls appear as explicit escapes.',
        ),
        const SizedBox(height: 16),
        SelectableText(
          state.reviewText,
          key: const Key('provider-review'),
          style: const TextStyle(fontFamily: 'monospace'),
        ),
        const SizedBox(height: 16),
        const Text(
          'Review expires within 55 seconds and at the request deadline. Every attempt consumes its ticket.',
        ),
        const SizedBox(height: 24),
        accessPassword(password, 'Fresh approval password'),
        const SizedBox(height: 16),
        AccessActions(
          children: [
            FilledButton(
              onPressed: state.canDecide ? onApprove : null,
              child: const Text('Approve once with password'),
            ),
            OutlinedButton(
              onPressed: state.canDecide ? onDeny : null,
              child: const Text('Deny without password'),
            ),
            TextButton(onPressed: onCancel, child: const Text('Cancel review')),
          ],
        ),
        const SizedBox(height: 16),
        const Text(
          'Cancel review does not cancel the remote request. Approval and execution completion are separate states.',
        ),
      ],
    ),
  );
}
