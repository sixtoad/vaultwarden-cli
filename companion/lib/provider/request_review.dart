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
  Widget build(BuildContext context) {
    final review = state.review;
    if (review == null) return const SizedBox.shrink();
    return AccessPanel(
      child: Column(
        key: const Key('provider-review'),
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const AccessHeading(
            'Review request',
            'Authorize only the exact operation below. Linux keeps secrets and executes approved operations.',
          ),
          FactRow('Request ID', review.id, key: const Key('review-id')),
          FactRow('Provider endpoint', endpoint),
          const Text(
            'Complete request review · quoted values preserve argument boundaries. Unicode and controls appear as explicit escapes.',
          ),
          const SizedBox(height: 16),
          FactRow(
            'Requester',
            review.requester,
            key: const Key('review-requester'),
          ),
          const FactRow(
            'Originating device',
            'Not supplied by provider protocol v1.',
          ),
          FactRow(
            'Operation',
            review.operation,
            key: const Key('review-operation'),
          ),
          FactRow('Effect', review.effect, key: const Key('review-effect')),
          FactRow('Target', review.target, key: const Key('review-target')),
          Text('Arguments (${review.arguments.length} separate values)'),
          const SizedBox(height: 8),
          for (var i = 0; i < review.arguments.length; i++)
            _argument(review, i),
          Text('Credentials (${review.credentials.length})'),
          const SizedBox(height: 8),
          for (var i = 0; i < review.credentials.length; i++)
            _credential(review, i),
          FactRow(
            'Executable SHA-256',
            review.executableDigest,
            key: const Key('review-executable-digest'),
          ),
          FactRow(
            'Policy SHA-256',
            review.policyDigest,
            key: const Key('review-policy-digest'),
          ),
          FactRow(
            'Arguments SHA-256',
            review.argumentsDigest,
            key: const Key('review-arguments-digest'),
          ),
          FactRow(
            'Expires (Unix seconds)',
            review.expiresAtUnixSeconds.toString(),
            key: const Key('review-expiry'),
          ),
          FactRow(
            'One-time scope',
            review.oneTime,
            key: const Key('review-one-time'),
          ),
          FactRow('Status', review.status, key: const Key('review-status')),
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
              TextButton(
                onPressed: onCancel,
                child: const Text('Cancel review'),
              ),
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

  Widget _argument(core.ProviderReview review, int i) => FactRow(
    'Argument [$i]',
    review.arguments[i],
    key: Key('review-argument-$i'),
  );

  Widget _credential(core.ProviderReview review, int i) => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      FactRow(
        'Credential [$i] label',
        review.credentials[i].label,
        key: Key('review-credential-$i-label'),
      ),
      FactRow(
        'Credential [$i] use type',
        review.credentials[i].useType,
        key: Key('review-credential-$i-use-type'),
      ),
    ],
  );
}
