import 'package:flutter/material.dart';

import '../../design/components.dart';
import '../../src/rust/api/provider.dart' as core;

/// Second step of an approval (owner decision, #50 Q6), bound to one review's
/// request ID by the page. Touch ID is the primary action when it can approve
/// this review; otherwise the password is. "Cancel authorization" returns to
/// the review and clears the password; it never cancels the request.
class AuthorizationStep extends StatelessWidget {
  const AuthorizationStep({
    super.key,
    required this.review,
    required this.password,
    required this.enabled,
    required this.onApprove,
    required this.onCancel,
    this.touchIdOffered = false,
    this.onTouchId,
    this.touchIdNote = '',
  });
  final core.ProviderReview review;
  final TextEditingController password;

  /// The review still admits a decision (ticket live, provider idle).
  final bool enabled;
  final VoidCallback onApprove, onCancel;
  final bool touchIdOffered;

  /// Null when Touch ID cannot approve this review; [touchIdNote] says why.
  final VoidCallback? onTouchId;
  final String touchIdNote;

  @override
  Widget build(BuildContext context) {
    final small = Theme.of(context).textTheme.labelSmall;
    final touchPrimary = touchIdOffered && onTouchId != null;
    const touchKey = Key('approve-touch-id');
    const touchLabel = Text('Approve once with Touch ID');
    final touchHandler = enabled ? onTouchId : null;
    final Widget touchButton = touchPrimary
        ? FilledButton.icon(
            key: touchKey,
            onPressed: touchHandler,
            icon: const Icon(Icons.fingerprint),
            label: touchLabel,
          )
        : OutlinedButton.icon(
            key: touchKey,
            onPressed: touchHandler,
            icon: const Icon(Icons.fingerprint),
            label: touchLabel,
          );
    const passwordKey = Key('approve-password');
    const passwordLabel = Text('Approve once with password');
    final passwordHandler = enabled ? onApprove : null;
    final Widget passwordButton = touchPrimary
        ? OutlinedButton(
            key: passwordKey,
            onPressed: passwordHandler,
            child: passwordLabel,
          )
        : FilledButton(
            key: passwordKey,
            onPressed: passwordHandler,
            child: passwordLabel,
          );
    return Column(
      key: const Key('authorization-step'),
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        AccessNotice(
          child: SelectableText(
            'Authorizing ${review.id} only · ${review.requester}\n'
            'Operation ${review.operation} on target ${review.target}',
            key: const Key('authorization-scope'),
          ),
        ),
        const SizedBox(height: 16),
        if (touchIdOffered) ...[
          SizedBox(width: double.infinity, child: touchButton),
          if (touchIdNote.isNotEmpty) ...[
            const SizedBox(height: 8),
            Text(touchIdNote, key: const Key('touch-id-note'), style: small),
          ],
          const SizedBox(height: 8),
          Text(
            'Touch ID signs this exact review after fetching it again. If it is unavailable, dismissed or refused, nothing is sent and you can approve with your password instead.',
            style: small,
          ),
          const SizedBox(height: 16),
        ],
        accessPassword(password, 'Fresh approval password'),
        const SizedBox(height: 12),
        AccessActions(
          children: [
            TextButton(
              key: const Key('cancel-authorization'),
              onPressed: onCancel,
              child: const Text('Cancel authorization'),
            ),
            passwordButton,
          ],
        ),
        const SizedBox(height: 12),
        Text(
          'Every attempt consumes this review’s ticket. Cancelling here returns to the review; the request stays pending.',
          style: small,
        ),
      ],
    );
  }
}
