import 'package:flutter/material.dart';

import '../design/components.dart';
import '../platform/approval_key.dart';
import '../src/rust/api/biometric.dart' as bio;
import 'touch_id.dart';

/// Own-device Touch ID key management. Enrolling and revoking need a fresh
/// approval password; enrolling also needs one Touch ID proof by the new key.
class TouchIdKeyPanel extends StatelessWidget {
  const TouchIdKeyPanel({
    super.key,
    required this.touchId,
    required this.keys,
    required this.password,
    required this.enabled,
  });
  final TouchIdController touchId;
  final bio.BiometricKeySnapshot keys;
  final TextEditingController password;
  final bool enabled;

  String get _providerState => switch (keys.state) {
    bio.BiometricKeyState.enrolled => 'Enrolled (key ${keys.keyId})',
    bio.BiometricKeyState.notEnrolled => 'Not enrolled',
    bio.BiometricKeyState.unsupported =>
      'Not supported by this provider (password approval only)',
    bio.BiometricKeyState.unknown => 'Unknown. Read it from the provider.',
  };

  @override
  Widget build(BuildContext context) {
    final idle = enabled && !touchId.working && keys.configured && !keys.busy;
    return Column(
      key: const Key('touch-id-keys'),
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text('Touch ID approval key'),
        const SizedBox(height: 8),
        Text(
          touchId.available ? 'Touch ID is available on this Mac.' : 'Touch ID is unavailable on this Mac (no sensor, no enrolled finger or locked out). Approve with your password.',
          key: const Key('touch-id-availability'),
        ),
        FactRow(
          'Provider record',
          keys.configured ? _providerState : 'Provider not pinned',
          key: const Key('touch-id-provider-state'),
        ),
        FactRow('Key on this Mac', switch (touchId.local) {
          KeyOutcome.present => 'Present in the Secure Enclave',
          KeyOutcome.invalidated =>
            'Invalidated by a fingerprint change (enroll again to replace it)',
          KeyOutcome.unsafe || KeyOutcome.failed =>
            'Present, but it could not be read (${touchId.local.name}). Replace it to enroll; approve with your password meanwhile.',
          _ => 'None',
        }, key: const Key('touch-id-local-key')),
        const Text(
          'One non-exportable Secure Enclave key per provider and client identity. Every approval needs its own touch. Adding or removing a fingerprint invalidates the key; enrolling again replaces it, as it replaces any key the provider no longer holds as current.',
        ),
        const SizedBox(height: 12),
        accessPassword(password, 'Fresh approval password for key changes'),
        const SizedBox(height: 12),
        AccessActions(
          children: [
            OutlinedButton(
              key: const Key('touch-id-read'),
              onPressed: idle ? touchId.readKey : null,
              child: const Text('Read key state'),
            ),
            FilledButton(
              key: const Key('touch-id-enroll'),
              onPressed:
                  idle &&
                      touchId.available &&
                      keys.state != bio.BiometricKeyState.unsupported
                  ? () => touchId.localUnreadable
                        ? _confirmReplace(context)
                        : _withPassword(touchId.enroll)
                  : null,
              child: Text(
                touchId.localUnreadable
                    ? 'Replace key and enroll'
                    : 'Enroll Touch ID key',
              ),
            ),
            OutlinedButton(
              key: const Key('touch-id-revoke'),
              onPressed: idle && keys.state == bio.BiometricKeyState.enrolled
                  ? () => _withPassword(touchId.revoke)
                  : null,
              child: const Text('Revoke Touch ID key'),
            ),
          ],
        ),
        if (touchId.message.isNotEmpty || keys.message.isNotEmpty) ...[
          const SizedBox(height: 8),
          Text(
            touchId.message.isNotEmpty ? touchId.message : keys.message,
            key: const Key('touch-id-key-message'),
          ),
        ],
      ],
    );
  }

  /// An unreadable local key is deleted only after this confirmation.
  Future<void> _confirmReplace(BuildContext context) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialog) => AlertDialog(
        title: const Text('Replace this Mac\'s approval key?'),
        content: const Text(
          'The key stored for this provider could not be read. Replacing it deletes it from this Mac and enrolls a new Secure Enclave key. If the provider still holds the old key as current, the new key replaces it there once enrollment completes.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(dialog, false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            key: const Key('touch-id-replace-confirm'),
            onPressed: () => Navigator.pop(dialog, true),
            child: const Text('Delete and replace'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    _withPassword((secret) => touchId.enroll(secret, replaceUnreadable: true));
  }

  void _withPassword(Future<void> Function(String) action) {
    final secret = password.text; // secrets-ignore: runtime input
    password.clear();
    action(secret);
  }
}
