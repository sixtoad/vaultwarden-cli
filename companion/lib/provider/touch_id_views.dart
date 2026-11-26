import 'package:flutter/material.dart';

import '../design/components.dart';
import '../platform/approval_key.dart';
import '../src/rust/api/biometric.dart' as bio;
import 'touch_id.dart';

/// What the key panel says: macOS keeps its Touch ID wording; Windows names
/// Windows Hello (desktop-approval-spec D-10).
class _KeyTexts {
  const _KeyTexts({
    required this.title,
    required this.available,
    required this.unavailable,
    required this.localLabel,
    required this.present,
    required this.invalidated,
    required this.explainer,
    required this.enroll,
    required this.revoke,
    required this.replaceTitle,
    required this.replaceBody,
  });
  final String title, available, unavailable, localLabel, present, invalidated;
  final String explainer, enroll, revoke, replaceTitle, replaceBody;

  static const mac = _KeyTexts(
    title: 'Touch ID approval key',
    available: 'Touch ID is available on this Mac.',
    unavailable: 'Touch ID is unavailable on this Mac (no sensor, no enrolled finger or locked out). Approve with your password.',
    localLabel: 'Key on this Mac',
    present: 'Present in the Secure Enclave',
    invalidated:
        'Invalidated by a fingerprint change (enroll again to replace it)',
    explainer: 'One non-exportable Secure Enclave key per provider and client identity. Every approval needs its own touch. Adding or removing a fingerprint invalidates the key; enrolling again replaces it, as it replaces any key the provider no longer holds as current.',
    enroll: 'Enroll Touch ID key',
    revoke: 'Revoke Touch ID key',
    replaceTitle: 'Replace this Mac\'s approval key?',
    replaceBody: 'The key stored for this provider could not be read. Replacing it deletes it from this Mac and enrolls a new Secure Enclave key. If the provider still holds the old key as current, the new key replaces it there once enrollment completes.',
  );
  static const windows = _KeyTexts(
    title: 'Windows Hello approval key',
    available: 'Windows Hello is available on this PC.',
    unavailable: 'Windows Hello is unavailable on this PC (not set up, or no supported authenticator). Approve with your password.',
    localLabel: 'Key on this PC',
    present: 'Present (a Windows Hello credential)',
    invalidated:
        'Windows Hello no longer holds it (enroll again to replace it)',
    explainer: 'One Windows Hello credential per provider and client identity, bound to this PC. Every approval needs its own Windows Hello check (fingerprint, face or PIN). The provider records these approvals as Windows Hello, never as biometric.',
    enroll: 'Enroll Windows Hello key',
    revoke: 'Revoke Windows Hello key',
    replaceTitle: 'Replace this PC\'s approval key?',
    replaceBody: 'The key stored for this provider could not be read. Replacing it forgets it on this PC and enrolls a new Windows Hello credential. If the provider still holds the old key as current, the new key replaces it there once enrollment completes.',
  );
}

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

  _KeyTexts get _texts =>
      touchId.operatingSystem == 'windows' ? _KeyTexts.windows : _KeyTexts.mac;

  @override
  Widget build(BuildContext context) {
    final t = _texts;
    final idle = enabled && !touchId.working && keys.configured && !keys.busy;
    return Column(
      key: const Key('touch-id-keys'),
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(t.title),
        const SizedBox(height: 8),
        Text(
          touchId.available ? t.available : t.unavailable,
          key: const Key('touch-id-availability'),
        ),
        FactRow(
          'Provider record',
          keys.configured ? _providerState : 'Provider not pinned',
          key: const Key('touch-id-provider-state'),
        ),
        FactRow(t.localLabel, switch (touchId.local) {
          KeyOutcome.present => t.present,
          KeyOutcome.invalidated => t.invalidated,
          KeyOutcome.unsafe || KeyOutcome.failed =>
            'Present, but it could not be read (${touchId.local.name}). Replace it to enroll; approve with your password meanwhile.',
          _ => 'None',
        }, key: const Key('touch-id-local-key')),
        Text(t.explainer),
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
                touchId.localUnreadable ? 'Replace key and enroll' : t.enroll,
              ),
            ),
            OutlinedButton(
              key: const Key('touch-id-revoke'),
              onPressed: idle && keys.state == bio.BiometricKeyState.enrolled
                  ? () => _withPassword(touchId.revoke)
                  : null,
              child: Text(t.revoke),
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
        title: Text(_texts.replaceTitle),
        content: Text(_texts.replaceBody),
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
