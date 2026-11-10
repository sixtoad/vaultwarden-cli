import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../design/access_theme.dart';
import '../design/components.dart';
import '../src/rust/api/enrollment.dart' as enroll;
import 'enrollment_flow.dart';

/// Entry point in Devices & agents: two plain actions, nothing else on the
/// happy path. Each opens its own guided panel.
class EnrollmentEntry extends StatelessWidget {
  const EnrollmentEntry({super.key, required this.flow});
  final EnrollmentFlow flow;
  @override
  Widget build(BuildContext context) => AccessPanel(
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const AccessHeading(
          'Guided enrollment',
          'Add a device or agent with approval at both ends. A comparison code is read on the joining device and typed at the provider.',
        ),
        AccessActions(
          children: [
            FilledButton(
              onPressed: () => flow.open(EnrollmentMode.add),
              child: const Text('Add a device or agent'),
            ),
            OutlinedButton(
              onPressed: () => flow.open(EnrollmentMode.join),
              child: const Text('Join this device to a provider'),
            ),
          ],
        ),
      ],
    ),
  );
}

/// The app's field pattern: a visible label above, the same text for
/// assistive technology, no floating label.
Widget _field(String label, TextField field) => Column(
  crossAxisAlignment: CrossAxisAlignment.start,
  children: [
    ExcludeSemantics(child: Text(label)),
    const SizedBox(height: 8),
    Semantics(label: label, child: field),
  ],
);

String _minutes(int seconds) {
  final m = seconds ~/ 60, s = seconds % 60;
  return '$m:${s.toString().padLeft(2, '0')}';
}

/// Manual fallback: the same protocol from a terminal, and the older paths.
class ManualEnrollment extends StatelessWidget {
  const ManualEnrollment({super.key, this.initiallyExpanded = false});
  final bool initiallyExpanded;
  @override
  Widget build(BuildContext context) => ExpansionTile(
    key: const Key('manual-enrollment'),
    initiallyExpanded: initiallyExpanded,
    tilePadding: EdgeInsets.zero,
    childrenPadding: const EdgeInsets.only(bottom: 16),
    expandedCrossAxisAlignment: CrossAxisAlignment.start,
    title: const Text('Manual enrollment (terminal)'),
    children: const [
      Text('On the provider host, as the provider owner:'),
      SizedBox(height: 8),
      SelectableText(
        'vw-access enroll invite-companion "Studio Mac"\n'
        'vw-access enroll invite-agent ci-runner --uid 42001 --gid 42003\n'
        'vw-access enroll list\n'
        'vw-access enroll approve <id> --code <code shown on the joining device>',
      ),
      SizedBox(height: 8),
      Text('In the invited agent account:'),
      SizedBox(height: 8),
      SelectableText(
        'vw-access enroll join --socket <agent socket> --key-file <new key file>',
      ),
      SizedBox(height: 8),
      Text(
        'Without guided enrollment: "vw-access agent pair" for an agent, or the offline "vaultwarden-accessd --companion-enroll-cert" for a companion with the provider stopped.',
      ),
    ],
  );
}

class _Details extends StatelessWidget {
  const _Details(this.facts, {required this.id});
  final List<(String, String)> facts;
  final String id;
  @override
  Widget build(BuildContext context) => ExpansionTile(
    key: Key('details-$id'),
    tilePadding: EdgeInsets.zero,
    expandedCrossAxisAlignment: CrossAxisAlignment.start,
    title: const Text('Details'),
    children: [
      for (final (label, value) in facts)
        if (value.isNotEmpty) FactRow(label, value),
    ],
  );
}

String joinerEndText(enroll.JoinerEnd end) => switch (end) {
  enroll.JoinerEnd.none => '',
  enroll.JoinerEnd.declined => 'You reported that the codes differ. Nothing was enrolled. Ask the provider owner for a new invitation.',
  enroll.JoinerEnd.cancelled => 'Cancelled. Nothing was enrolled.',
  enroll.JoinerEnd.cancelledByProvider =>
    'The provider owner cancelled this invitation. Nothing was enrolled.',
  enroll.JoinerEnd.codeMismatch => 'The provider owner typed a different code. Nothing was enrolled. Someone may be relaying between the devices: start again with a new invitation.',
  enroll.JoinerEnd.duplicateJoin => 'Another device used this invitation, so it is no longer private. Nothing was enrolled. Ask for a new invitation.',
  enroll.JoinerEnd.tooManyFailures => 'Too many wrong attempts used up this invitation. Nothing was enrolled. Ask for a new one.',
  enroll.JoinerEnd.expired => 'The invitation expired. Nothing was enrolled. Ask the provider owner for a new one.',
  enroll.JoinerEnd.identityRefused => 'The provider already knows this client certificate (enrolled or revoked). A revoked certificate is never reactivated; enrolling again needs a new certificate.',
  enroll.JoinerEnd.commitUnavailable => 'The provider could not record this device. The outcome is unclear: check Devices & agents, or ask the provider owner.',
  enroll.JoinerEnd.invalidInvitation => 'The provider does not recognise this invitation. It may be mistyped, cancelled, expired or finished, or the provider restarted. Nothing was enrolled.',
  enroll.JoinerEnd.alreadyUsed =>
    'This invitation was already used. Nothing was enrolled.',
  enroll.JoinerEnd.providerNotAuthenticated => 'The provider could not prove it issued this invitation. No code is shown and nothing was enrolled. Check the provider connection.',
  enroll.JoinerEnd.wrongRole => 'This invitation is for an agent, not this app. Run "vw-access enroll join" in the agent account.',
  enroll.JoinerEnd.malformed =>
    'The provider sent an unexpected reply. Nothing was enrolled.',
  enroll.JoinerEnd.outcomeUnknown => 'A confirmation reply was lost and the provider no longer knows this session. This device may or may not be enrolled: check Devices & agents.',
};

/// The comparison step on the joining device: the code large, then the
/// joining human's own decision. Pure, so its appearance is pinned by goldens.
class JoinerComparison extends StatelessWidget {
  const JoinerComparison({
    super.key,
    required this.code,
    required this.label,
    required this.secondsRemaining,
    required this.waiting,
    required this.providerApproved,
    this.onConfirm,
    this.onDecline,
    this.onCancel,
  });
  final String code, label;
  final int secondsRemaining;
  final bool waiting, providerApproved;
  final VoidCallback? onConfirm, onDecline, onCancel;
  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          'Joining as approval client "$label"',
          style: theme.textTheme.titleMedium,
        ),
        const SizedBox(height: 16),
        const Text('Comparison code'),
        Semantics(
          label: 'Comparison code ${code.split('').join(' ')}',
          excludeSemantics: true,
          child: SelectableText(
            code,
            key: const Key('comparison-code'),
            style: theme.textTheme.displayMedium?.copyWith(
              fontFeatures: const [FontFeature.tabularFigures()],
              letterSpacing: 4,
            ),
          ),
        ),
        const SizedBox(height: 8),
        const Text(
          'Read this code to the provider owner. They type it at the provider, which never shows it.',
        ),
        Text(
          'Expires in ${_minutes(secondsRemaining)}',
          style: TextStyle(color: AccessTheme.of(context).secondary),
        ),
        const SizedBox(height: 16),
        if (!waiting) ...[
          const Text(
            'Enroll only if you expected this invitation and the owner is reading this code from this screen.',
          ),
          const SizedBox(height: 16),
          AccessActions(
            children: [
              FilledButton(
                onPressed: onConfirm,
                child: const Text('Yes, enroll this device'),
              ),
              OutlinedButton(
                onPressed: onDecline,
                child: const Text('No, something is wrong'),
              ),
              TextButton(onPressed: onCancel, child: const Text('Cancel')),
            ],
          ),
        ] else ...[
          StatusLabel(
            providerApproved ? 'The provider owner approved. Finishing…' : 'Confirmed here. Waiting for the provider owner to type the code.',
            icon: Icons.hourglass_top,
          ),
          const SizedBox(height: 16),
          TextButton(
            onPressed: onCancel,
            child: const Text('Cancel enrollment'),
          ),
        ],
      ],
    );
  }
}

/// The joining endpoint: type the invitation, show the code, confirm.
class EnrollmentJoinPanel extends StatefulWidget {
  const EnrollmentJoinPanel({super.key, required this.flow});
  final EnrollmentFlow flow;
  @override
  State<EnrollmentJoinPanel> createState() => _EnrollmentJoinPanelState();
}

class _EnrollmentJoinPanelState extends State<EnrollmentJoinPanel> {
  final invitation = TextEditingController();
  @override
  void dispose() {
    invitation.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final flow = widget.flow, s = flow.joiner;
    final configured = flow.provider.configuration.configured;
    final idle = flow.ready && !s.busy;
    final code = s.comparisonCode;
    return AccessPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const AccessHeading(
            'Join this device to a provider',
            'Uses this app\'s provider connection and client certificate. Enrolling makes this device an approval client, never an administrator.',
          ),
          if (!flow.provider.platform.available)
            const StatusLabel(
              'Provider transport unavailable on this platform.',
            )
          else if (!configured)
            const StatusLabel(
              'Set up the provider connection first (Settings, advanced setup), or use manual enrollment below.',
            ),
          if (flow.sending || s.busy) const LinearProgressIndicator(),
          const SizedBox(height: 8),
          if (s.phase == enroll.JoinerPhase.idle) ...[
            const Text('Invitation from the provider owner'),
            const SizedBox(height: 8),
            Semantics(
              label: 'Invitation code',
              child: TextField(
                key: const Key('invitation-input'),
                controller: invitation,
                obscureText: true,
                enableSuggestions: false,
                autocorrect: false,
                enableIMEPersonalizedLearning: false,
                decoration: const InputDecoration(hintText: 'vwe1.…'),
              ),
            ),
            const SizedBox(height: 16),
            AccessActions(
              children: [
                FilledButton(
                  onPressed: idle && configured
                      ? () {
                          final text = invitation.text;
                          invitation.clear();
                          flow.join(text);
                        }
                      : null,
                  child: const Text('Join'),
                ),
                TextButton(onPressed: flow.close, child: const Text('Close')),
              ],
            ),
          ] else if (s.phase == enroll.JoinerPhase.joining) ...[
            StatusLabel(
              s.retryable
                  ? 'The provider did not answer. Trying again sends the identical request.'
                  : 'Contacting the provider…',
              icon: s.retryable ? Icons.wifi_off : Icons.sync,
            ),
            const SizedBox(height: 16),
            AccessActions(
              children: [
                if (s.retryable)
                  FilledButton(
                    onPressed: idle ? flow.retry : null,
                    child: const Text('Try again'),
                  ),
                TextButton(
                  onPressed: s.busy ? null : flow.cancelJoin,
                  child: const Text('Cancel'),
                ),
              ],
            ),
          ] else if (code.isNotEmpty) ...[
            JoinerComparison(
              code: code,
              label: s.label,
              secondsRemaining: s.secondsRemaining.toInt(),
              waiting: s.phase == enroll.JoinerPhase.waiting,
              providerApproved: s.providerApproved,
              onConfirm: idle ? flow.confirm : null,
              onDecline: idle ? flow.decline : null,
              onCancel: idle ? flow.cancelJoin : null,
            ),
          ] else if (s.phase == enroll.JoinerPhase.enrolled) ...[
            const StatusLabel(
              'Enrolled as an approval client. This device is not an administrator.',
              icon: Icons.check_circle_outline,
            ),
            const SizedBox(height: 16),
            FactRow('This client certificate · SHA-256', s.enrolledFingerprint),
            FilledButton(
              onPressed: () {
                flow.reset();
                flow.close();
              },
              child: const Text('Done'),
            ),
          ] else ...[
            StatusLabel(
              joinerEndText(s.end),
              key: const Key('joiner-end'),
              icon: Icons.error_outline,
            ),
            const SizedBox(height: 16),
            AccessActions(
              children: [
                FilledButton(
                  onPressed: flow.reset,
                  child: const Text('Start over'),
                ),
                TextButton(onPressed: flow.close, child: const Text('Close')),
              ],
            ),
          ],
          if (flow.message.isNotEmpty)
            Text(flow.message, key: const Key('enrollment-message')),
          const SizedBox(height: 16),
          _Details([
            ('Invitation ID', s.invitationId),
            (
              'This client certificate · SHA-256',
              flow.provider.configuration.fingerprint,
            ),
            ('Provider TLS leaf · SHA-256', flow.provider.configuration.pin),
          ], id: 'joiner'),
          const ManualEnrollment(),
        ],
      ),
    );
  }
}

String adminRefusalText(enroll.AdminRefusal refusal) => switch (refusal) {
  enroll.AdminRefusal.none => '',
  enroll.AdminRefusal.codeMismatch => 'That code does not match the joining device. The enrollment was stopped and nothing was enrolled. Create a new invitation.',
  enroll.AdminRefusal.awaitingPeer => 'The device has not joined yet.',
  enroll.AdminRefusal.expired => 'This invitation expired.',
  enroll.AdminRefusal.final_ => 'This enrollment already finished.',
  enroll.AdminRefusal.notFound =>
    'The provider no longer knows this enrollment.',
  enroll.AdminRefusal.duplicate => 'An equivalent invitation is already open, or an enabled agent already has this name.',
  enroll.AdminRefusal.limitReached =>
    'Too many open invitations. Cancel one or wait for it to expire.',
  enroll.AdminRefusal.invalidRequest => 'The provider refused these details. An agent must be its own account, not the provider or operator account, and a code is 8 digits.',
};

String adminOutcomeText(enroll.EnrollmentAdminSnapshot s) =>
    switch (s.outcome) {
      enroll.AdminOutcome.refused => adminRefusalText(s.refusal),
      enroll.AdminOutcome.authenticationFailed =>
        'Password not accepted. Nothing was approved.',
      enroll.AdminOutcome.rateLimited => 'Too many attempts. Wait a minute.',
      enroll.AdminOutcome.unavailable => 'The provider did not answer. If you approved or cancelled, refresh to see the outcome.',
      enroll.AdminOutcome.invalid => 'The provider sent an unexpected reply.',
      enroll.AdminOutcome.approved =>
        'Approved. The enrollment completes when the joining device confirms.',
      enroll.AdminOutcome.cancelled => 'Invitation cancelled.',
      _ => '',
    };

String sessionStateText(enroll.AdminSessionView s) => switch (s.state) {
  enroll.AdminSessionState.awaitingJoin => 'Waiting for the device to join',
  enroll.AdminSessionState.awaitingApprovals =>
    s.providerApproved
        ? 'You approved · waiting for the joining device to confirm'
        : s.joinerConfirmed
        ? 'Joined and confirmed there · type the code it shows'
        : 'Joined · type the code it shows',
  enroll.AdminSessionState.enrolled => 'Enrolled',
  enroll.AdminSessionState.cancelled =>
    'Cancelled by ${s.detail == 'joiner' ? 'the joining device' : 'the provider'}',
  enroll.AdminSessionState.expired => 'Expired · nothing enrolled',
  enroll.AdminSessionState.aborted =>
    'Stopped (${s.detail.replaceAll('_', ' ')}) · nothing enrolled',
  enroll.AdminSessionState.failed =>
    'Failed (${s.detail.replaceAll('_', ' ')})',
};

/// The provider owner, from an administrator companion.
class EnrollmentAddPanel extends StatefulWidget {
  const EnrollmentAddPanel({
    super.key,
    required this.flow,
    required this.password,
  });
  final EnrollmentFlow flow;
  final TextEditingController password;
  @override
  State<EnrollmentAddPanel> createState() => _EnrollmentAddPanelState();
}

class _EnrollmentAddPanelState extends State<EnrollmentAddPanel> {
  final label = TextEditingController(),
      uid = TextEditingController(),
      gid = TextEditingController(),
      code = TextEditingController();
  enroll.EnrolleeRole role = enroll.EnrolleeRole.companion;
  @override
  void dispose() {
    for (final c in [label, uid, gid, code]) {
      c.dispose();
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final flow = widget.flow, s = flow.admin;
    final idle = flow.ready && !s.busy;
    final theme = Theme.of(context);
    final blocked = switch (s.state) {
      enroll.AdminState.unauthorized => 'This approval client is not a provider administrator. The provider owner can invite from the terminal, or grant administration explicitly from the trusted console.',
      enroll.AdminState.unsupported => 'This provider does not offer guided enrollment to companions. Use the terminal on the provider host.',
      _ => '',
    };
    final issued = s.issued;
    final selected = s.sessions
        .where((row) => row.id == flow.selected)
        .firstOrNull;
    return AccessPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const AccessHeading(
            'Add a device or agent',
            'Invite, then type the code shown on the joining device. This provider never shows that code. A new device becomes an approval client; an agent becomes a requester. Neither is an administrator.',
          ),
          if (flow.sending || s.busy) const LinearProgressIndicator(),
          if (!flow.provider.configuration.configured)
            const StatusLabel(
              'No provider configured. Use advanced setup in Settings, or the terminal.',
            ),
          if (blocked.isNotEmpty) ...[
            StatusLabel(blocked, icon: Icons.lock_outline),
            const SizedBox(height: 8),
            const ManualEnrollment(initiallyExpanded: true),
          ] else ...[
            if (issued != null) ...[
              Text(
                'Invitation for "${issued.label}"',
                style: theme.textTheme.titleMedium,
              ),
              const SizedBox(height: 8),
              SelectableText(
                issued.invitationCode,
                key: const Key('invitation-code'),
              ),
              const SizedBox(height: 8),
              Text(
                'Shown once. Give it privately to the person at the joining ${issued.role == enroll.EnrolleeRole.agent ? 'agent account ("vw-access enroll join")' : 'device ("Join this device to a provider")'}. Anyone holding it can try to join until it is used, cancelled or expires (${_minutes(issued.expiresInSeconds.toInt())}).',
              ),
              const SizedBox(height: 8),
              AccessActions(
                children: [
                  OutlinedButton.icon(
                    onPressed: () => Clipboard.setData(
                      ClipboardData(text: issued.invitationCode),
                    ),
                    icon: const Icon(Icons.copy),
                    label: const Text('Copy invitation'),
                  ),
                  TextButton(
                    onPressed: flow.dismissInvitation,
                    child: const Text('Hide invitation'),
                  ),
                ],
              ),
              const Divider(height: 32),
            ],
            Text('New invitation', style: theme.textTheme.titleMedium),
            const SizedBox(height: 8),
            SegmentedButton<enroll.EnrolleeRole>(
              segments: const [
                ButtonSegment(
                  value: enroll.EnrolleeRole.companion,
                  label: Text('Device (this app)'),
                  icon: Icon(Icons.laptop_mac),
                ),
                ButtonSegment(
                  value: enroll.EnrolleeRole.agent,
                  label: Text('Agent (terminal)'),
                  icon: Icon(Icons.terminal),
                ),
              ],
              selected: {role},
              onSelectionChanged: (value) => setState(() => role = value.first),
            ),
            const SizedBox(height: 16),
            _field(
              'Name',
              TextField(key: const Key('enroll-label'), controller: label),
            ),
            if (role == enroll.EnrolleeRole.agent)
              Row(
                children: [
                  Expanded(
                    child: _field(
                      'Agent user ID',
                      TextField(
                        key: const Key('enroll-uid'),
                        controller: uid,
                        keyboardType: TextInputType.number,
                        inputFormatters: [
                          FilteringTextInputFormatter.digitsOnly,
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: _field(
                      'Agent group ID',
                      TextField(
                        key: const Key('enroll-gid'),
                        controller: gid,
                        keyboardType: TextInputType.number,
                        inputFormatters: [
                          FilteringTextInputFormatter.digitsOnly,
                        ],
                      ),
                    ),
                  ),
                ],
              ),
            const SizedBox(height: 16),
            FilledButton(
              onPressed: idle
                  ? () => flow.invite(
                      role: role,
                      label: label.text,
                      uid: int.tryParse(uid.text) ?? 0,
                      gid: int.tryParse(gid.text) ?? 0,
                    )
                  : null,
              child: const Text('Create invitation'),
            ),
            const Divider(height: 32),
            Row(
              children: [
                Expanded(
                  child: Text(
                    'Invitations on this provider',
                    style: theme.textTheme.titleMedium,
                  ),
                ),
                TextButton(
                  onPressed: idle ? flow.list : null,
                  child: const Text('Refresh'),
                ),
              ],
            ),
            if (s.state == enroll.AdminState.unavailable)
              const StatusLabel('Provider unavailable.'),
            if (s.sessions.isEmpty && s.state == enroll.AdminState.ready)
              const Text('None. Invitations live in provider memory only.'),
            for (final row in s.sessions)
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 8),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      '${row.label} · ${row.role == enroll.EnrolleeRole.agent ? 'agent' : 'device'}',
                      style: theme.textTheme.titleSmall,
                    ),
                    Text(
                      sessionStateText(row),
                      key: Key('session-state-${row.id}'),
                    ),
                    if (row.state == enroll.AdminSessionState.awaitingJoin ||
                        row.state == enroll.AdminSessionState.awaitingApprovals)
                      AccessActions(
                        children: [
                          if (row.state ==
                                  enroll.AdminSessionState.awaitingApprovals &&
                              !row.providerApproved &&
                              row.id != flow.selected)
                            FilledButton(
                              onPressed: idle
                                  ? () => flow.select(row.id)
                                  : null,
                              child: const Text('Type code to approve'),
                            ),
                          TextButton(
                            onPressed: idle
                                ? () => flow.cancelInvitation(row.id)
                                : null,
                            child: const Text('Cancel invitation'),
                          ),
                        ],
                      ),
                    if (selected != null && row.id == selected.id) ...[
                      const SizedBox(height: 16),
                      Text(
                        'Ask the person at "${row.label}" to read the code on their screen, and type it here.',
                      ),
                      const SizedBox(height: 8),
                      _field(
                        'Code shown on the joining device',
                        TextField(
                          key: const Key('approve-code'),
                          controller: code,
                          keyboardType: TextInputType.number,
                          autocorrect: false,
                          enableSuggestions: false,
                          inputFormatters: [
                            FilteringTextInputFormatter.allow(
                              RegExp(r'[0-9 -]'),
                            ),
                            LengthLimitingTextInputFormatter(9),
                          ],
                          decoration: const InputDecoration(
                            hintText: '1234-5678',
                          ),
                        ),
                      ),
                      const SizedBox(height: 16),
                      accessPassword(widget.password, 'Provider password'),
                      const SizedBox(height: 16),
                      AccessActions(
                        children: [
                          FilledButton(
                            onPressed: idle
                                ? () {
                                    final typed = code.text;
                                    final secret = widget.password.text;
                                    code.clear();
                                    widget.password.clear();
                                    flow.approve(row.id, typed, secret);
                                  }
                                : null,
                            child: const Text('Approve enrollment'),
                          ),
                          TextButton(
                            onPressed: () {
                              code.clear();
                              widget.password.clear();
                              flow.select('');
                            },
                            child: const Text('Back'),
                          ),
                        ],
                      ),
                    ],
                    _Details([
                      ('Enrollment ID', row.id),
                      ('Joining identity · SHA-256', row.joinerFingerprint),
                      if (row.role == enroll.EnrolleeRole.agent)
                        (
                          'Agent account',
                          'uid ${row.agentUid} · gid ${row.agentGid}',
                        ),
                      if (row.state == enroll.AdminSessionState.enrolled)
                        ('Enrolled identity', row.detail),
                    ], id: row.id),
                    const Divider(),
                  ],
                ),
              ),
            const SizedBox(height: 8),
            const ManualEnrollment(),
          ],
          if (adminOutcomeText(s).isNotEmpty || flow.message.isNotEmpty)
            Text(
              flow.message.isNotEmpty ? flow.message : adminOutcomeText(s),
              key: const Key('enrollment-message'),
            ),
          const SizedBox(height: 8),
          TextButton(onPressed: flow.close, child: const Text('Close')),
        ],
      ),
    );
  }
}
