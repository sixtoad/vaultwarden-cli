import 'dart:async';

import 'package:flutter/material.dart';

import '../platform/approval_key.dart';
import '../platform/notifications.dart';
import '../platform/provider.dart';
import '../app/access_shell.dart';
import '../design/access_theme.dart';
import '../design/components.dart';
import 'request_review.dart';
import 'support_views.dart';
import 'installation_settings.dart';
import 'devices_view.dart';
import 'controller.dart';
import 'pilot_bundle.dart';
import 'review_notifications.dart';
import 'touch_id.dart';
import 'touch_id_views.dart';

class ProviderPage extends StatefulWidget {
  const ProviderPage({
    super.key,
    required this.platform,
    required this.syntheticBuilder,
    this.approvalKeys,
    this.notifications,
  });
  final ProviderPlatform platform;
  final ApprovalKeyPlatform? approvalKeys;
  final ReviewNotificationPlatform? notifications;
  final WidgetBuilder syntheticBuilder;
  @override
  State<ProviderPage> createState() => _ProviderPageState();
}

class _ProviderPageState extends State<ProviderPage>
    with WidgetsBindingObserver {
  late ProviderController controller;
  late TouchIdController touchId;
  late ReviewNotifier notifier;

  /// Set when a notification opened a request: what the detail pane says if
  /// the fresh review of that request cannot be loaded.
  String notificationRequest = '';
  String notificationNote = '';
  final endpoint = TextEditingController(), pin = TextEditingController();
  final importPassword = TextEditingController(),
      approvalPassword = TextEditingController(),
      unlockPassword = TextEditingController();
  final pilotBundle = TextEditingController();
  final managementPassword = TextEditingController();
  final touchIdPassword = TextEditingController();
  final contentScroll = ScrollController(keepScrollOffset: false);
  bool dedicated = false;
  bool detailOpen = false;
  AccessDestination destination = AccessDestination.requests;
  ThemeMode appearance = ThemeMode.system;
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    controller = ProviderController(widget.platform)
      ..clearPasswords = clearPasswords;
    notifier = ReviewNotifier(
      widget.notifications ?? NativeReviewNotificationPlatform(),
    )..addListener(changed);
    controller.addListener(changed);
    touchId = TouchIdController(
      controller,
      widget.approvalKeys ?? NativeApprovalKeyPlatform(),
    )..addListener(changed);
    touchId.onExemptionEnded = applyLifecycle;
    controller.onInbox = (ids, foreground) =>
        notifier.observe(ids, foreground: foreground);
    controller.watchAllowed = () => notifier.active;
    unawaited(
      start().catchError((Object error, StackTrace stack) {
        FlutterError.reportError(
          FlutterErrorDetails(
            exception: error,
            stack: stack,
            library: 'provider page',
          ),
        );
      }),
    );
  }

  /// Initialize the provider, and read Touch ID and the local key even when
  /// that fails (password approval and Settings still need them).
  Future<void> start() async {
    // Independent of the provider: never delays (or blocks) its first read.
    unawaited(startNotifications());
    try {
      await controller.initialize();
    } finally {
      if (mounted) await touchId.refreshLocal();
    }
  }

  /// Reads the notification setting and permission (never prompts) and
  /// takes a click that launched the app before Flutter listened.
  Future<void> startNotifications() async {
    await notifier.load();
    if (!mounted) return;
    String? launched;
    try {
      launched = await notifier.platform.listen(openNotification);
    } catch (_) {
      launched = null;
    }
    if (launched != null && mounted) openNotification(launched);
  }

  /// A notification was clicked. The native side has brought the window
  /// forward; the request is reviewed freshly from the provider once the
  /// window is foreground. Nothing from the notification is displayed.
  void openNotification(String token) {
    if (!mounted) return;
    final id = notifier.resolve(token);
    controller.devicesVisible = false;
    controller.setActivityCurrent(false);
    resetContentScroll();
    if (id == null) {
      controller.cancelPendingReview();
      controller.invalidate();
      setState(() {
        destination = AccessDestination.requests;
        detailOpen = false;
        notificationRequest = '';
        notificationNote = 'That notification is no longer available. Pending requests are listed here.';
      });
      unawaited(controller.refresh());
      return;
    }
    // Never retire an operation in flight (a decision, a Touch ID prompt):
    // the fresh review simply waits until the provider is idle.
    if (!controller.busy && !touchId.lifecycleExempt) controller.invalidate();
    setState(() {
      destination = AccessDestination.requests;
      detailOpen = true;
      notificationRequest = id;
      notificationNote = '';
    });
    controller.reviewWhenReady(id);
  }

  /// After a Touch ID approval or enrollment: the window's lifecycle events
  /// were partly ignored while the system prompt was up, so apply the
  /// current state now. Anything but `resumed` suspends.
  void applyLifecycle() {
    if (!mounted) return;
    if (WidgetsBinding.instance.lifecycleState == AppLifecycleState.resumed) {
      if (controller.suspended) controller.resume();
    } else {
      controller.suspend();
    }
  }

  String _notifiedProvider = '';
  void changed() {
    // Notification tokens and announced ids belong to one provider.
    final c = controller.configuration;
    final provider = '${c.endpoint}|${c.pin}|${c.fingerprint}';
    if (provider != _notifiedProvider) {
      _notifiedProvider = provider;
      notifier.reset();
      controller.cancelPendingReview();
    }
    if (notificationRequest.isNotEmpty &&
        controller.state.review?.id == notificationRequest) {
      notificationRequest = ''; // loaded; later retirement reads normally
    }
    if (mounted) setState(() {});
  }

  void clearPasswords() {
    importPassword.clear();
    approvalPassword.clear();
    unlockPassword.clear();
    pilotBundle.clear();
    managementPassword.clear();
    touchIdPassword.clear();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (touchId.lifecycleExempt) {
      // The system Touch ID prompt deactivates the window, so `inactive` and
      // `resumed` are deferred until the approval or enrollment ends
      // (`applyLifecycle`). Hiding, pausing and detaching still cancel the
      // prompt and suspend at once; the native signer also cancels it on
      // sleep, display sleep, screen lock, session switch, close and quit.
      if (state == AppLifecycleState.inactive ||
          state == AppLifecycleState.resumed) {
        return;
      }
      unawaited(touchId.cancel());
      controller.suspend();
      return;
    }
    if (state == AppLifecycleState.resumed) {
      controller.resume();
      unawaited(touchId.refreshLocal());
      unawaited(notifier.refreshPermission());
    }
    if ([
      AppLifecycleState.inactive,
      AppLifecycleState.hidden,
      AppLifecycleState.paused,
      AppLifecycleState.detached,
    ].contains(state)) {
      controller.suspend();
    }
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    controller.removeListener(changed);
    touchId.removeListener(changed);
    touchId.dispose();
    notifier.removeListener(changed);
    notifier.dispose();
    controller.dispose();
    contentScroll.dispose();
    for (final field in [
      endpoint,
      pin,
      importPassword,
      approvalPassword,
      unlockPassword,
      pilotBundle,
      managementPassword,
      touchIdPassword,
    ]) {
      field.dispose();
    }
    super.dispose();
  }

  // Every navigation boundary retires Rust authority and clears all secrets
  // before changing the visible destination. Status settlement keeps its owner.
  void resetContentScroll() {
    if (contentScroll.hasClients) contentScroll.jumpTo(0);
    // Destination changes replace the Scrollable. Reset its newly attached
    // position too; review/back within Requests keeps the existing position.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted && contentScroll.hasClients) contentScroll.jumpTo(0);
    });
  }

  void navigate(AccessDestination next) {
    if (next == destination && !detailOpen) return;
    controller.cancelPendingReview();
    notificationRequest = '';
    notificationNote = '';
    controller.invalidate(); // mutation: navigation retirement
    controller.devicesVisible = next == AccessDestination.devices;
    controller.setActivityCurrent(next == AccessDestination.activity);
    setState(() {
      destination = next;
      detailOpen = false;
    });
    resetContentScroll();
    unawaited(controller.refresh());
  }

  void backToRequests() {
    controller.cancelPendingReview();
    notificationRequest = '';
    notificationNote = '';
    controller.invalidate(); // mutation: back retirement
    controller.devicesVisible = false;
    controller.setActivityCurrent(false);
    setState(() {
      destination = AccessDestination.requests;
      detailOpen = false;
    });
    resetContentScroll();
    unawaited(controller.refresh());
  }

  void openRequest(String id) {
    controller.cancelPendingReview();
    notificationRequest = '';
    notificationNote = '';
    controller.devicesVisible = false;
    controller.setActivityCurrent(false);
    resetContentScroll();
    setState(() {
      destination = AccessDestination.requests;
      detailOpen = true;
    });
    unawaited(controller.review(id));
  }

  Widget recoveryAndStatus() => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      if (controller.recoveryId.isNotEmpty) ...[
        AccessPanel(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const StatusLabel(
                'Decision outcome requires recovery',
                icon: Icons.help_outline,
              ),
              const SizedBox(height: 8),
              SelectableText(
                'Uncertain decision for request: ${controller.recoveryId}',
                key: const Key('provider-uncertain'),
              ),
              const Text(
                'Only the original request status will be checked. A pending or unavailable status remains uncertain; decisions and unlocks are never resent.',
              ),
              const SizedBox(height: 12),
              OutlinedButton(
                onPressed: controller.busy ? null : controller.refresh,
                child: const Text('Refresh original request status'),
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),
      ],
      Text(controller.state.message, key: const Key('provider-status')),
      if (controller.diagnostic.isNotEmpty) Text(controller.diagnostic),
      if (controller.busy) const LinearProgressIndicator(),
      const SizedBox(height: 16),
    ],
  );

  Widget requestList() {
    final state = controller.state, config = controller.configuration;
    return AccessPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const AccessHeading(
            'Requests',
            'Review the exact scope before each decision.',
          ),
          if (!config.configured) ...[
            const Text(
              'Connect a dedicated development identity in Settings to load requests.',
            ),
            const SizedBox(height: 16),
            OutlinedButton(
              onPressed: () => navigate(AccessDestination.settings),
              child: const Text('Open advanced setup'),
            ),
          ] else ...[
            StatusLabel(
              state.locked
                  ? 'Provider locked or authority not refreshed'
                  : 'Provider unlocked',
              icon: state.locked ? Icons.lock_outline : Icons.lock_open,
            ),
            const SizedBox(height: 16),
            if (state.locked && controller.recoveryId.isEmpty) ...[
              const Text(
                'Unlock is separate from approval. After unlocking, the agent must submit a new request.',
              ),
              const SizedBox(height: 12),
              accessPassword(unlockPassword, 'Provider unlock password'),
              const SizedBox(height: 12),
              OutlinedButton(
                onPressed: controller.busy
                    ? null
                    : () {
                        final secret = unlockPassword.text; // secrets-ignore: runtime input, not a credential literal
                        clearPasswords();
                        unawaited(controller.unlock(secret));
                      },
                child: const Text('Unlock provider'),
              ),
            ],
            OutlinedButton(
              onPressed: controller.busy ? null : controller.refresh,
              child: const Text('Refresh authority and inbox'),
            ),
            if (notificationNote.isNotEmpty) ...[
              const SizedBox(height: 16),
              Text(notificationNote, key: const Key('notification-note')),
            ],
            const SizedBox(height: 16),
            Text(
              'Pending requests: ${state.requests.length} / 256 maximum. The provider caps the inbox at 256; this is not pagination.',
            ),
            const SizedBox(height: 16),
            if (state.requests.isEmpty)
              const Text('No pending request IDs are currently available.'),
            for (final id in state.requests)
              Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: OutlinedButton(
                  onPressed:
                      controller.busy ||
                          state.locked ||
                          controller.recoveryId.isNotEmpty
                      ? null
                      : () => openRequest(id),
                  child: Text('Review $id'),
                ),
              ),
          ],
        ],
      ),
    );
  }

  Widget requestDetail() {
    final state = controller.state;
    if (state.review == null) {
      return AccessPanel(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const AccessHeading(
              'Request review',
              'A fresh validated review is required for every decision.',
            ),
            if (controller.busy ||
                controller.pendingReview == notificationRequest &&
                    notificationRequest.isNotEmpty)
              const Text('Loading or finishing the original operation…')
            else if (notificationRequest.isNotEmpty)
              const Text(
                'The request from the notification could not be loaded. It may have been removed or the provider is locked or unreachable. Pending requests are listed.',
                key: Key('notification-unavailable'),
              )
            else
              const Text(
                'No active review. Select a pending request to load its complete scope. Expired or retired reviews cannot authorize an operation.',
              ),
            if (touchId.message.isNotEmpty) ...[
              const SizedBox(height: 16),
              Text(touchId.message, key: const Key('touch-id-message')),
            ],
            if (state.statusId.isNotEmpty) ...[
              const SizedBox(height: 16),
              FactRow('Latest status request', state.statusId),
              SelectableText(state.statusText),
            ],
            const SizedBox(height: 16),
            TextButton(
              onPressed: backToRequests,
              child: const Text('Back to requests'),
            ),
          ],
        ),
      );
    }
    return RequestReview(
      state: state,
      endpoint: controller.configuration.endpoint,
      origin: controller.management.originId == controller.state.reviewId
          ? controller.management.originText
          : '',
      password: approvalPassword, // secrets-ignore: UI controller
      onApprove: () {
        final secret = approvalPassword.text; // secrets-ignore: runtime input
        clearPasswords();
        unawaited(controller.decide(true, secret));
      },
      onDeny: () {
        clearPasswords();
        unawaited(controller.decide(false, ''));
      },
      onCancel: backToRequests,
      touchIdOffered: touchId.available,
      onTouchId: touchId.canApprove ? () => unawaited(touchId.approve()) : null,
      touchIdNote: touchId.working ? '' : touchId.unavailableReason,
      touchIdMessage: touchId.message,
    );
  }

  Widget settings() {
    final config = controller.configuration;
    return AccessPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const AccessHeading(
            'Settings',
            'Appearance, native capabilities and advanced development setup',
          ),
          DropdownButtonFormField<ThemeMode>(
            initialValue: appearance,
            isExpanded: true,
            decoration: const InputDecoration(labelText: 'Appearance'),
            items: const [
              DropdownMenuItem(value: ThemeMode.system, child: Text('System')),
              DropdownMenuItem(value: ThemeMode.light, child: Text('Light')),
              DropdownMenuItem(value: ThemeMode.dark, child: Text('Dark')),
            ],
            onChanged: (value) {
              if (value != null) setState(() => appearance = value);
            },
          ),
          const SizedBox(height: 24),
          ReviewNotificationSettings(notifier: notifier),
          const SizedBox(height: 24),
          const InstallationSettings(),
          if (config.configured) ...[
            TouchIdKeyPanel(
              touchId: touchId,
              keys: controller.keys,
              password: touchIdPassword, // secrets-ignore: UI controller
              enabled: controller.canManage && !controller.managementPending,
            ),
            const SizedBox(height: 24),
          ],
          const ProviderCapabilities(),
          const SizedBox(height: 24),
          if (disposablePilotEnabled &&
              widget.platform is PilotProviderPlatform) ...[
            const Text(
              'Disposable test only. This bundle contains a private identity and test passwords. Never paste real vault credentials.',
            ),
            TextField(
              key: const Key('pilot-bundle'),
              controller: pilotBundle,
              enabled: controller.canSetupPilot,
              obscureText: true,
              maxLength: PilotBundle.maximumLength,
              enableSuggestions: false,
              autocorrect: false,
              enableIMEPersonalizedLearning: false,
              decoration: const InputDecoration(
                labelText: 'Paste disposable test bundle',
                counterText: '',
              ),
            ),
            FilledButton(
              onPressed: controller.canSetupPilot
                  ? () {
                      final input = pilotBundle.text;
                      clearPasswords();
                      unawaited(controller.setupPilot(input));
                    }
                  : null,
              child: const Text('Configure and unlock'),
            ),
            const SizedBox(height: 20),
          ],
          ExpansionTile(
            title: const Text('Advanced development provider setup'),
            initiallyExpanded: !config.configured,
            children: [
              const Text(
                'Use a separately issued and enrolled Flutter development client certificate. Do not import the installed Swift companion identity. Select the private CA in DER format and the dedicated PKCS#12 in the native file dialogs.',
              ),
              TextField(
                controller: endpoint,
                enabled: controller.canSetup,
                decoration: const InputDecoration(
                  labelText: 'HTTPS provider endpoint',
                ),
              ),
              TextField(
                controller: pin,
                enabled: controller.canSetup,
                decoration: const InputDecoration(
                  labelText: 'Trusted server leaf SHA-256 (64 lowercase hex)',
                ),
              ),
              accessPassword(importPassword, 'PKCS#12 import passphrase'),
              CheckboxListTile(
                value: dedicated,
                onChanged: controller.canSetup
                    ? (value) => setState(() => dedicated = value ?? false)
                    : null,
                title: const Text(
                  'This is a dedicated development identity, separately enrolled on Linux.',
                ),
              ),
              FilledButton(
                onPressed: controller.canSetup && dedicated
                    ? () {
                        final secret = importPassword.text; // secrets-ignore: runtime input, not a credential literal
                        clearPasswords();
                        unawaited(
                          controller.setup(endpoint.text, pin.text, secret),
                        );
                      }
                    : null,
                child: const Text('Select CA and import dedicated identity'),
              ),
            ],
          ),

          if (!config.configured)
            OutlinedButton(
              onPressed: controller.busy ? null : controller.refresh,
              child: const Text('Reload saved provider setup'),
            ),
          const SizedBox(height: 24),
          OutlinedButton(
            onPressed:
                controller.busy ||
                    controller.recoveryId.isNotEmpty ||
                    controller.managementPending
                ? null
                : () async {
                    controller.setRouteCurrent(false);
                    await Navigator.of(context).push(
                      MaterialPageRoute<void>(
                        builder: (context) => Theme(
                          data: accessTheme(resolvedBrightness),
                          child: widget.syntheticBuilder(context),
                        ),
                      ),
                    );
                    if (mounted) controller.setRouteCurrent(true);
                  },
            child: const Text('Open separate synthetic signing demonstration'),
          ),
        ],
      ),
    );
  }

  Brightness get resolvedBrightness => switch (appearance) {
    ThemeMode.light => Brightness.light,
    ThemeMode.dark => Brightness.dark,
    ThemeMode.system => MediaQuery.platformBrightnessOf(context),
  };

  @override
  Widget build(BuildContext context) => Theme(
    data: accessTheme(resolvedBrightness),
    child: AccessShell(
      destination: destination,
      onDestination: navigate,
      detailOpen: detailOpen,
      onBack: backToRequests,
      body: LayoutBuilder(
        builder: (context, constraints) {
          final wide =
              constraints.maxWidth >= 800 &&
              MediaQuery.textScalerOf(context).scale(15) <= 21;
          final state = controller.state;
          final content = switch (destination) {
            AccessDestination.requests =>
              wide
                  ? Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        SizedBox(width: 300, child: requestList()),
                        const SizedBox(width: 24),
                        Expanded(child: requestDetail()),
                      ],
                    )
                  : detailOpen
                  ? requestDetail()
                  : requestList(),
            AccessDestination.devices => ProviderDevices(
              controller: controller,
              password: managementPassword, // secrets-ignore: UI controller
            ),
            AccessDestination.activity => ProviderActivity(
              state: state,
              connected: controller.connected,
              configured: controller.configuration.configured,
              recoveryPending: controller.recoveryId.isNotEmpty,
              managementPending: controller.managementPending,
              onRefresh:
                  controller.busy ||
                      !controller.eligible ||
                      controller.managementPending
                  ? null
                  : controller.refresh,
              onReopen:
                  !controller.connected ||
                      state.locked ||
                      controller.busy ||
                      (controller.recoveryId.isNotEmpty ||
                          controller.managementPending)
                  ? null
                  : openRequest,
            ),
            AccessDestination.settings => settings(),
          };
          return SingleChildScrollView(
            controller: contentScroll,
            key: ValueKey(destination),
            padding: const EdgeInsets.all(24),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                if (!widget.platform.available) ...[
                  const StatusLabel(
                    'Provider transport unavailable on this platform. Provider approvals require macOS.',
                    key: Key('provider-unavailable'),
                  ),
                  const SizedBox(height: 16),
                ],
                recoveryAndStatus(),
                content,
              ],
            ),
          );
        },
      ),
    ),
  );
}
