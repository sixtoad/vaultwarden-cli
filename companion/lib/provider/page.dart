import 'dart:async';
import 'dart:io' show Platform;

import 'package:flutter/material.dart';

import '../platform/approval_client.dart';
import '../platform/approval_key.dart';
import '../platform/installation.dart';
import '../platform/notifications.dart';
import '../platform/provider.dart';
import '../app/access_shell.dart';
import '../app/capabilities.dart';
import '../app/shell_status.dart';
import '../design/access_theme.dart';
import '../design/components.dart';
import '../design/metrics.dart';
import 'request_panes.dart';
import 'review/review_session.dart';
import 'review/validity.dart';
import 'requests_view.dart';
import 'settings_view.dart';
import 'support_views.dart';
import 'devices_view.dart';
import 'enrollment_flow.dart';
import 'controller.dart';
import 'pilot_bundle.dart';
import 'review_notifications.dart';
import 'touch_id.dart';

class ProviderPage extends StatefulWidget {
  const ProviderPage({
    super.key,
    required this.platform,
    required this.syntheticBuilder,
    this.approvalKeys,
    this.notifications,
    this.installation,
    this.clock,
    this.operatingSystem,
    this.deviceSignals,
  });
  final ProviderPlatform platform;

  /// `Platform.operatingSystem` unless a test pins another one.
  final String? operatingSystem;

  /// Native lock/interruption signals; null uses the native ones (phones).
  final DeviceSignalPlatform? deviceSignals;

  /// The wall clock for the review countdown; null reads `DateTime.now`.
  final ReviewClock? clock;

  /// Desktop installation inspection; null uses the native one.
  final InstallationPlatform? installation;
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
  final enrollmentPassword = TextEditingController();
  late final EnrollmentFlow enrollment;
  final touchIdPassword = TextEditingController();
  final contentScroll = ScrollController(keepScrollOffset: false);
  bool dedicated = false;
  bool detailOpen = false;

  /// The authorization/denial step (bound to one request ID) and the
  /// countdown of the loaded review.
  final reviewSession = ReviewSession();
  DateTime now() => (widget.clock ?? _monotonic)();

  /// Wall time at start plus monotonic elapsed time: a wall clock moved
  /// during the session never stretches or shortens the 55 s ticket
  /// countdown (Rust measures it with a monotonic clock).
  late final DateTime _started = DateTime.now();
  final _elapsed = Stopwatch()..start();
  DateTime _monotonic() => _started.add(_elapsed.elapsed);

  /// The request the user (or a notification) last opened; marks its row
  /// while the detail is open, even before its review has loaded.
  String openedRequest = '';

  /// This device's system, and whether it is a phone (#60).
  String get os => widget.operatingSystem ?? Platform.operatingSystem;
  bool get mobile => isMobileSystem(os);

  /// A device lock signal arrived while the app was already out of the
  /// foreground; the next lifecycle `resumed` (even one deferred during a
  /// system prompt) clears it.
  bool _locked = false;
  void Function()? _stopSignals;
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
    enrollment = EnrollmentFlow(controller)..addListener(changed);
    touchId = TouchIdController(
      controller,
      widget.approvalKeys ?? NativeApprovalKeyPlatform(),
      operatingSystem: os,
    )..addListener(changed);
    touchId.onExemptionEnded = applyLifecycle;
    _stopSignals =
        (widget.deviceSignals ??
                NativeDeviceSignalPlatform(operatingSystem: os))
            .listen(onDeviceSignal);
    controller.onInbox = (ids, foreground) =>
        notifier.observe(ids, foreground: foreground);
    controller.watchAllowed = () => notifier.active;
    controller.onWatching = notifier.setWatching;
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
    var launched = <String>[];
    try {
      launched = await notifier.platform.listen(openNotification);
    } catch (_) {
      launched = [];
    }
    // Every click queued before Flutter listened, oldest first; the last
    // one is what the page ends up showing.
    for (final token in launched) {
      if (mounted) openNotification(token);
    }
  }

  /// A notification was clicked. The native side has brought the window
  /// forward; the request is reviewed freshly from the provider once the
  /// window is foreground. Nothing from the notification is displayed.
  void openNotification(String token) {
    if (!mounted) return;
    final id = notifier.resolve(token);
    controller.devicesVisible = false;
    controller.setActivityCurrent(false);
    reviewSession.closeStep();
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
      openedRequest = id;
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
    if (!_locked &&
        WidgetsBinding.instance.lifecycleState == AppLifecycleState.resumed) {
      if (controller.suspended) {
        controller.resume();
        reloadOpenReview();
      }
    } else {
      controller.suspend();
    }
  }

  /// A phone locked or was interrupted: retire the authorization and the
  /// review at once, whatever Flutter's lifecycle says yet (#60).
  ///
  /// A `locked` that arrives while Flutter still reports `resumed` (the
  /// signal raced ahead of the lifecycle, or came late after an unlock) is
  /// handled like `interrupted`: a real lock always takes the app out of
  /// `resumed`, which suspends it until the next `resumed`. Latching it
  /// would leave the phone suspended after an unlock that already happened.
  void onDeviceSignal(DeviceSignal signal) {
    if (!mounted) return;
    if (signal == DeviceSignal.locked &&
        WidgetsBinding.instance.lifecycleState != AppLifecycleState.resumed) {
      _locked = true;
    }
    unawaited(touchId.retire());
    controller.suspend();
    if (!touchId.lifecycleExempt) applyLifecycle();
  }

  /// Phones re-load the open request's review from the provider on return
  /// to the foreground; nothing from before the interruption is reused.
  void reloadOpenReview() {
    if (!mobile ||
        !detailOpen ||
        openedRequest.isEmpty ||
        destination != AccessDestination.requests ||
        notificationRequest.isNotEmpty) {
      return;
    }
    reviewSession.beginLoad(openedRequest);
    controller.reviewWhenReady(openedRequest);
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
    if (reviewSession.observe(controller.state, now())) clearPasswords();
    if (mounted) setState(() {});
  }

  void clearPasswords() {
    importPassword.clear();
    approvalPassword.clear();
    unlockPassword.clear();
    pilotBundle.clear();
    managementPassword.clear();
    enrollmentPassword.clear();
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
      if (state == AppLifecycleState.resumed) {
        // The device is unlocked again; `applyLifecycle` resumes when the
        // prompt ends.
        _locked = false;
        return;
      }
      if (state == AppLifecycleState.inactive) return;
      unawaited(touchId.retire());
      controller.suspend();
      return;
    }
    if (state == AppLifecycleState.resumed) {
      _locked = false;
      controller.resume();
      reloadOpenReview();
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
    _stopSignals?.call();
    controller.removeListener(changed);
    enrollment
      ..removeListener(changed)
      ..dispose();
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
      enrollmentPassword,
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
    unawaited(touchId.retire()); // a route change retires the attempt
    controller.cancelPendingReview();
    notificationRequest = '';
    notificationNote = '';
    controller.invalidate(); // mutation: navigation retirement
    reviewSession.closeStep();
    enrollment.close();
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
    unawaited(touchId.retire());
    controller.cancelPendingReview();
    notificationRequest = '';
    notificationNote = '';
    controller.invalidate(); // mutation: back retirement
    reviewSession.closeStep();
    enrollment.close();
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
    unawaited(touchId.retire()); // even reopening the same request
    controller.cancelPendingReview();
    reviewSession.beginLoad(id); // mutation: selection closes step
    notificationRequest = '';
    notificationNote = '';
    controller.devicesVisible = false;
    controller.setActivityCurrent(false);
    resetContentScroll();
    setState(() {
      destination = AccessDestination.requests;
      detailOpen = true;
      openedRequest = id;
    });
    unawaited(controller.review(id));
  }

  // Every operation below reads its secret once, then clears all of them
  // before the operation starts.
  void unlock() {
    final secret = unlockPassword
        .text; // secrets-ignore: runtime input, not a credential literal
    clearPasswords();
    unawaited(controller.unlock(secret));
  }

  void approve() {
    final secret = approvalPassword.text; // secrets-ignore: runtime input
    clearPasswords();
    unawaited(controller.decide(true, secret));
  }

  void deny() {
    clearPasswords();
    unawaited(controller.decide(false, ''));
  }

  /// Opens or leaves the authorization/denial step of the shown review.
  /// Every change clears the typed password first.
  void setReviewStep(ReviewStep step) {
    clearPasswords(); // mutation: step change clears secrets
    setState(() => reviewSession.setStep(controller.state.reviewId, step));
  }

  /// A fresh review of the request whose review expired.
  void reloadReview() {
    final shown = controller.state.reviewId;
    final id = shown.isNotEmpty ? shown : openedRequest;
    if (id.isNotEmpty) openRequest(id);
  }

  void setupPilot() {
    final input = pilotBundle.text;
    clearPasswords();
    unawaited(controller.setupPilot(input));
  }

  void setupProvider() {
    final secret = importPassword
        .text; // secrets-ignore: runtime input, not a credential literal
    clearPasswords();
    unawaited(controller.setup(endpoint.text, pin.text, secret));
  }

  Future<void> openSynthetic() async {
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
  }

  Brightness get resolvedBrightness => switch (appearance) {
    ThemeMode.light => Brightness.light,
    ThemeMode.dark => Brightness.dark,
    ThemeMode.system => MediaQuery.platformBrightnessOf(context),
  };

  ShellStatus get shellStatus => ShellStatus(
    connection: ShellConnection.of(
      available: widget.platform.available,
      configured: controller.configuration.configured,
      connected: controller.connected,
      locked: controller.state.locked,
    ),
    endpoint: controller.configuration.endpoint,
    capabilities: DeviceCapabilities.derive(
      operatingSystem: os,
      providerTransport: widget.platform.available,
      biometricSigner: touchId.available,
      reviewNotifications: notifier.available,
    ),
  );

  Widget content(BuildContext context, double width) {
    final state = controller.state;
    return switch (destination) {
      AccessDestination.requests => RequestsView(
        width: width,
        detailOpen: detailOpen,
        list: RequestListPane(
          controller: controller,
          unlockPassword: unlockPassword, // secrets-ignore: UI controller
          notificationNote: notificationNote,
          selectedId: detailOpen ? openedRequest : '',
          onUnlock: unlock,
          onOpenRequest: openRequest,
          onOpenSettings: () => navigate(AccessDestination.settings),
        ),
        detail: RequestDetailPane(
          controller: controller,
          touchId: touchId,
          approvalPassword: approvalPassword, // secrets-ignore: UI controller
          notificationRequest: notificationRequest,
          openedRequest: detailOpen ? openedRequest : '',
          session: reviewSession,
          now: now(),
          onApprove: approve,
          onDeny: deny,
          onBack: backToRequests,
          onStep: setReviewStep,
          onReload: reloadReview,
          onActivity: () => navigate(AccessDestination.activity),
          revealOnOpen:
              AccessMetrics.of(context).masterWidth(context, width) == null,
        ),
      ),
      AccessDestination.devices => ProviderDevices(
        controller: controller,
        password: managementPassword, // secrets-ignore: UI controller
        enrollment: enrollment,
        enrollmentPassword: enrollmentPassword, // secrets-ignore: UI controller
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
      AccessDestination.settings => ProviderSettings(
        controller: controller,
        notifier: notifier,
        touchId: touchId,
        installation: widget.installation,
        installationControls: !mobile,
        pilotOffered:
            disposablePilotEnabled && widget.platform is PilotProviderPlatform,
        appearance: appearance,
        onAppearance: (value) => setState(() => appearance = value),
        dedicated: dedicated,
        onDedicated: (value) => setState(() => dedicated = value),
        endpoint: endpoint,
        pin: pin,
        importPassword: importPassword, // secrets-ignore: UI controller
        pilotBundle: pilotBundle,
        touchIdPassword: touchIdPassword, // secrets-ignore: UI controller
        onSetupPilot: setupPilot,
        onSetup: setupProvider,
        onOpenSynthetic: () => unawaited(openSynthetic()),
      ),
    };
  }

  @override
  Widget build(BuildContext context) => Theme(
    data: accessTheme(resolvedBrightness),
    child: AccessShell(
      destination: destination,
      onDestination: navigate,
      detailOpen: detailOpen,
      onBack: backToRequests,
      pendingCount: controller.state.requests.length,
      status: shellStatus,
      body: LayoutBuilder(
        builder: (context, constraints) {
          final m = AccessMetrics.of(context);
          final side = constraints.maxWidth >= 600 ? m.space[5] : m.space[3];
          final width = constraints.maxWidth - 2 * side;
          final page = content(context, width);
          return SingleChildScrollView(
            controller: contentScroll,
            key: ValueKey(destination),
            padding: EdgeInsets.symmetric(horizontal: side, vertical: 24),
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
                ProviderStatusArea(controller: controller),
                if (destination == AccessDestination.requests)
                  page
                else
                  ConstrainedBox(
                    constraints: BoxConstraints(maxWidth: m.workpageMaxWidth),
                    child: page,
                  ),
              ],
            ),
          );
        },
      ),
    ),
  );
}
