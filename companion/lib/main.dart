import 'dart:async';

import 'package:flutter/material.dart';

import 'platform/signer.dart';
import 'platform/core_loader.dart';
import 'src/rust/api.dart' as core;

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  try {
    await initializePackagedCore();
    runApp(CompanionApp(platform: NativeApprovalPlatform()));
  } catch (_) {
    runApp(
      const MaterialApp(
        home: Scaffold(
          body: Center(
            child: Text(
              'Companion core could not load. Signing is unavailable.',
            ),
          ),
        ),
      ),
    );
  }
}

class CompanionApp extends StatelessWidget {
  const CompanionApp({super.key, required this.platform});
  final ApprovalPlatform platform;
  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'Companion Slice',
    theme: ThemeData(
      colorSchemeSeed: const Color(0xff315b65),
      useMaterial3: true,
    ),
    home: CompanionReview(platform: platform),
  );
}

class CompanionReview extends StatefulWidget {
  const CompanionReview({super.key, required this.platform});
  final ApprovalPlatform platform;
  @override
  State<CompanionReview> createState() => _CompanionReviewState();
}

class _CompanionReviewState extends State<CompanionReview>
    with WidgetsBindingObserver {
  late core.Snapshot state;
  AuthenticationAvailability availability =
      AuthenticationAvailability.unavailable;
  core.Work? active;
  bool cancelling = false;
  core.Work? lastCompleted;
  core.Outcome? lastOutcome;
  ApprovalPlatform? activePlatform;
  VoidCallback? unsubscribe;
  int platformGeneration = 0;
  int availabilityRequest = 0;
  bool disposed = false;
  Timer? timer;
  String? error;

  @override
  void initState() {
    super.initState();
    state = core.snapshot();
    WidgetsBinding.instance.addObserver(this);
    connectPlatform();
    timer = Timer.periodic(const Duration(milliseconds: 250), (_) {
      if (mounted) setState(() => state = core.snapshot());
    });
  }

  void connectPlatform() {
    final generation = ++platformGeneration;
    unsubscribe = widget.platform.onInvalidation((reason) {
      if (!disposed && mounted && generation == platformGeneration) {
        invalidate(reason);
      }
    });
    unawaited(refreshAvailability());
  }

  Future<void> refreshAvailability() async {
    final request = ++availabilityRequest;
    final generation = platformGeneration;
    final value = await widget.platform.availability();
    if (!disposed &&
        mounted &&
        generation == platformGeneration &&
        request == availabilityRequest) {
      setState(() => availability = value);
    }
  }

  @override
  void didUpdateWidget(covariant CompanionReview oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (!identical(oldWidget.platform, widget.platform)) {
      unsubscribe?.call();
      invalidate(core.Invalidation.close);
      availability = AuthenticationAvailability.unavailable;
      connectPlatform();
    }
  }

  void invalidate(core.Invalidation reason) {
    if (disposed || !mounted) return;
    final next = core.invalidate(reason: reason);
    final work = active;
    if (work != null) {
      cancelling = true;
      unawaited(activePlatform!.cancel(work.token));
    }
    if (mounted) setState(() => state = next);
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState value) {
    if (value == AppLifecycleState.resumed) unawaited(refreshAvailability());
    // Inactive includes the system Touch ID sheet on macOS. Cancelling there
    // would cancel every valid touch. Hidden/paused/detached retire the review.
    if ([
      AppLifecycleState.hidden,
      AppLifecycleState.paused,
      AppLifecycleState.detached,
    ].contains(value)) {
      invalidate(core.Invalidation.close);
    }
  }

  void review(int id) {
    invalidate(core.Invalidation.selection);
    setState(() {
      state = core.selectFixture(id: id);
      error = null;
    });
  }

  Future<void> perform(core.Operation operation) async {
    core.Work work;
    try {
      work = core.begin(operation: operation);
    } catch (_) {
      setState(() => error = 'A fresh review and an idle signer are required.');
      return;
    }
    active = work;
    cancelling = false;
    final platform = widget.platform;
    activePlatform = platform;
    setState(() {
      state = core.snapshot();
      error = null;
    });
    final completion = await platform.perform(work);
    final next = core.finish(
      token: work.token,
      epoch: work.epoch,
      completion: completion,
    );
    active = null;
    activePlatform = null;
    if (mounted) {
      setState(() {
        state = next;
        lastCompleted = work;
        lastOutcome = next.outcome;
        cancelling = false;
      });
    }
  }

  String operationLabel(core.Work work) =>
      work.operation == core.Operation.sign ||
          work.operation == core.Operation.noInteraction
      ? 'Request ${work.fixture}'
      : 'Test key (${work.operation.name})';

  String get resultLabel {
    final work = active;
    if (work != null) {
      return cancelling
          ? 'Cancelling ${operationLabel(work).toLowerCase()}…'
          : '${operationLabel(work)}: in progress';
    }
    final completed = lastCompleted;
    if (completed != null) {
      return 'Last attempt — ${operationLabel(completed)}: ${lastOutcome!.name}';
    }
    return 'Result: ${state.outcome.name}';
  }

  @override
  void dispose() {
    disposed = true;
    platformGeneration++;
    availabilityRequest++;
    unsubscribe?.call();
    core.invalidate(reason: core.Invalidation.close);
    final work = active;
    if (work != null) unawaited(activePlatform!.cancel(work.token));
    timer?.cancel();
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final available = availability == AuthenticationAvailability.touchId;
    return Scaffold(
      appBar: AppBar(title: const Text('Companion · synthetic slice')),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 760),
          child: ListView(
            padding: const EdgeInsets.all(28),
            children: [
              const Text('Rust core connected', key: Key('core-connected')),
              const SizedBox(height: 12),
              const Text(
                'Local demonstration only. No vault access, provider approval or execution.',
              ),
              const SizedBox(height: 20),
              Text(
                available
                    ? 'Touch ID available'
                    : 'Biometric signing unavailable on this device',
                key: const Key('availability'),
              ),
              TextButton(
                onPressed: refreshAvailability,
                child: const Text('Refresh availability'),
              ),
              const SizedBox(height: 20),
              Wrap(
                spacing: 12,
                runSpacing: 12,
                children: [
                  for (final id in [1, 2])
                    OutlinedButton(
                      onPressed: () => review(id),
                      child: Text('Review request $id'),
                    ),
                ],
              ),
              const SizedBox(height: 20),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(20),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        state.fixture.title,
                        style: Theme.of(context).textTheme.headlineSmall,
                      ),
                      const SizedBox(height: 12),
                      Text(state.fixture.detail),
                      const SizedBox(height: 12),
                      const Text(
                        'Review expires after 55 seconds. Review again before each attempt.',
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 16),
              Wrap(
                spacing: 12,
                runSpacing: 12,
                children: [
                  FilledButton(
                    onPressed: available && state.canSign
                        ? () => perform(core.Operation.sign)
                        : null,
                    child: const Text('Sign with Touch ID'),
                  ),
                  OutlinedButton(
                    onPressed: available && state.canSign
                        ? () => perform(core.Operation.noInteraction)
                        : null,
                    child: const Text('Check without interaction'),
                  ),
                  OutlinedButton(
                    onPressed: state.busy
                        ? () => invalidate(core.Invalidation.cancel)
                        : null,
                    child: const Text('Cancel attempt'),
                  ),
                ],
              ),
              const SizedBox(height: 24),
              Text(resultLabel, key: const Key('outcome')),
              if (state.unsafeObserved)
                const Text(
                  'Acceptance failed: unsafe signing observed in this session. Signing is disabled; delete the test key for cleanup. Restart begins a new session, not a passing hardware result.',
                  key: Key('unsafe-warning'),
                ),
              Text('Verified synthetic signatures: ${state.verified}'),
              Text(
                'Blocked without interaction: ${state.blockedWithoutInteraction}',
              ),
              if (state.keyFingerprint.isNotEmpty)
                SelectableText(
                  'Public test-key SHA-256: ${state.keyFingerprint}',
                  key: const Key('key-fingerprint'),
                ),
              if (state.busy)
                const Text('Waiting for native worker to return…'),
              if (error != null) Text(error!),
              const Divider(height: 40),
              const Text(
                'Disposable test key · separate from the installed companion',
              ),
              Text(
                state.hasKey
                    ? 'Public key retained for this session'
                    : 'No public key retained. Create or reopen explicitly.',
              ),
              Wrap(
                spacing: 12,
                runSpacing: 12,
                children: [
                  OutlinedButton(
                    onPressed: available && !state.busy && !state.hasKey
                        ? () => perform(core.Operation.create)
                        : null,
                    child: const Text('Create test key'),
                  ),
                  OutlinedButton(
                    onPressed: !state.busy
                        ? () => perform(core.Operation.reopen)
                        : null,
                    child: const Text('Reopen test key'),
                  ),
                  OutlinedButton(
                    onPressed: !state.busy
                        ? () => perform(core.Operation.delete)
                        : null,
                    child: const Text('Delete test key'),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}
