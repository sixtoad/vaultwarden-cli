import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:companion_slice/platform/provider.dart';
import 'package:companion_slice/src/rust/api/provider.dart' as core;

const providerId = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
Uint8List encoded(Object value) =>
    Uint8List.fromList(utf8.encode(jsonEncode(value)));
Map<String, dynamic> providerReview() => jsonDecode(
  File('../tests/fixtures/companion/review.json').readAsStringSync(),
) as Map<String, dynamic>;

String reviewFact(WidgetTester tester, String key) => tester
    .widget<SelectableText>(
      find.descendant(
        of: find.byKey(Key(key)),
        matching: find.byType(SelectableText),
      ),
    )
    .data!;

void resetProvider() {
  final state = core.providerSnapshot();
  if (state.uncertainId.isNotEmpty) {
    final work = core.providerBegin(
      command: core.ProviderCommand.status,
      requestId: state.uncertainId,
      password: '',
    );
    core.providerFinish(
      token: work.token,
      response: encoded({
        'version': 1,
        'status': {'status': 'expired'},
      }),
    );
  }
  core.providerConfigure(uncertainId: '');
}

class FixtureProviderPlatform implements ProviderPlatform {
  @override
  bool available = true;
  final List<Map<String, dynamic>> commands = [];
  final List<String> settled = [];
  final List<String> settlementAttempts = [];
  Completer<Uint8List>? heldReview, heldDecision, heldSession, heldHistory;
  Uint8List? historyReply;
  Completer<ProviderConfiguration>? heldConfiguration, heldSetup;
  Completer<void>? heldSettlement;
  bool failSettlement = false, failConfiguration = false;
  bool clearThenFailSettlement = false;
  Uint8List? sessionReply;
  Map<String, dynamic>? reviewReply;
  ProviderConfiguration saved = ProviderConfiguration(
    configured: true,
    endpoint: 'https://fixture.example/v1/companion',
    pin: 'a' * 64,
    fingerprint: 'b' * 64,
  );
  bool loseDecision = false, wrongPassword = false;
  String status = 'pending';
  List<String> requestIds = [providerId];
  void Function()? invalidate;
  @override
  Future<ProviderConfiguration> configuration() async {
    if (failConfiguration) throw StateError('Synthetic metadata failure');
    return heldConfiguration == null ? saved : heldConfiguration!.future;
  }

  @override
  Future<ProviderConfiguration> setup(
    String endpoint,
    String pin,
    String passphrase,
  ) async {
    if (heldSetup != null) saved = await heldSetup!.future;
    return saved;
  }

  @override
  Future<Uint8List> send(Uint8List body) async {
    final command = jsonDecode(utf8.decode(body)) as Map<String, dynamic>;
    // Fixtures use synthetic strings only; production adapter never records bodies.
    commands.add(command);
    switch (command['command']) {
      case 'session':
        if (heldSession != null) return heldSession!.future;
        if (sessionReply != null) return sessionReply!;
        return encoded({'version': 1, 'state': 'unlocked', 'generation': 1});
      case 'unlock':
        return encoded({'version': 1, 'state': 'unlocked', 'generation': 1});
      case 'list':
        return encoded({'version': 1, 'requests': requestIds});
      case 'history':
        if (heldHistory != null) return heldHistory!.future;
        return historyReply ??
            encoded(
              providerHistory(
                outcome: status == 'denied' ? 'denied' : 'submitted',
              ),
            );
      case 'review':
        return heldReview == null
            ? encoded(reviewReply ?? providerReview())
            : heldReview!.future;
      case 'decision':
        savePending(command['request_id'] as String);
        if (heldDecision != null) return heldDecision!.future;
        if (wrongPassword) {
          return encoded({'version': 1, 'error': 'authentication_failed'});
        }
        if (loseDecision) throw StateError('Synthetic lost response');
        status = command['decision'] == 'deny' ? 'denied' : 'approved';
        return encoded({
          'version': 1,
          'status': {'status': status},
        });
      case 'status':
        return encoded({
          'version': 1,
          'status': {
            'status': status,
            if (status == 'completed') 'exit_code': 0,
          },
        });
      default:
        throw StateError('Unexpected command');
    }
  }

  @override
  Future<void> settle(String id) async {
    settlementAttempts.add(id);
    if (heldSettlement != null) await heldSettlement!.future;
    if (failSettlement) throw StateError('Synthetic settlement failure');
    if (saved.uncertainId != id) throw StateError('Synthetic marker mismatch');
    settled.add(id);
    savePending('');
    if (clearThenFailSettlement) {
      throw StateError('Synthetic permissions failure after atomic save');
    }
  }

  void savePending(String id) {
    saved = ProviderConfiguration(
      configured: saved.configured,
      endpoint: saved.endpoint,
      pin: saved.pin,
      fingerprint: saved.fingerprint,
      uncertainId: id,
    );
  }

  @override
  void Function() onInvalidation(void Function() callback) {
    invalidate = callback;
    return () => invalidate = null;
  }
}

Map<String, dynamic> providerHistory({
  String outcome = 'succeeded',
  String id = providerId,
}) => {
  'version': 1,
  'history_version': 1,
  'events': <Map<String, dynamic>>[
    {
      'request_id': id,
      'operation': 'deploy',
      'at_unix_seconds': 1700000000,
      'ordinal': 1,
      'outcome': outcome,
    },
  ],
};
