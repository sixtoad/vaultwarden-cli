import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:companion_slice/platform/provider.dart';
import 'package:companion_slice/src/rust/api/provider.dart' as core;

const providerId = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
Uint8List encoded(Object value) =>
    Uint8List.fromList(utf8.encode(jsonEncode(value)));
Map<String, dynamic> providerReview() => jsonDecode(
  File('../tests/fixtures/companion/review.json').readAsStringSync(),
) as Map<String, dynamic>;

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
  Completer<Uint8List>? heldReview, heldDecision;
  bool loseDecision = false, wrongPassword = false;
  String status = 'pending';
  void Function()? invalidate;
  @override
  Future<ProviderConfiguration> configuration() async => ProviderConfiguration(
    configured: true,
    endpoint: 'https://fixture.example/v1/companion',
    pin: 'a' * 64,
    fingerprint: 'b' * 64,
  );
  @override
  Future<ProviderConfiguration> setup(
    String endpoint,
    String pin,
    String passphrase,
  ) => configuration();
  @override
  Future<Uint8List> send(Uint8List body) async {
    final command = jsonDecode(utf8.decode(body)) as Map<String, dynamic>;
    // Fixtures use synthetic strings only; production adapter never records bodies.
    commands.add(command);
    switch (command['command']) {
      case 'session':
      case 'unlock':
        return encoded({'version': 1, 'state': 'unlocked', 'generation': 1});
      case 'list':
        return encoded({
          'version': 1,
          'requests': [providerId],
        });
      case 'review':
        return heldReview == null
            ? encoded(providerReview())
            : heldReview!.future;
      case 'decision':
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
          'status': {'status': status},
        });
      default:
        throw StateError('Unexpected command');
    }
  }

  @override
  Future<void> settle(String id) async {
    settled.add(id);
  }

  @override
  void Function() onInvalidation(void Function() callback) {
    invalidate = callback;
    return () => invalidate = null;
  }
}
