import 'dart:convert';

import 'package:companion_slice/src/rust/api/provider.dart' as provider;

/// Runs through generated FFI in both debug and AOT bundles. This is a bounded
/// protocol fixture; it does not count as real provider or packaged TLS evidence.
void checkProviderBridge(void Function(bool, String) require) {
  const id = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  provider.providerConfigure(uncertainId: '');
  void respond(
    provider.ProviderCommand command,
    Map<String, Object?> response, {
    String requestId = '',
  }) {
    final work = provider.providerBegin(
      command: command,
      requestId: requestId,
      password: '',
    );
    provider.providerFinish(
      token: work.token,
      response: utf8.encode(jsonEncode(response)),
    );
  }

  respond(provider.ProviderCommand.session, {
    'version': 1,
    'state': 'unlocked',
    'generation': 1,
  });
  respond(provider.ProviderCommand.review, {
    'version': 1,
    'generation': 1,
    'ticket': 'd' * 64,
    'review': {
      'id': id,
      'requester': 'fixture',
      'operation': 'deploy',
      'effect': 'Synthetic fixture only',
      'target': 'staging',
      'arguments': ['', ' a b ', '\u202e'],
      'credentials': <Object>[],
      'executable_digest': 'a' * 64,
      'policy_digest': 'b' * 64,
      'arguments_digest': 'c' * 64,
      'expires_at_unix_seconds': 2000000000,
      'one_time': 'once',
      'status': {'status': 'pending'},
    },
  }, requestId: id);
  require(provider.providerSnapshot().canDecide, 'provider review bridge');
  require(
    provider.providerSnapshot().reviewText.contains(r'\u{202e}'),
    'escaped provider review',
  );
  final review = provider.providerSnapshot().review;
  require(
    review != null &&
        review.id == '"$id"' &&
        review.arguments.length == 3 &&
        review.arguments[0] == '""' &&
        review.arguments[1] == '" a b "' &&
        review.arguments[2] == r'"\u{202e}"' &&
        review.expiresAtUnixSeconds.toString() == '2000000000',
    'typed escaped provider review',
  );
  final decision = provider.providerBegin(
    command: provider.ProviderCommand.deny,
    requestId: id,
    password: '',
  );
  require(
    !jsonDecode(utf8.decode(decision.body)).containsKey('password'),
    'passwordless denial',
  );
  provider.providerInvalidate();
  require(
    provider.providerSnapshot().review == null,
    'typed review retirement',
  );
  provider.providerFinish(token: decision.token, response: []);
  require(
    provider.providerSnapshot().uncertainId == id,
    'original request uncertainty',
  );
  respond(provider.ProviderCommand.status, {
    'version': 1,
    'status': {'status': 'pending'},
  }, requestId: id);
  require(
    provider.providerSnapshot().uncertainId == id,
    'pending remains uncertain',
  );
  respond(provider.ProviderCommand.status, {
    'version': 1,
    'status': {'status': 'denied'},
  }, requestId: id);
  require(
    provider.providerSnapshot().uncertainId.isEmpty,
    'authoritative recovery',
  );
  provider.providerConfigure(uncertainId: '');
}
