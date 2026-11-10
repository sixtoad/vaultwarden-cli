// Test-only provider for guided enrollment (#59 phase 2). It is an
// independent oracle of the provider's half (HKDF/HMAC-SHA256 via
// package:crypto), checked against companion/fixtures/enrollment-v1.json, so
// widget tests exercise the real Rust joiner with real proofs. Never shipped.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:companion_slice/platform/provider.dart';
import 'package:crypto/crypto.dart';

import 'provider_support.dart';

final domain = utf8.encode('vaultwarden-access/enroll/v1\x00');
const deviceFp =
    'bb00000000000000000000000000000000000000000000000000000000000002';
const providerFp =
    'aa00000000000000000000000000000000000000000000000000000000000001';

Map<String, dynamic> enrollmentVector() =>
    jsonDecode(File('fixtures/enrollment-v1.json').readAsStringSync())
        as Map<String, dynamic>;

String b64(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');
Uint8List unb64(String value) =>
    base64Url.decode(value.padRight((value.length + 3) ~/ 4 * 4, '='));
Uint8List unhex(String value) => Uint8List.fromList([
  for (var i = 0; i < value.length; i += 2)
    int.parse(value.substring(i, i + 2), radix: 16),
]);

void field(BytesBuilder out, List<int> value) {
  out.add([
    (value.length >> 24) & 255,
    (value.length >> 16) & 255,
    (value.length >> 8) & 255,
    value.length & 255,
  ]);
  out.add(value);
}

/// HKDF-SHA256 (RFC 5869) for outputs of at most one block.
List<int> hkdf(List<int> salt, List<int> ikm, List<int> info, int length) {
  final prk = Hmac(sha256, salt).convert(ikm).bytes;
  return Hmac(sha256, prk).convert([...info, 1]).bytes.sublist(0, length);
}

List<int> mac(List<int> secret, List<int> id, String purpose, List<int> m) {
  final key = hkdf(id, secret, [...domain, ...utf8.encode(purpose)], 32);
  return Hmac(sha256, key).convert(m).bytes;
}

class FixtureInvitation {
  FixtureInvitation(this.id, this.secret, this.kind);
  final List<int> id, secret;
  final Map<String, dynamic> kind;
  String get code => 'vwe1.${b64(id)}.${b64(secret)}';
  String get idText => b64(id);
  List<int>? full;
  String comparisonCode = '';
  String state = 'awaiting_join';
  bool providerApproved = false, joinerConfirmed = false;
  String detail = '';
  Map<String, dynamic> get stateJson => switch (state) {
    'awaiting_join' => {'state': 'awaiting_join'},
    'awaiting_approvals' => {
      'state': 'awaiting_approvals',
      'provider_approved': providerApproved,
      'joiner_confirmed': joinerConfirmed,
    },
    'enrolled' => {
      'state': 'enrolled',
      'identity': {'role': 'companion', 'fingerprint': deviceFp},
    },
    'cancelled' => {'state': 'cancelled', 'by': detail},
    'expired' => {'state': 'expired'},
    'aborted' => {'state': 'aborted', 'reason': detail},
    _ => {'state': 'failed', 'reason': detail},
  };
  Map<String, dynamic> view() => {
    'id': idText,
    'kind': kind,
    'state': stateJson,
    'expires_in_seconds': 540,
    if (full != null) 'joiner_fingerprint': deviceFp,
  };

  /// The provider's answer to a join, as `Book::handle` computes it; null
  /// when the join does not prove the secret.
  Map<String, dynamic>? joined(Map<String, dynamic> join, List<int> nonce) {
    final t = BytesBuilder()..add(domain);
    field(t, utf8.encode('companion-mtls'));
    field(t, id);
    field(t, unhex(deviceFp));
    field(t, unb64(join['nonce'] as String));
    field(t, unhex(providerFp));
    final joinBytes = t.toBytes();
    if (b64(mac(secret, id, 'join', joinBytes)) != join['mac']) return null;
    final f = BytesBuilder()..add(joinBytes);
    field(f, utf8.encode('companion'));
    field(f, utf8.encode(kind['label'] as String));
    field(f, nonce);
    full = f.toBytes();
    final hash = sha256.convert(full!).bytes;
    final okm = hkdf(hash, secret, [
      ...domain,
      ...utf8.encode('comparison-code'),
      ...id,
    ], 8);
    final value =
        okm.fold(BigInt.zero, (n, b) => (n << 8) | BigInt.from(b)) %
        BigInt.from(100000000);
    final digits = value.toString().padLeft(8, '0');
    comparisonCode = '${digits.substring(0, 4)}-${digits.substring(4)}';
    state = 'awaiting_approvals';
    return {
      'result': 'joined',
      'protocol_version': 1,
      'invitation_id': idText,
      'kind': kind,
      'provider_nonce': b64(nonce),
      'provider_mac': b64(mac(secret, id, 'provider', full!)),
      'expires_in_seconds': 599,
    };
  }
}

/// A provider that speaks the enrollment commands. `owner` controls whether
/// this client is an administrator; `joinReply`/`nextState` force outcomes.
class EnrollmentPlatform extends FixtureProviderPlatform {
  EnrollmentPlatform() {
    saved = const ProviderConfiguration(
      configured: true,
      endpoint: 'https://fixture.example/v1/companion',
      pin: providerFp,
      fingerprint: deviceFp,
    );
  }
  bool admin = true;
  String? joinRejection;
  Map<String, dynamic>? forcedState;
  final List<FixtureInvitation> invitations = [];
  final List<Map<String, dynamic>> enrollCommands = [];
  int _seed = 1;

  FixtureInvitation issue(Map<String, dynamic> kind) {
    final invitation = FixtureInvitation(
      List.generate(32, (i) => (i * 7 + _seed) & 255),
      List.generate(32, (i) => (i * 13 + _seed * 3) & 255),
      kind,
    );
    _seed++;
    invitations.add(invitation);
    return invitation;
  }

  FixtureInvitation? byId(Object? id) =>
      invitations.where((i) => i.idText == id).firstOrNull;

  @override
  Future<Uint8List> send(Uint8List body) async {
    final c = jsonDecode(utf8.decode(body)) as Map<String, dynamic>;
    final command = c['command'] as String;
    if (command != 'enroll' && !command.startsWith('enroll_')) {
      return super.send(body);
    }
    enrollCommands.add(c);
    if (command == 'enroll') {
      return encoded(_joiner(c['message'] as Map<String, dynamic>));
    }
    if (!admin) return encoded({'version': 1, 'error': 'unauthorized'});
    switch (command) {
      case 'enroll_invite':
        final i = issue(c['kind'] as Map<String, dynamic>);
        return encoded({
          'version': 1,
          'invitation': {
            'id': i.idText,
            'invitation_code': i.code,
            'kind': i.kind,
            'expires_in_seconds': 600,
          },
        });
      case 'enroll_list':
        return encoded({
          'version': 1,
          'enrollments': [for (final i in invitations) i.view()],
        });
      case 'enroll_approve':
        final i = byId(c['id']);
        if (i == null) return refused('not_found');
        if (i.state == 'awaiting_join') return refused('awaiting_peer');
        if (c['password'] != 'synthetic-password') {
          return encoded({'version': 1, 'error': 'authentication_failed'});
        }
        if (c['code'] != i.comparisonCode) {
          i
            ..state = 'aborted'
            ..detail = 'code_mismatch';
          return refused('code_mismatch');
        }
        i.providerApproved = true;
        return encoded({'version': 1, 'enrollment': i.view()});
      case 'enroll_cancel':
        final i = byId(c['id'])!
          ..state = 'cancelled'
          ..detail = 'provider';
        return encoded({'version': 1, 'enrollment': i.view()});
    }
    throw StateError('unknown enrollment command');
  }

  Uint8List refused(String reason) =>
      encoded({'version': 1, 'error': 'enrollment_refused', 'reason': reason});

  Map<String, dynamic> _joiner(Map<String, dynamic> m) {
    final rejected = joinRejection;
    if (m['purpose'] == 'enroll_join' && rejected != null) {
      return {'result': 'rejected', 'protocol_version': 1, 'reason': rejected};
    }
    final i = byId(m['invitation_id']);
    if (i == null) {
      return {
        'result': 'rejected',
        'protocol_version': 1,
        'reason': 'invalid_invitation',
      };
    }
    switch (m['purpose']) {
      case 'enroll_join':
        return i.joined(m, List.filled(32, 9)) ??
            {
              'result': 'rejected',
              'protocol_version': 1,
              'reason': 'invalid_invitation',
            };
      case 'enroll_confirm':
        if (i.state == 'awaiting_approvals') {
          i.joinerConfirmed = true;
          if (i.providerApproved) i.state = 'enrolled';
        }
      case 'enroll_cancel':
        if (i.state == 'awaiting_approvals') {
          final mismatch = m['reason'] == 'code_mismatch';
          i
            ..state = mismatch ? 'aborted' : 'cancelled'
            ..detail = mismatch ? 'joiner_reported_mismatch' : 'joiner';
        }
    }
    return {
      'result': 'state',
      'protocol_version': 1,
      'invitation_id': i.idText,
      'state': forcedState ?? i.stateJson,
    };
  }
}
