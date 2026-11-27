import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

/// A software P-256 ECDSA key for the Dart tests only. The Rust core now
/// verifies every approval signature with the signer's public key before it
/// sends a proof (docs/implementation/shared-approval-checks-spec.md S-3), so
/// a fake signer must really sign the transcript it is given. Plain affine
/// arithmetic with BigInt: slow, not constant time, never used outside tests.
/// The Rust verifier is its oracle (a wrong signature is refused).
class TestP256Key {
  TestP256Key(this._d) : publicKey = _encode(_mul(_d, _g)!);

  final BigInt _d;

  /// The 65-byte uncompressed SEC1 point (0x04 || X || Y).
  final Uint8List publicKey;

  /// Lowercase hex SHA-256 of [publicKey]: the provider's key id.
  String get keyId => sha256.convert(publicKey).bytes.map(_hex2).join();

  /// ASN.1 DER ECDSA P-256 SHA-256 over [message] (randomized nonce).
  Uint8List sign(List<int> message) {
    final z = _int(sha256.convert(message).bytes);
    final random = Random.secure();
    while (true) {
      final k = _int(List.generate(32, (_) => random.nextInt(256))) % _n;
      if (k == BigInt.zero) continue;
      final r = _mul(k, _g)!.x % _n;
      final s = (k.modInverse(_n) * (z + r * _d)) % _n;
      if (r == BigInt.zero || s == BigInt.zero) continue;
      final body = [..._derInt(r), ..._derInt(s)];
      return Uint8List.fromList([0x30, body.length, ...body]);
    }
  }
}

BigInt _h(String hex) => BigInt.parse(hex, radix: 16);
final _p = _h(
  'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
);
final _n = _h(
  'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
);
final _g = (
  x: _h('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'),
  y: _h('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5'),
);

typedef _Point = ({BigInt x, BigInt y});

String _hex2(int b) => b.toRadixString(16).padLeft(2, '0');
BigInt _int(List<int> bytes) =>
    bytes.fold(BigInt.zero, (v, b) => (v << 8) | BigInt.from(b));

/// Affine addition; `null` is the point at infinity. `%` is Euclidean.
_Point? _add(_Point? a, _Point? b) {
  if (a == null) return b;
  if (b == null) return a;
  final BigInt slope;
  if (a.x == b.x) {
    if ((a.y + b.y) % _p == BigInt.zero) return null;
    slope =
        (BigInt.from(3) * a.x * a.x - BigInt.from(3)) *
        (BigInt.two * a.y).modInverse(_p) %
        _p;
  } else {
    slope = (b.y - a.y) * ((b.x - a.x) % _p).modInverse(_p) % _p;
  }
  final x = (slope * slope - a.x - b.x) % _p;
  return (x: x, y: (slope * (a.x - x) - a.y) % _p);
}

_Point? _mul(BigInt k, _Point point) {
  _Point? result;
  _Point? addend = point;
  for (var bits = k; bits > BigInt.zero; bits >>= 1) {
    if (bits.isOdd) result = _add(result, addend);
    addend = _add(addend, addend);
  }
  return result;
}

List<int> _fixed(BigInt value) => List.generate(
  32,
  (i) => ((value >> (8 * (31 - i))) & BigInt.from(255)).toInt(),
);

Uint8List _encode(_Point point) =>
    Uint8List.fromList([4, ..._fixed(point.x), ..._fixed(point.y)]);

/// A minimal positive DER INTEGER.
List<int> _derInt(BigInt value) {
  var bytes = _fixed(value);
  while (bytes.length > 1 && bytes.first == 0 && bytes[1] < 0x80) {
    bytes = bytes.sublist(1);
  }
  if (bytes.first >= 0x80) bytes = [0, ...bytes];
  return [0x02, bytes.length, ...bytes];
}
