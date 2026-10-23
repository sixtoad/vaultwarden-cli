import 'dart:convert';

/// Only the separately built disposable pilot may admit this credential bundle.
const disposablePilotEnabled = bool.fromEnvironment(
  'COMPANION_DISPOSABLE_PILOT',
);

class PilotBundle {
  PilotBundle._(this._values);
  static const maximumLength = 1600000;
  final Map<String, dynamic> _values;
  String get endpoint => _values['endpoint'] as String;
  String get pin => _values['leaf_sha256'] as String;
  String get fingerprint => _values['client_sha256'] as String;
  String get unlockPassword => _values['unlock_password'] as String;

  Map<String, Object> get nativeArguments => {
    for (final entry in _values.entries)
      if (entry.key != 'unlock_password') entry.key: entry.value as Object,
  };

  static PilotBundle parse(String input) {
    // Collapse all parse errors: FormatException from JSON/base64 can retain
    // the offending secret as its source or include it in the error text.
    try {
      if (input.length > maximumLength ||
          utf8.encode(input).length > maximumLength) {
        throw const FormatException();
      }
      final value = jsonDecode(input);
      const fields = {
        'version',
        'kind',
        'endpoint',
        'leaf_sha256',
        'client_sha256',
        'ca_der',
        'pkcs12',
        'import_passphrase',
        'unlock_password',
      };
      if (value is! Map<String, dynamic> ||
          value.length != fields.length ||
          !value.keys.every(fields.contains) ||
          value['version'] is! int ||
          value['version'] != 1 ||
          value['kind'] != 'disposable-companion-pilot' ||
          !fields
              .where((key) => key != 'version')
              .every((key) => value[key] is String)) {
        throw const FormatException();
      }
      final endpoint = value['endpoint'] as String;
      final url = Uri.parse(endpoint);
      if (endpoint.length > 2048 ||
          url.scheme != 'https' ||
          !url.hasAuthority ||
          url.host.isEmpty ||
          url.userInfo.isNotEmpty ||
          url.hasQuery ||
          url.hasFragment ||
          !['', '/', '/v1/companion'].contains(url.path) ||
          url.port <= 0 ||
          url.port > 65535 ||
          RegExp(r'[\s\\]').hasMatch(endpoint)) {
        throw const FormatException();
      }
      for (final key in ['leaf_sha256', 'client_sha256']) {
        if (!RegExp(r'^[a-f0-9]{64}$').hasMatch(value[key] as String)) {
          throw const FormatException();
        }
      }
      for (final key in ['import_passphrase', 'unlock_password']) {
        final secret = value[key] as String;
        if (secret.isEmpty || utf8.encode(secret).length > 4096) {
          throw const FormatException();
        }
      }
      for (final entry in {'ca_der': 65536, 'pkcs12': 1048576}.entries) {
        final encoded = value[entry.key] as String;
        final bytes = base64Decode(encoded);
        try {
          if (bytes.isEmpty ||
              bytes.length > entry.value ||
              base64Encode(bytes) != encoded) {
            throw const FormatException();
          }
        } finally {
          bytes.fillRange(0, bytes.length, 0);
        }
      }
      // Normalize to the same route saved by the existing native validator.
      value['endpoint'] = url.replace(path: '/v1/companion').toString();
      return PilotBundle._(value);
    } catch (_) {
      throw const FormatException('Invalid disposable pilot bundle');
    }
  }
}
