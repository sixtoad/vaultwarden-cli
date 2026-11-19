import 'package:flutter_test/flutter_test.dart';
import 'package:companion_slice/app/capabilities.dart';
import 'package:companion_slice/app/shell_status.dart';

void main() {
  DeviceCapabilities derive(
    String os, {
    bool transport = true,
    bool biometric = true,
    bool notifications = true,
  }) => DeviceCapabilities.derive(
    operatingSystem: os,
    providerTransport: transport,
    biometricSigner: biometric,
    reviewNotifications: notifications,
  );

  test('requesting, approving and executing are separate per platform', () {
    // (os) -> canRequest, cliInstall. No platform executes in this app.
    const expected = {
      'macos': (true, true),
      'linux': (true, true),
      'windows': (false, true),
      'android': (false, false),
      'ios': (false, false),
    };
    for (final entry in expected.entries) {
      final caps = derive(entry.key);
      expect(caps.canRequest, entry.value.$1, reason: entry.key);
      expect(caps.cliInstall, entry.value.$2, reason: entry.key);
      expect(caps.canApprove, isTrue, reason: entry.key);
      expect(caps.canExecute, isFalse, reason: entry.key);
    }
  });

  test('approval and biometrics follow the native adapters, not the label', () {
    final noTransport = derive('macos', transport: false);
    expect(noTransport.canApprove, isFalse);
    expect(noTransport.biometric, isFalse, reason: 'no transport to sign for');
    expect(noTransport.roleText, 'This device: approval unavailable');
    expect(derive('macos', biometric: false).biometric, isFalse);
    expect(derive('macos').biometric, isTrue);
    expect(derive('macos').roleText, 'This device: approval client');
    expect(derive('linux', notifications: false).notifications, isFalse);
    expect(derive('linux').notifications, isTrue);
  });

  test('an unknown platform claims nothing', () {
    for (final os in ['fuchsia', '', 'web']) {
      expect(derive(os), DeviceCapabilities.none, reason: os);
    }
  });

  test(
    'connection precedence: unavailable, unconfigured, disconnected, lock',
    () {
      ShellConnection of(bool a, bool c, bool n, bool l) => ShellConnection.of(
        available: a,
        configured: c,
        connected: n,
        locked: l,
      );
      expect(of(false, true, true, false), ShellConnection.unavailable);
      expect(of(true, false, true, true), ShellConnection.notConfigured);
      expect(of(true, true, false, true), ShellConnection.disconnected);
      expect(of(true, true, true, true), ShellConnection.locked);
      expect(of(true, true, true, false), ShellConnection.connected);
      for (final value in ShellConnection.values) {
        expect(value.label, isNotEmpty, reason: 'status is never color alone');
      }
    },
  );

  test('the footer names only the provider host', () {
    ShellStatus status(String endpoint) => ShellStatus(
      connection: ShellConnection.connected,
      endpoint: endpoint,
      capabilities: DeviceCapabilities.none,
    );
    expect(
      status('https://user:secret@fixture.example/v1/companion?x=1').host,
      'fixture.example',
    );
    expect(
      status('https://fixture.example:8443/v1').host,
      'fixture.example:8443',
    );
    expect(status('').host, isEmpty);
    expect(status('not a url').host, isEmpty);
    expect(status('https://[::1]:8443/v1').host, '[::1]:8443');
    expect(
      status('fixture.example:8443/v1').executesText,
      'Executes: provider (endpoint unreadable)',
    );
    expect(
      status('https://user:secret@fixture.example/v1').executesText,
      isNot(contains('secret')),
    );
    expect(status('').executesText, 'Executes: no provider configured');
    expect(
      status('https://fixture.example').executesText,
      'Executes: provider at fixture.example',
    );
  });
}
