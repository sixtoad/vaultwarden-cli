import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:companion_slice/platform/signer.dart';
import 'package:companion_slice/src/rust/api.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('test-synthetic-signer');
  Work work(Operation operation) => Work(
    token: 1,
    epoch: 2,
    operation: operation,
    fixture: 1,
    expiresUnixMs: BigInt.from(1700000000000),
    nonce: Uint8List(32),
    keyId: Uint8List(32),
  );

  test(
    'unsupported platform never invokes native channel or returns proof',
    () async {
      var calls = 0;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (_) async {
            calls++;
            return null;
          });
      final platform = NativeApprovalPlatform(macOS: false, channel: channel);
      expect(
        await platform.availability(),
        AuthenticationAvailability.unavailable,
      );
      for (final operation in Operation.values) {
        final result = await platform.perform(work(operation));
        expect(result.outcome, Outcome.unavailable);
        expect(result.signature, isEmpty);
      }
      await platform.cancel(1);
      expect(calls, 0);
    },
  );

  test(
    'typed native contract sends fixed fixture fields and bounded proof',
    () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
            expect(call.method, 'perform');
            final args = call.arguments as Map;
            expect(args.keys.toSet(), {
              'token',
              'epoch',
              'operation',
              'fixture',
              'expiresUnixMs',
              'nonce',
              'keyId',
            });
            expect(args['operation'], 'sign');
            expect(args['fixture'], 1);
            return {
              'outcome': 'verified',
              'publicKey': Uint8List(0),
              'signature': Uint8List.fromList([1, 2]),
            };
          });
      final result = await NativeApprovalPlatform(
        macOS: true,
        channel: channel,
      ).perform(work(Operation.sign));
      expect(result.signature, [1, 2]);
    },
  );

  test(
    'noninteractive signature cannot be hidden by oversized output',
    () async {
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(
            channel,
            (_) async => {
              'outcome': 'verified',
              'publicKey': Uint8List(0),
              'signature': Uint8List(73),
            },
          );
      final result = await NativeApprovalPlatform(
        macOS: true,
        channel: channel,
      ).perform(work(Operation.noInteraction));
      expect(result.outcome, Outcome.unsafe);
    },
  );

  test('noninteractive proof survives malformed result metadata', () async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
          channel,
          (_) async => {
            'signature': Uint8List.fromList([1]),
          },
        );
    final result = await NativeApprovalPlatform(
      macOS: true,
      channel: channel,
    ).perform(work(Operation.noInteraction));
    expect(result.outcome, Outcome.unsafe);
  });
}
