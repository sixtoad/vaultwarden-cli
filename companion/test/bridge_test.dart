import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:companion_slice/src/rust/api.dart' as core;
import 'package:companion_slice/src/rust/frb_generated.dart';

void main() {
  test(
    'real FFI library owns fixture selection, admission, and stale callbacks',
    () async {
      await RustLib.init();
      expect(core.snapshot().fixture.title, 'Synthetic request one');
      expect(core.snapshot().hasKey, false);
      core.selectFixture(id: 2);
      expect(core.snapshot().fixture.title, 'Synthetic request two');
      final work = core.begin(operation: core.Operation.reopen);
      expect(
        () => core.begin(operation: core.Operation.create),
        throwsA(anything),
      );
      core.invalidate(reason: core.Invalidation.cancel);
      expect(core.snapshot().busy, true);
      final reply = core.Completion(
        outcome: core.Outcome.unavailable,
        publicKey: Uint8List(0),
        signature: Uint8List(0),
      );
      core.finish(token: work.token + 1, epoch: work.epoch, completion: reply);
      expect(core.snapshot().busy, true);
      core.finish(token: work.token, epoch: work.epoch, completion: reply);
      expect(core.snapshot().busy, false);
      expect(core.snapshot().verified, 0);
      expect(
        () => core.begin(operation: core.Operation.sign),
        throwsA(anything),
      );
    },
  );
}
