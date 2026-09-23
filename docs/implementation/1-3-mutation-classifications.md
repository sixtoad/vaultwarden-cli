# Story 1.3 mutation classifications — iteration 3

Complete inventory: 289; 251 CaughtMutant, 33 Unviable, 5 MissedMutant.

Scope includes entire edited production function bodies plus changed constants. Each current mutation maps to a completed run; retained results require a byte-identical function body and stable mutation identity. The full integration suite and browser checks were rerun on this implementation.

## Remaining survivors

- `src/adapters/loopback_ui.rs:129:39: replace match guard peer.ip().is_loopback() with true in LoopbackUi::serve` — Defense-in-depth peer guard; fixture gap. The production listener explicitly binds literal 127.0.0.1, but the suite does not inject a peer with a non-loopback source address. The guard remains intact alongside TLS, one-use launch and independent browser proof. This is not claimed equivalent or caught.
- `src/adapters/loopback_ui.rs:163:27: replace match guard e.kind() == std::io::ErrorKind::WouldBlock with true in LoopbackUi::serve` — OS accept-error fixture gap: no fault injection produces a fatal listener accept error. Replacing the WouldBlock guard with true could suppress that error and retry; production fail-closed handling remains intact. The retry branch does not authenticate or resolve data. This is not equivalent or caught.
- `src/adapters/loopback_ui.rs:295:40: replace | with ^ in identity_file` — Equivalent on the supported Linux target: O_NOFOLLOW and O_NONBLOCK have disjoint bits, so OR and XOR produce the same open flags.
- `src/adapters/loopback_ui.rs:361:9: replace <impl Write for DeadlineStream>::flush -> std::io::Result<()> with Ok(())` — Equivalent for the concrete unbuffered TcpStream: its Write::flush already returns Ok(()). TLS buffering/flush remains in rustls; this wrapper adds no buffering. Rust primary source: https://doc.rust-lang.org/src/std/net/tcp.rs.html#713-716
- `src/adapters/session.rs:118:40: replace | with ^ in load_setup` — Equivalent on the supported Linux target: O_NOFOLLOW and O_NONBLOCK have disjoint bits, so OR and XOR produce the same open flags.

Compiler rejections are not counted as behavioral catches. Each diagnostic, test log, mutation diff and outcome is mapped in [per-mutation results](1-3-mutation-results.json).

Earlier individually classified outcomes and test improvements are preserved in [iteration 2](review-2/1-3-mutation-classifications.md) and [iteration 1](review-1/1-3-mutation-classifications.md). Review-triggered corrections are recorded in [review results](1-3-review-results.md).


## Fixed iteration-3 survivor

Run 9 tested 113 mutations: 102 caught, ten compiler rejections and one survivor.
The item-key `||` to `&&` format-guard mutation survived because the invalid-key
fixture's fields used the parent key; a later field MAC failure masked successful
unauthenticated item-key unwrapping. Added missing-MAC and extra-component cases
whose fields are valid under the actual item key, including the isolated legacy
MAC-override test. Production code was unchanged. Run 10 caught the mutation.
The full 617-test suite passed again after this test-only correction.
