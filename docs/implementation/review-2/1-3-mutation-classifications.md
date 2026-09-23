# Story 1.3 mutation classifications — iteration 2

Final inventory: 254; 221 CaughtMutant, 28 Unviable, 5 MissedMutant.

Every changed production function was tested after independent review. No iteration-1 outcome is reused and no current mutation is unmapped. See [per-mutation results](1-3-mutation-results.json).

## Remaining survivors

- `src/adapters/loopback_ui.rs:113:39: replace match guard peer.ip().is_loopback() with true in LoopbackUi::serve` — Defense-in-depth peer guard; fixture gap. The production listener explicitly binds literal 127.0.0.1, but the suite does not inject a peer with a non-loopback source address. The guard remains intact alongside TLS, one-use launch and independent browser proof. This is not claimed equivalent or caught.
- `src/adapters/loopback_ui.rs:147:27: replace match guard e.kind() == std::io::ErrorKind::WouldBlock with true in LoopbackUi::serve` — OS accept-error fixture gap: no fault injection produces a fatal listener accept error. Replacing the WouldBlock guard with true could suppress that error and retry; production fail-closed handling remains intact. The retry branch does not authenticate or resolve data. This is not equivalent or caught.
- `src/adapters/loopback_ui.rs:284:40: replace | with ^ in identity_file` — Equivalent on the supported Linux target: O_NOFOLLOW and O_NONBLOCK have disjoint bits, so OR and XOR produce the same open flags.
- `src/adapters/loopback_ui.rs:350:9: replace <impl Write for DeadlineStream>::flush -> std::io::Result<()> with Ok(())` — Equivalent for the concrete unbuffered TcpStream: its Write::flush already returns Ok(()). TLS buffering/flush remains in rustls; this wrapper adds no buffering. Rust primary source: https://doc.rust-lang.org/src/std/net/tcp.rs.html#713-716
- `src/adapters/session.rs:84:40: replace | with ^ in load_setup` — Equivalent on the supported Linux target: O_NOFOLLOW and O_NONBLOCK have disjoint bits, so OR and XOR produce the same open flags.

Unviable means a compiler rejection, not a caught behavioral mutation. Each diagnostic and full log path is recorded in the JSON inventory.

## Fixed misses and timeouts

Run 5 missed six mutations: the four UI survivors above remain classified; reversed worker reaping (`<` to `>`) is caught by 24 sequential connections, and weakening the TLS regular-file/owner predicate (`||` to `&&`) is caught by an owned FIFO containing a valid certificate. The analogous setup-file predicate is also caught with a complete valid configuration in an owned FIFO.

Run 6 resolves all nine run-5 timeouts (eight caught and one compiler rejection), plus the three regression targets above. Run 7 exposes a setup-file open-flag mutation that blocks on a FIFO. The two FIFO tests now require rejection within two seconds; run 8 catches both setup and TLS open-flag AND mutations without timeout. Production was unchanged throughout these test improvements.

The flush equivalence is supported by the [Rust TcpStream Write implementation](https://doc.rust-lang.org/src/std/net/tcp.rs.html#713-716).

## Earlier iteration

The first review exposed missing requirements despite passing checks; its test evidence is historical. All 37 original survivors retain individual dispositions in [iteration 1 classifications](review-1/1-3-mutation-classifications.md), and review findings are recorded in [review results](1-3-review-results.md).
