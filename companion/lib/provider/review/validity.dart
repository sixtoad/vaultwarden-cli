import 'package:flutter/material.dart';

import '../../design/access_theme.dart';

/// Reads the wall clock. Production passes `DateTime.now`; tests and goldens
/// pass a fixed or advancing clock.
typedef ReviewClock = DateTime Function();

/// How long a review ticket admits a decision after its review command began
/// (`rust/src/provider/session.rs`, 55 s).
const ticketLifetime = Duration(seconds: 55);

/// When one loaded review stops admitting a decision: the earlier of the
/// ticket lifetime from when the review command began and the request's own
/// deadline. Display only; Rust independently refuses and retires the review.
@immutable
class ReviewDeadline {
  ReviewDeadline({required this.loadedAt, required BigInt expiresAtUnixSeconds})
    : at = _earlier(
        loadedAt.add(ticketLifetime),
        _fromUnix(expiresAtUnixSeconds),
      );

  final DateTime loadedAt;
  final DateTime at;

  static DateTime _fromUnix(BigInt seconds) {
    // Beyond what DateTime holds: the ticket lifetime is always earlier.
    final max = BigInt.from(8640000000000);
    final clamped = seconds > max ? max : seconds;
    return DateTime.fromMillisecondsSinceEpoch(
      clamped.toInt() * 1000,
      isUtc: true,
    );
  }

  static DateTime _earlier(DateTime a, DateTime b) => a.isBefore(b) ? a : b;

  /// Time left at [now], never negative.
  Duration remaining(DateTime now) {
    final left = at.difference(now);
    return left.isNegative ? Duration.zero : left;
  }

  bool expiredAt(DateTime now) => remaining(now) == Duration.zero;

  /// "Valid for 54 s" / "Valid for 1 min 5 s" (rounded up to whole seconds,
  /// so the line never reads 0 while a decision is still admitted).
  static String describe(Duration left) {
    final seconds = (left.inMilliseconds + 999) ~/ 1000;
    if (seconds >= 60) {
      return 'Valid for ${seconds ~/ 60} min ${seconds % 60} s';
    }
    return 'Valid for $seconds s';
  }
}

/// The validity line under the scope: countdown and what bounds it.
class ValidityLine extends StatelessWidget {
  const ValidityLine({super.key, required this.left, required this.expired});
  final Duration left;
  final bool expired;
  @override
  Widget build(BuildContext context) {
    final c = AccessTheme.of(context);
    final style = Theme.of(context).textTheme.labelSmall!
        .copyWith(color: expired ? c.error : c.secondary);
    return Semantics(
      liveRegion: expired,
      child: SizedBox(
        width: double.infinity,
        child: Wrap(
          key: const Key('review-validity'),
          spacing: 12,
          runSpacing: 4,
          alignment: WrapAlignment.spaceBetween,
          children: [
            Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(
                  expired ? Icons.timer_off_outlined : Icons.schedule,
                  size: 14,
                  color: style.color,
                ),
                const SizedBox(width: 4),
                Flexible(
                  child: Text(
                    expired
                        ? 'Review expired. Reload it to decide.'
                        : ReviewDeadline.describe(left),
                    style: style,
                  ),
                ),
              ],
            ),
            Text(
              'Bounded by the 55 s review ticket and the request deadline',
              style: style.copyWith(color: c.secondary),
            ),
          ],
        ),
      ),
    );
  }
}
