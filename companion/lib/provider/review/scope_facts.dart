import 'package:flutter/material.dart';

import '../../design/access_theme.dart';
import '../../design/components.dart';
import '../../design/typography.dart';
import '../../src/rust/api/provider.dart' as core;

/// A selectable value under a stable key (the key names the exact fact).
Widget _value(
  BuildContext context,
  String key,
  String text, {
  bool mono = false,
}) => KeyedSubtree(
  key: Key(key),
  child: SelectableText(
    text,
    style: mono
        ? AccessType.of(context).mono
        : Theme.of(context).textTheme.bodySmall!
              .copyWith(fontWeight: FontWeight.w500),
  ),
);

Widget _sub(BuildContext context, String text) => Padding(
  padding: const EdgeInsets.only(top: 2),
  child: Text(text, style: Theme.of(context).textTheme.labelSmall),
);

/// The primary scope: operation and its separate arguments, requester and
/// origin, where it runs, the target and every credential's label and use
/// type (never a value). All values are Rust's escaped projection verbatim.
class ScopeFacts extends StatelessWidget {
  const ScopeFacts({
    super.key,
    required this.review,
    required this.endpoint,
    this.origin = '',
  });
  final core.ProviderReview review;
  final String endpoint, origin;
  @override
  Widget build(BuildContext context) {
    final c = AccessTheme.of(context);
    final arguments = review.arguments, credentials = review.credentials;
    return DecoratedBox(
      decoration: BoxDecoration(
        border: Border(top: BorderSide(color: c.divider)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          FactGroup(
            'Operation',
            children: [
              _value(context, 'review-operation', review.operation),
              _sub(context, 'Arguments (${arguments.length} separate values)'),
              for (var i = 0; i < arguments.length; i++)
                Padding(
                  padding: const EdgeInsets.only(top: 4),
                  child: _value(
                    context,
                    'review-argument-$i',
                    arguments[i],
                    mono: true,
                  ),
                ),
            ],
          ),
          FactGroup(
            'Requested by',
            children: [
              _value(context, 'review-requester', review.requester),
              _sub(
                context,
                origin.isEmpty
                    ? 'Originating device'
                    : 'Authenticated request origin',
              ),
              SelectableText(
                origin.isEmpty
                    ? 'Not supplied by provider protocol v1.'
                    : origin,
                style: Theme.of(context).textTheme.labelSmall,
              ),
            ],
          ),
          FactRow(
            'Runs on',
            endpoint,
            mono: true,
            sub: 'Protected execution provider',
          ),
          FactGroup(
            'Target',
            children: [
              _value(context, 'review-target', review.target, mono: true),
            ],
          ),
          FactGroup(
            'Credentials (${credentials.length})',
            children: [
              if (credentials.isEmpty) _sub(context, 'None requested'),
              for (var i = 0; i < credentials.length; i++)
                Padding(
                  padding: EdgeInsets.only(top: i == 0 ? 0 : 8),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      _value(
                        context,
                        'review-credential-$i-label',
                        credentials[i].label,
                      ),
                      _value(
                        context,
                        'review-credential-$i-use-type',
                        credentials[i].useType,
                        mono: true,
                      ),
                      _sub(context, 'Value never shared with the agent'),
                    ],
                  ),
                ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            'Quoted values preserve argument boundaries. Unicode and controls appear as explicit escapes.',
            style: Theme.of(context).textTheme.labelSmall,
          ),
        ],
      ),
    );
  }
}

/// Lower-emphasis, always rendered (owner decision, #50 Q1): the three
/// digests, the one-time scope, the exact deadline and the raw status.
class VerificationDetails extends StatelessWidget {
  const VerificationDetails({super.key, required this.review});
  final core.ProviderReview review;

  static String utc(BigInt seconds) {
    if (seconds > BigInt.from(8640000000000)) return 'beyond the clock range';
    final t = DateTime.fromMillisecondsSinceEpoch(
      seconds.toInt() * 1000,
      isUtc: true,
    );
    String two(int v) => v.toString().padLeft(2, '0');
    return '${t.year}-${two(t.month)}-${two(t.day)} '
        '${two(t.hour)}:${two(t.minute)}:${two(t.second)} UTC';
  }

  @override
  Widget build(BuildContext context) {
    final c = AccessTheme.of(context), text = Theme.of(context).textTheme;
    return Column(
      key: const Key('review-verification'),
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Semantics(
          header: true,
          child: Text('Verification details', style: text.titleMedium),
        ),
        const SizedBox(height: 4),
        Text(
          'Exact values the provider bound to this request.',
          style: text.labelSmall,
        ),
        const SizedBox(height: 12),
        DecoratedBox(
          decoration: BoxDecoration(
            border: Border(top: BorderSide(color: c.divider)),
          ),
          child: Column(
            children: [
              FactRow(
                'Executable SHA-256',
                review.executableDigest,
                mono: true,
                key: const Key('review-executable-digest'),
              ),
              FactRow(
                'Policy SHA-256',
                review.policyDigest,
                mono: true,
                key: const Key('review-policy-digest'),
              ),
              FactRow(
                'Arguments SHA-256',
                review.argumentsDigest,
                mono: true,
                key: const Key('review-arguments-digest'),
              ),
              FactRow(
                'One-time scope',
                review.oneTime,
                key: const Key('review-one-time'),
              ),
              FactRow(
                'Request deadline (Unix seconds)',
                review.expiresAtUnixSeconds.toString(),
                mono: true,
                sub: utc(review.expiresAtUnixSeconds),
                key: const Key('review-expiry'),
              ),
              FactRow(
                'Provider status',
                review.status,
                mono: true,
                key: const Key('review-status'),
              ),
            ],
          ),
        ),
      ],
    );
  }
}
