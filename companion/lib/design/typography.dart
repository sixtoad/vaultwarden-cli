import 'package:flutter/material.dart';

/// The Quiet Instrument styles that have no Material [TextTheme] slot.
@immutable
class AccessType extends ThemeExtension<AccessType> {
  const AccessType({
    required this.kicker,
    required this.mono,
    required this.factMono,
    required this.code,
    required this.brand,
  });

  /// 10 px uppercase list and section label (callers pass uppercase text).
  final TextStyle kicker;

  /// 12 px monospace for request IDs, targets and digests.
  final TextStyle mono;

  /// 11 px monospace for values inside fact rows (#50 §1.2: "fact 11").
  final TextStyle factMono;

  /// 28 px monospace verification code, widely tracked.
  final TextStyle code;

  /// The "v·" brand mark.
  final TextStyle brand;

  /// Platform monospace faces; the first installed one is used.
  static const monoFallback = [
    'SF Mono',
    'Menlo',
    'Consolas',
    'DejaVu Sans Mono',
    'monospace',
  ];

  factory AccessType.of(BuildContext context) =>
      Theme.of(context).extension<AccessType>() ??
      AccessType.build(
        text: Theme.of(context).colorScheme.onSurface,
        secondary: Theme.of(context).colorScheme.onSurfaceVariant,
        accent: Theme.of(context).colorScheme.primary,
      );

  factory AccessType.build({
    required Color text,
    required Color secondary,
    required Color accent,
  }) {
    const mono = TextStyle(
      fontFamily: 'monospace',
      fontFamilyFallback: monoFallback,
      fontSize: 12,
      height: 1.5,
    );
    return AccessType(
      kicker: TextStyle(
        fontSize: 10,
        height: 1.4,
        fontWeight: FontWeight.w700,
        letterSpacing: 1.5,
        color: secondary,
      ),
      mono: mono.copyWith(color: text),
      factMono: mono.copyWith(fontSize: 11, color: text),
      code: mono.copyWith(
        fontSize: 28,
        height: 1.3,
        letterSpacing: 5,
        color: text,
      ),
      brand: TextStyle(
        fontSize: 29,
        height: 1,
        fontWeight: FontWeight.w600,
        letterSpacing: -3,
        color: accent,
      ),
    );
  }

  @override
  AccessType copyWith({
    TextStyle? kicker,
    TextStyle? mono,
    TextStyle? factMono,
    TextStyle? code,
    TextStyle? brand,
  }) => AccessType(
    kicker: kicker ?? this.kicker,
    mono: mono ?? this.mono,
    factMono: factMono ?? this.factMono,
    code: code ?? this.code,
    brand: brand ?? this.brand,
  );

  @override
  AccessType lerp(AccessType? other, double t) => other == null
      ? this
      : AccessType(
          kicker: TextStyle.lerp(kicker, other.kicker, t)!,
          mono: TextStyle.lerp(mono, other.mono, t)!,
          factMono: TextStyle.lerp(factMono, other.factMono, t)!,
          code: TextStyle.lerp(code, other.code, t)!,
          brand: TextStyle.lerp(brand, other.brand, t)!,
        );
}
