import 'package:flutter/material.dart';

import 'metrics.dart';
import 'typography.dart';

/// Quiet Instrument semantic colors (#50 §1.1). Status is always expressed in
/// text too, never by color alone.
@immutable
class AccessTheme extends ThemeExtension<AccessTheme> {
  const AccessTheme({
    required this.surface,
    required this.text,
    required this.secondary,
    required this.divider,
    required this.accent,
    required this.soft,
    required this.back,
    required this.statusText,
    required this.error,
    required this.actionFill,
  });

  /// [soft] fills the sidebar, panels and notices; [back] is the page behind
  /// a drawn window. [statusText] is accent-colored text on [surface]: the
  /// dark accent itself is below 4.5:1. [actionFill] backs filled actions
  /// (white labels exceed 5:1 on it in both themes).
  final Color surface, text, secondary, divider, accent, soft;
  final Color back, statusText, error, actionFill;
  static const light = AccessTheme(
    surface: Color(0xffffffff),
    text: Color(0xff242d34),
    secondary: Color(0xff65717b),
    divider: Color(0xffe5e9ed),
    accent: Color(0xff305f82),
    soft: Color(0xfff4f7f9),
    back: Color(0xffedf0f2),
    statusText: Color(0xff305f82),
    error: Color(0xffb34d42),
    actionFill: Color(0xff305f82),
  );
  static const dark = AccessTheme(
    surface: Color(0xff232a30),
    text: Color(0xffe7edf1),
    secondary: Color(0xffacb8c2),
    divider: Color(0xff3c454e),
    accent: Color(0xff557fa2),
    soft: Color(0xff2a333b),
    back: Color(0xff191f24),
    statusText: Color(0xffb1cbe0),
    error: Color(0xffffb6ab),
    actionFill: Color(0xff456d8e),
  );
  static AccessTheme of(BuildContext context) =>
      Theme.of(context).extension<AccessTheme>() ??
      (Theme.of(context).brightness == Brightness.dark ? dark : light);
  @override
  AccessTheme copyWith({
    Color? surface,
    Color? text,
    Color? secondary,
    Color? divider,
    Color? accent,
    Color? soft,
    Color? back,
    Color? statusText,
    Color? error,
    Color? actionFill,
  }) => AccessTheme(
    surface: surface ?? this.surface,
    text: text ?? this.text,
    secondary: secondary ?? this.secondary,
    divider: divider ?? this.divider,
    accent: accent ?? this.accent,
    soft: soft ?? this.soft,
    back: back ?? this.back,
    statusText: statusText ?? this.statusText,
    error: error ?? this.error,
    actionFill: actionFill ?? this.actionFill,
  );
  @override
  AccessTheme lerp(AccessTheme? other, double t) {
    if (other == null) return this;
    Color mix(Color a, Color b) => Color.lerp(a, b, t)!;
    return AccessTheme(
      surface: mix(surface, other.surface),
      text: mix(text, other.text),
      secondary: mix(secondary, other.secondary),
      divider: mix(divider, other.divider),
      accent: mix(accent, other.accent),
      soft: mix(soft, other.soft),
      back: mix(back, other.back),
      statusText: mix(statusText, other.statusText),
      error: mix(error, other.error),
      actionFill: mix(actionFill, other.actionFill),
    );
  }
}

final _lightTheme = _buildAccessTheme(Brightness.light);
final _darkTheme = _buildAccessTheme(Brightness.dark);
ThemeData accessTheme(Brightness brightness) =>
    brightness == Brightness.dark ? _darkTheme : _lightTheme;

ThemeData _buildAccessTheme(Brightness brightness) {
  final c = brightness == Brightness.dark
      ? AccessTheme.dark
      : AccessTheme.light;
  final scheme =
      ColorScheme.fromSeed(
        seedColor: c.accent,
        brightness: brightness,
      ).copyWith(
        primary: brightness == Brightness.dark ? c.text : c.accent,
        onPrimary: brightness == Brightness.dark ? c.surface : Colors.white,
        surface: c.surface,
        onSurface: c.text,
        onSurfaceVariant: c.secondary,
        outlineVariant: c.divider,
        error: c.error,
        onError: brightness == Brightness.dark ? c.surface : Colors.white,
      );
  final base = ThemeData(
    useMaterial3: true,
    brightness: brightness,
    colorScheme: scheme,
  );
  final shape = RoundedRectangleBorder(borderRadius: BorderRadius.circular(7));
  ButtonStyle action({bool filled = false}) => ButtonStyle(
    minimumSize: const WidgetStatePropertyAll(Size(48, 48)),
    padding: const WidgetStatePropertyAll(
      EdgeInsets.symmetric(horizontal: 16, vertical: 12),
    ),
    shape: WidgetStatePropertyAll(shape),
    // Focus ring: 3 px in the text color rather than the prototype's
    // #739cb9, whose contrast was not sufficient on both surfaces (#51).
    side: WidgetStateProperty.resolveWith(
      (states) => states.contains(WidgetState.focused)
          ? BorderSide(color: c.text, width: 3)
          : BorderSide(color: filled ? Colors.transparent : c.secondary),
    ),
  );
  return base.copyWith(
    extensions: [
      c,
      AccessMetrics.standard,
      AccessType.build(text: c.text, secondary: c.secondary, accent: c.accent),
    ],
    scaffoldBackgroundColor: c.soft,
    textTheme: _textTheme(base.textTheme, c),
    dividerColor: c.divider,
    filledButtonTheme: FilledButtonThemeData(
      style: action(filled: true).copyWith(
        backgroundColor: WidgetStateProperty.resolveWith(
          (states) =>
              states.contains(WidgetState.disabled) ? null : c.actionFill,
        ),
        foregroundColor: WidgetStateProperty.resolveWith(
          (states) =>
              states.contains(WidgetState.disabled) ? null : Colors.white,
        ),
      ),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(style: action()),
    textButtonTheme: TextButtonThemeData(
      style: action(filled: true)
          .copyWith(foregroundColor: WidgetStatePropertyAll(c.text)),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: c.surface,
      border: OutlineInputBorder(borderRadius: BorderRadius.circular(7)),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(7),
        borderSide: BorderSide(color: c.text, width: 3),
      ),
    ),
  );
}

/// The direction A type scale (#50 §1.2) on the platform sans-serif.
TextTheme _textTheme(TextTheme base, AccessTheme c) {
  TextStyle style(
    double size,
    double height, {
    FontWeight weight = FontWeight.w400,
    double? spacing,
    Color? color,
  }) => TextStyle(
    fontSize: size,
    height: height,
    fontWeight: weight,
    letterSpacing: spacing,
    color: color ?? c.text,
  );
  const semibold = FontWeight.w600;
  return base
      .copyWith(
        headlineMedium: style(28, 34 / 28, weight: semibold, spacing: -0.8),
        headlineSmall: style(25, 1.3, weight: semibold, spacing: -0.6),
        titleLarge: style(22, 1.3, weight: semibold),
        titleMedium: style(16, 1.4, weight: semibold),
        bodyLarge: style(15, 1.6),
        bodyMedium: style(15, 1.6),
        bodySmall: style(13, 1.5),
        labelLarge: style(13, 20 / 13, weight: semibold),
        labelMedium: style(12, 1.4, weight: semibold, color: c.statusText),
        labelSmall: style(11, 1.4, color: c.secondary),
      )
      .apply(fontFamily: base.bodyMedium!.fontFamily);
}
