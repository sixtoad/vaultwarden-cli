import 'package:flutter/material.dart';

/// Quiet Instrument semantic colors. Status is always expressed in text too.
@immutable
class AccessTheme extends ThemeExtension<AccessTheme> {
  const AccessTheme({
    required this.surface,
    required this.text,
    required this.secondary,
    required this.divider,
    required this.accent,
    required this.soft,
  });
  final Color surface, text, secondary, divider, accent, soft;
  static const light = AccessTheme(
    surface: Color(0xffffffff),
    text: Color(0xff242d34),
    secondary: Color(0xff65717b),
    divider: Color(0xffe5e9ed),
    accent: Color(0xff305f82),
    soft: Color(0xfff4f7f9),
  );
  static const dark = AccessTheme(
    surface: Color(0xff232a30),
    text: Color(0xffe7edf1),
    secondary: Color(0xffacb8c2),
    divider: Color(0xff3c454e),
    accent: Color(0xff557fa2),
    soft: Color(0xff2a333b),
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
  }) => AccessTheme(
    surface: surface ?? this.surface,
    text: text ?? this.text,
    secondary: secondary ?? this.secondary,
    divider: divider ?? this.divider,
    accent: accent ?? this.accent,
    soft: soft ?? this.soft,
  );
  @override
  AccessTheme lerp(AccessTheme? other, double t) => other == null
      ? this
      : AccessTheme(
          surface: Color.lerp(surface, other.surface, t)!,
          text: Color.lerp(text, other.text, t)!,
          secondary: Color.lerp(secondary, other.secondary, t)!,
          divider: Color.lerp(divider, other.divider, t)!,
          accent: Color.lerp(accent, other.accent, t)!,
          soft: Color.lerp(soft, other.soft, t)!,
        );
}

final _lightTheme = _buildAccessTheme(Brightness.light);
final _darkTheme = _buildAccessTheme(Brightness.dark);
ThemeData accessTheme(Brightness brightness) =>
    brightness == Brightness.dark ? _darkTheme : _lightTheme;

ThemeData _buildAccessTheme(Brightness brightness) {
  final c = brightness == Brightness.dark
      ? AccessTheme.dark
      : AccessTheme.light;
  // Preserve the reference accent while using a darker action fill in dark
  // mode: white on #456d8e exceeds 5:1 for small button labels.
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
    side: WidgetStateProperty.resolveWith(
      (states) => states.contains(WidgetState.focused)
          ? BorderSide(color: c.text, width: 3)
          : BorderSide(color: filled ? Colors.transparent : c.secondary),
    ),
  );
  return base.copyWith(
    extensions: [c],
    scaffoldBackgroundColor: c.soft,
    textTheme: base.textTheme
        .copyWith(
          headlineMedium: TextStyle(
            fontSize: 28,
            height: 34 / 28,
            fontWeight: FontWeight.w600,
            color: c.text,
          ),
          titleLarge: TextStyle(
            fontSize: 20,
            height: 1.4,
            fontWeight: FontWeight.w600,
            color: c.text,
          ),
          bodyMedium: TextStyle(fontSize: 15, height: 1.6, color: c.text),
          bodyLarge: TextStyle(fontSize: 15, height: 1.6, color: c.text),
          labelLarge: TextStyle(
            fontSize: 13,
            height: 20 / 13,
            fontWeight: FontWeight.w600,
            color: c.text,
          ),
        )
        .apply(fontFamily: base.textTheme.bodyMedium!.fontFamily),
    dividerColor: c.divider,
    filledButtonTheme: FilledButtonThemeData(
      style: action(filled: true).copyWith(
        backgroundColor: WidgetStateProperty.resolveWith(
          (states) => states.contains(WidgetState.disabled)
              ? null
              : brightness == Brightness.dark
              ? const Color(0xff456d8e)
              : c.accent,
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
