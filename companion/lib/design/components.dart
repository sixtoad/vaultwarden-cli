import 'package:flutter/material.dart';

import 'access_theme.dart';

class AccessHeading extends StatelessWidget {
  const AccessHeading(this.title, this.description, {super.key});
  final String title, description;
  @override
  Widget build(BuildContext context) => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Semantics(
        header: true,
        child: Text(title, style: Theme.of(context).textTheme.headlineMedium),
      ),
      const SizedBox(height: 8),
      Text(
        description,
        style: TextStyle(color: AccessTheme.of(context).secondary),
      ),
      const SizedBox(height: 24),
    ],
  );
}

class AccessPanel extends StatelessWidget {
  const AccessPanel({super.key, required this.child});
  final Widget child;
  @override
  Widget build(BuildContext context) => Material(
    color: AccessTheme.of(context).surface,
    shape: RoundedRectangleBorder(
      borderRadius: BorderRadius.circular(7),
      side: BorderSide(color: AccessTheme.of(context).divider),
    ),
    child: SizedBox(
      width: double.infinity,
      child: Padding(padding: const EdgeInsets.all(24), child: child),
    ),
  );
}

class StatusLabel extends StatelessWidget {
  const StatusLabel(this.label, {super.key, this.icon = Icons.info_outline});
  final String label;
  final IconData icon;
  @override
  Widget build(BuildContext context) => Row(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Icon(icon, size: 20),
      const SizedBox(width: 8),
      Expanded(child: Text(label)),
    ],
  );
}

class FactRow extends StatelessWidget {
  const FactRow(this.label, this.value, {super.key});
  final String label, value;
  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(bottom: 16),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label, style: TextStyle(color: AccessTheme.of(context).secondary)),
        SelectableText(value),
      ],
    ),
  );
}

class AccessActions extends StatelessWidget {
  const AccessActions({super.key, required this.children});
  final List<Widget> children;
  @override
  Widget build(BuildContext context) =>
      Wrap(spacing: 12, runSpacing: 12, children: children);
}

Widget accessPassword(TextEditingController controller, String label) => Column(
  crossAxisAlignment: CrossAxisAlignment.start,
  children: [
    ExcludeSemantics(child: Text(label)),
    const SizedBox(height: 8),
    Semantics(
      label: label,
      child: TextField(
        key: ValueKey(label),
        controller: controller,
        obscureText: true,
        enableSuggestions: false,
        autocorrect: false,
        enableIMEPersonalizedLearning: false,
        decoration: const InputDecoration(),
      ),
    ),
  ],
);
