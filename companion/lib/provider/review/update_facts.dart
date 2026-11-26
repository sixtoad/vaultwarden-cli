import 'package:flutter/material.dart';

import '../../design/facts.dart';
import '../../src/rust/api/provider.dart' as core;

/// Issue 48 phase 2: the existing vault item a protected update replaces
/// fields of, its binding and the revision the provider read. Never a value:
/// the producer has not run yet. Every value is Rust's escaped projection,
/// shown verbatim under a stable key. Approving this review from the
/// companion asserts the `update-review.v1` capability (Rust core).
class UpdateFacts extends StatelessWidget {
  const UpdateFacts({super.key, required this.update});
  final core.ProviderReviewUpdate update;

  @override
  Widget build(BuildContext context) {
    final fields = update.fields;
    return Column(
      key: const Key('review-update'),
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        FactRow(
          'Vault update',
          'Replaces fields of an existing item; creates nothing',
          sub:
              'A replaced password or hidden value is kept in password history',
          key: const Key('review-update-effect'),
        ),
        FactRow(
          'Item ID',
          update.itemId,
          mono: true,
          key: const Key('review-update-item'),
        ),
        FactRow(
          'Vault account',
          update.accountId,
          mono: true,
          sub: 'on ${update.server}',
          key: const Key('review-update-account'),
        ),
        FactRow(
          'Folder',
          update.folder,
          mono: true,
          sub: 'Folder ID ${update.folderId}',
          key: const Key('review-update-folder'),
        ),
        FactRow(
          'Reference',
          update.reference,
          mono: true,
          key: const Key('review-update-reference'),
        ),
        FactGroup(
          'Fields replaced (${fields.length})',
          key: const Key('review-update-fields'),
          children: [
            for (var i = 0; i < fields.length; i++)
              Padding(
                padding: EdgeInsets.only(top: i == 0 ? 0 : 4),
                child: SelectableText(
                  fields[i],
                  key: Key('review-update-field-$i'),
                ),
              ),
          ],
        ),
        FactRow(
          'Expected revision',
          update.expectedRevision,
          mono: true,
          sub: 'Any change to the item after this review cancels the update',
          key: const Key('review-update-revision'),
        ),
      ],
    );
  }
}
