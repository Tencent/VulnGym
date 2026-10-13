# Trace structure cleanup report

## Config

- mode: `fix`
- input: `data/entries.jsonl`
- output: `data/entries.trace_fixed.jsonl`
- fix_verify: `0`
- order_policy: `entry-before-only`
- duplicate_policy: `safe`
- log_cross_file: `False`

## Totals

- entries scanned: 408
- trace nodes scanned: 2073
- changed entries: 2
- log events: 402
- manual-review entries: 37
- input schema errors: 0
- output schema errors: 0

## Issue Counts

- duplicate_node: 7
- order_after_critical: 217
- order_after_critical_overlap: 32
- order_before_entry: 139
- order_before_entry_overlap: 7

## Action Counts

- manual_review: 41
- removed: 2
- skipped_not_fix_target: 359

## Changed Entries

- entry-00103
- entry-00320

## Manual Review Entries

- entry-00058
- entry-00062
- entry-00081
- entry-00103
- entry-00104
- entry-00105
- entry-00106
- entry-00129
- entry-00140
- entry-00145
- entry-00176
- entry-00185
- entry-00186
- entry-00195
- entry-00212
- entry-00258
- entry-00303
- entry-00317
- entry-00351
- entry-00391
- entry-00394
- entry-00400
- entry-00401
- entry-00417
- entry-00429
- entry-00438
- entry-00440
- entry-00443
- entry-00448
- entry-00449
- entry-00450
- entry-00451
- entry-00464
- entry-00491
- entry-00496
- entry-00509
- entry-00511
