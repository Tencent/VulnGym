# Trace structure cleanup report

## Summary

- Mode: `fix`
- Order policy: `review`
- Entries scanned: 408
- Trace nodes scanned: 2073
- Exact duplicate findings: 7
- Before-entry findings: 139
- After-critical findings: 237
- Cross-file comparisons skipped: 1658
- Automatic changes: 0
- Protected verified findings: 379
- Manual-review findings: 4
- Fingerprinted manual-review rows: 4
- Manual-review schema version: 1
- Manual-review manifest SHA-256: `d9e8f1cd72bce2179795730560fd224e47caf50109cb9f04943a8de629eb542f`
- Input SHA-256: `8a0385a987dbad8e573ad06aec1b6b05367dd783b28f3bbf1ce2464aef851bf2`
- Output SHA-256: `8a0385a987dbad8e573ad06aec1b6b05367dd783b28f3bbf1ce2464aef851bf2`

The default result intentionally makes no source-order deletion when execution
semantics are not proven. Identical hashes demonstrate that the conservative
fixed artifact preserves the canonical dataset byte-for-byte.

## Reviewed unverified findings

| Entry | Trace index | Finding | Decision |
|---|---:|---|---|
| `entry-00103` | `1` | `before_entry` | The current entry point is only the closing brace at line 615. Lines 605-614 are the semantically relevant streaming branch, so deleting them would remove evidence rather than repair the chain. |
| `entry-00185` | `2` | `after_critical` | The later return false is the path-blocking decision and remains security-relevant. The current critical anchor is a closing brace; the entry requires semantic review rather than trace deletion. |
| `entry-00320` | `2` | `before_entry` | save_file_routine is defined earlier in the same file but is called downstream at runtime. Source line order does not make this node an invalid call-chain step. |
| `entry-00511` | `4` | `after_critical` | extend is defined after findExtendedFunction but calls that helper at runtime. Removing the caller because of declaration order would invert the actual execution relationship. |

## Policy boundary

`before_entry` and `after_critical` describe source-layout findings only.
Functions and helpers can be defined before or after their callers, so source
line order must not be treated as runtime order without stronger evidence.

`--order-policy structural` is available for explicitly requested mechanical
removal, but reviewed exceptions above remain protected. Cross-file trace nodes
are never reordered or compared by line number.
