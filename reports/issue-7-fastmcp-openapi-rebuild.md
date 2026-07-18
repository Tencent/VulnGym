# Issue #7 — FastMCP OpenAPI SSRF / path-traversal chain rebuild

## Scope and confidence boundary

This patch examines all four VulnGym entries associated with
`GHSA-VV7Q-7JX5-F767` / `CVE-2026-32871`, but changes canonical JSONL only
where the upstream security fix provides direct evidence:

- rebuilt in `data/entries.jsonl`: `entry-00391`, `entry-00394`;
- retained for manual review: `entry-00392`, `entry-00395`.

The distinction is deliberate. The fix changes
`src/fastmcp/utilities/openapi/director.py` and adds regression tests for
`RequestDirector`; it does not change
`src/fastmcp/server/providers/openapi/components.py`. The resource entries
contain visually similar unencoded substitutions, but source similarity alone
does not prove that their URI parsing and `httpx.AsyncClient` request semantics
form the advisory's exploitable path.

## Pinned evidence

- Vulnerable snapshot:
  `PrefectHQ/fastmcp@c861862aededc7294cea5634d77e6926444ca101`
- Fix commit:
  `PrefectHQ/fastmcp@40bdfb6b1de0ce30609ee9ba5bb95ecd04a9fb71`
- Advisory: `GHSA-VV7Q-7JX5-F767` / `CVE-2026-32871`

The fix commit is a direct child of the vulnerable snapshot. Its production
change replaces:

```python
url_path = url_path.replace(placeholder, str(param_value))
```

with URL encoding through `quote(..., safe="")` plus dot encoding before
substitution. The accompanying tests exercise traversal strings, slashes,
question marks, fragments, bare dot segments, and double-encoded traversal.
This makes the unencoded replacement the strongest stable semantic anchor for
`critical_operation`.

## Rebuilt entries

### `entry-00391` — RequestDirector construction path

Before the rebuild, `critical_operation` pointed only to the `_build_url`
declaration. A declaration is not the operation that creates the unsafe URL.
The rebuilt chain is:

```text
RequestDirector.build(flat_args)
  → _unflatten_arguments(...)
  → path_params[openapi_name] = value
  → url_path.replace(placeholder, str(param_value))
  → urljoin(...)
  → httpx.Request(url=url)
```

The critical node is now vulnerable lines 208–213, exactly where attacker
input is inserted without encoding. The logger node from the old trace is not
retained.

### `entry-00394` — complete OpenAPITool execution path

Before the rebuild, the entry started inside `_build_url` and marked the final
`AsyncClient.send()` call as critical. Sending is the impact point, but it is
not unique to the vulnerability. The rebuilt chain preserves both root cause
and effect:

```text
OpenAPITool.run(arguments)
  → self._director.build(route, arguments, base_url)
  → RequestDirector.build(flat_args)
  → _unflatten_arguments(...)
  → path_params[openapi_name] = value
  → url_path.replace(placeholder, str(param_value))
  → urljoin(...)
  → httpx.Request(url=url)
  → self._client.send(request)
```

`entry_point` is moved to the public tool execution boundary,
`critical_operation` is moved to the unencoded substitution, and the
authenticated request send remains the downstream impact node.

## Manual-review entries

`entry-00392` and `entry-00395` use the separate
`OpenAPIResource.read()` implementation in `components.py`. Their candidate
root cause is the substitution at lines 307–308, but the official fix and its
regression tests cover only `RequestDirector._build_url()`.

The canonical records are therefore left unchanged. Detailed blockers and
candidate actions are recorded in
`reports/issue-7-fastmcp-openapi.manual_review.csv`. Resolving them requires a
resource-path reproduction that demonstrates whether traversal syntax can
survive URI parsing and escape the configured client base path.

## Verification policy

The two rebuilt entries are `verify=1` because:

1. every repaired `{file, line, code}` node exactly matches the pinned
   vulnerable commit;
2. the fix commit is verified as a direct child of that commit;
3. the fix directly removes the selected critical operation;
4. the complete `entry-00394` chain reaches the authenticated request send.

The apply script preserves every non-target JSONL line byte-for-byte and emits
the field-level diff CSV. Its upstream mode verifies every annotated node
occurrence plus the vulnerable-to-fix relationship:

```bash
python scripts/apply_issue7_fastmcp_openapi_patch.py
python scripts/apply_issue7_fastmcp_openapi_patch.py --check-upstream
python -m unittest discover -s tests -p "test_issue7_fastmcp_openapi.py" -v
```

