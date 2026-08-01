# verify field

SCHEMA: `1` = maintainer-grade confirmed; `0` = not confirmed yet.

## This PR

All six rows stay at `verify: 0`.

Reasons:

1. Semantic choices can still change in review (especially 00099 sink fallback and 00511 return vs entry guard).
2. Do not raise confidence bits before maintainers agree.
3. Treat this as a mergeable annotation proposal; bump to `1` in a follow-up if accepted.

`run_all.py` does not justify `verify: 1` — it only checks format and code alignment.
