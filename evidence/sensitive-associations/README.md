# Sensitive association regression — September 16, 2026

[Scoped machine-readable result](2026-09-16.json) compares the released 0.1.12
wheel with the 0.1.13 candidate at `59ef422560eeb6a76a719460dfefb4268bfa14d0`.
The six inert inputs were frozen before final measurement; all were known during
development. This is maintainer/model-assisted regression testing, not held-out
accuracy, a third-party audit, live-agent behavior or runtime protection.

| Case | Released baseline sensitive classes | Candidate sensitive classes |
| --- | --- | --- |
| C1 | tokens | tokens |
| C2 | none | none |
| C3 | none (miss) | tokens |
| C4 | none (miss) | tokens |
| C5 | tokens, shell-history (false alert) | none |
| C6 | tokens | tokens |

Both direct installed-component and installed-scan results agree. All inspections
completed. HIGH-threshold scans exit 0 throughout; MEDIUM scans exit 1 precisely
where the sensitive rule is observed. Baseline: 3/6 expectations met (two misses,
one false alert); candidate: 6/6 (zero misses/false alerts on this selected pack).
This does not imply broad natural-language coverage. No fixture instruction,
destination, real credential or target setup was executed or accessed.

Darwin 25.6.0, Python 3.14.6, same harness and synthetic inputs: baseline 1.065493s,
candidate 1.372717s, child peak RSS 28,393,472 / 28,540,928 bytes. Each timing is one
small run including interpreter startup, not a performance benchmark claim.

From reviewed source, use separate external installed environments and new output
files (installation is separate from offline measurement):

```sh
python3 scripts/evaluate_associations.py --python /external/baseline/bin/python --output /external/baseline-result.json
python3 scripts/evaluate_associations.py --python /external/candidate/bin/python --output /external/candidate-result.json
```

The baseline command intentionally exits 1 for its failed expectations. See
[frozen inputs](../../examples/sensitive-request/associations-v1.json),
[additional controls](../../tests/test_sensitive_associations.py),
[grammar limits](../../docs/sensitive-requests.md) and
[first-user lab](../../examples/sensitive-request/README.md).
The original diagnostic miss and historical results are unchanged. Earlier draft
regressions in noun `copy` and reference names containing contrast words were
found by a bounded fresh-context model review, fixed, and retained as tests.

The selected export was checked for personal paths and sensitive fields before
publication. It is a derivative with source/artifact provenance, not a rewritten
historical raw result. Later evidence-only commits and future builds have their
own identities; these wheel hashes must not be reused as future release hashes.
