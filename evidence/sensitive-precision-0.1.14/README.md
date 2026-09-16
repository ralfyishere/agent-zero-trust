# Sensitive-request precision: 0.1.14 candidate

This is an offline, installed-package regression measurement, not a live-agent
evaluation, independent audit or detection-accuracy estimate. The candidate is
unreleased; the public installation quickstart still correctly selects 0.1.13.

The same [16 synthetic inputs and three comparisons](../../examples/sensitive-request/precision-v1.json)
were checked with the released 0.1.13 wheel and the 0.1.14 candidate. Inputs were
visible during development; none is claimed as held out. The six older
negation/contrast cases already pass in 0.1.13 and still pass in this candidate.

| Measurement | Released 0.1.13 | Candidate 0.1.14 |
| --- | ---: | ---: |
| Precision cases matching expected observations | 10/16 | 16/16 |
| False-alert cases in this pack | 3 | 0 |
| Missed-request cases in this pack | 0 | 0 |
| Incorrect duplicate/reference observations | 3 | 0 |
| Comparison checks | 3/3 | 3/3 |
| Scan-to-JSON-review checks, two thresholds per case | 32/32 | 32/32 |
| Operational failures | 0 | 0 |

The corrected cases concern bare token measurements/parser material, repeated
exact recipients and links, and an additional hop incorrectly called a cycle.
Distinct recipients remain distinct. Explicit credential requests still deserve
review, including selected authentication-role and mixed measurement/value
phrases. Additional adversarial variants caught during review became visible
regression tests; they are not extra held-out successes in this table.

One sequential run on Darwin 25.6.0 / Python 3.11.15 took 3.578 seconds for the
baseline and 3.533 seconds for the candidate; child high-water RSS was 25,952,256
and 26,001,408 bytes respectively. These totals include process startup and
exports; one observation does not establish a speed improvement.

## Exact code and artifact scope

The tested candidate code is
[`6b944ab093d2ce7928702344b611348dd5fddb45`](https://github.com/ralfyishere/agent-zero-trust/commit/6b944ab093d2ce7928702344b611348dd5fddb45).
This evidence directory was added afterward; it is not part of the recorded
wheel or source distribution. A later rebuild has its own artifact identity.

| Candidate artifact | SHA-256 |
| --- | --- |
| `agent_zero_trust-0.1.14-py3-none-any.whl` | `e5edcefccbeb1662c0855c890c80ef4d9fdae23412273d73a6d925ca82e21afd` |
| `agent_zero_trust-0.1.14.tar.gz` | `647fb4c70068c94282d4a0298358f0c42bfd28330573b7f526e3f32cc6084d99` |

The clean tracked build passed 46 scanner checks, 256 unit tests and the
installed-wheel/extracted-sdist suite. That suite includes both existing labs,
Action error/injection regressions and the new precision/summary/bounds cases.
The separate installed intake benchmark passed 11/11 admission/workflow checks;
it ran zero runtime trials and left its eight runtime scenarios not run.
Historical FS-001 modules, probe and evidence were not changed or rerun.

[Machine-readable results](results.json) contain selected observations, original
result digests, source/module identities, fixture hashes and the actual local
build manifest. They are sanitized derivatives, not the complete raw private
records. Recipient values, excerpts, private paths and session logs are excluded.
Checksums identify bytes, not authentic issuance or an independent review.

## Reproduce with a reviewed installed candidate

Follow the existing [clean build/test procedure](../../docs/publication.md),
without publishing. Build tools may require explicitly installed development
dependencies; the evaluation itself is offline and stdlib-only. Keep the build,
environment and result files outside every inspected fixture tree. From the
reviewed source checkout, using the wheel produced by that build:

```sh
AZT_SOURCE=$(pwd -P)
AZT_REVIEW=$(mktemp -d)
AZT_REVIEW=$(cd "$AZT_REVIEW" && pwd -P)
cd "$AZT_REVIEW"
python3 -m venv "$AZT_REVIEW/precision environment"
"$AZT_REVIEW/precision environment/bin/python" -m pip --isolated install \
  --no-index --no-deps /absolute/path/to/agent_zero_trust-0.1.14-py3-none-any.whl
python3 "$AZT_SOURCE/scripts/evaluate_precision.py" \
  --python "$AZT_REVIEW/precision environment/bin/python" \
  --output "$AZT_REVIEW/precision-results.json"
python3 "$AZT_SOURCE/scripts/sensitive_request_lab.py" \
  --cli "$AZT_REVIEW/precision environment/bin/azt" \
  --output "$AZT_REVIEW/readable lab"
```

The last command exercises scan → compare → explain → export and creates
`readable lab/scan-review.html`. The precision evaluator returns 0 for matching
observations, 1 for mismatches, and 2 for setup/operation failures. Running its
new expectations against 0.1.13 intentionally returns 1, not a setup failure.
Output paths are create-only. Do not run any instruction inside a fixture.

## Result interpretation and compatibility

MEDIUM/default-HIGH semantics and scan exits 0/1/2 are unchanged. Human scan and
local-export summaries now separate inspection completeness, severity counts,
threshold outcome and the next review step; a green result is not approval.

Method `sensitive-request-v1.2` and `additional-hop-not-followed` are explicit
provenance/observation additions. New readers retain supported older reports;
old binaries may reject new observations. Upgrade the reader rather than editing
historical evidence. Changed detector identity requires explicit re-admission
for an optional snapshot gate. Referenced context remains dependency-bound and
cannot be suppressed by an insufficient primary-file exception.

This is still bounded English matching, not general language understanding.
Unqualified tokens can remain ambiguous; different contact blocks are not
silently merged. No secret content, actual disclosure, destination trust or
universal safety is established. [Supported relationships and limits](../../docs/sensitive-requests.md).
