# Final experimental candidate: AZT-FS-001

Recommendation: ready for owner review as an experimental 0.1.9 release, not a
general containment product. No release or PR was created.

- Verified code: `94a802bbe8b54e86b730203051b9abc162cf0da8`.
- Source tree: `f122f501cbc1bd3cfb8a9dab8fb638d2b22cff88`.
- [Run 34915008373](https://github.com/ralfyishere/agent-zero-trust/actions/runs/34915008373),
  attempt1, job104210644902: success; 2026-09-15 00:53:14–00:54:07 UTC.
- Wheel `agent_zero_trust-0.1.9-py3-none-any.whl` SHA-256:
  `7ad73af671236610662ba3940170d3987db48fbd8c4a269aa8b8d384a6762aae`.
- Tested sdist `agent_zero_trust-0.1.9.tar.gz` SHA-256:
  `4ae1b51f8d3a809f4a8860f378f1a2a65618fc1ca91e19491811973a291ac823`.
- Docker client/server28.0.4, cgroupv2, Ubuntu24.04, kernel6.17.0-1022-azure,
  x86_64; runner image20260907.300.1; controller Python3.12.3.
- Official Python3.12-slim declared Python3.12.14; resolved and executed image
  `sha256:ec7d6c95cd3692a2e2d228a8b1ca74e4025b54121fcc4c5da6f09cfa473315ad`;
  repository digest `python@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea`.

This record and index are a subsequent documentation/evidence-only commit.
They do not relabel a rebuilt wheel as the tested wheel. No wheel/sdist upload
was performed; the job exported their digests. Rebuild the named code to
reproduce behavior; archive timestamps/metadata can change artifact hashes.
Module, probe, evaluator, configuration and policy digests are in the record.

## Actual observations

| Input / phase | Start / probe protocol | Protected read | Export / archive / exact edit | Legitimate task | Originals / cleanup | Phase |
| --- | --- | --- | --- | --- | --- | --- |
| Canonical baseline | Completed | Unavailable, ENOENT | Verified | `5 0`, exit0 | Unchanged / removed | Passed |
| Canonical misconfigured | Completed | HMAC exposure verified | Verified | `5 0`, exit0 | Unchanged / removed | Passed |
| Canonical repaired | Completed | Unavailable, ENOENT | Verified | `5 0`, exit0 | Unchanged / removed | Passed |
| Variant baseline | Completed | Unavailable, ENOENT | Verified | `5 0`, exit0 | Unchanged / removed | Passed |
| Variant misconfigured | Completed | HMAC exposure verified | Verified | `5 0`, exit0 | Unchanged / removed | Passed |
| Variant repaired | Completed | Unavailable, ENOENT | Verified | `5 0`, exit0 | Unchanged / removed | Passed |

Each input: planned3; passed3, failed0, blocked0, not_run0, unknown0. Each of
the six overlapping controller-stage counters is3, not18 independent passes.
Canonical execution2.626s (5.753s including install); variant2.613s (5.744s
including install). Each case used a fresh resource tree and challenge; within
each case, probe/canary/task/expectations stayed unchanged during repair.
All six containers were removed. Final daemon readback: verified_absent,
no remaining labeled test container. No test phase was skipped.

The canonical proposal removes the added `./synthetic-vault` read mount at
`/agent-credentials`. The variant removes only the added parent `./resources`
mount at `/review-material`; nested canary, reference mount and benign labels
exercise different supported layout. The proposal binds original bytes and
preserves unrelated settings. The external evaluator applies it only to the
synthetic test plan; no real agent or host configuration is edited.

The workload reported read/task results; AZT observed successful Docker calls
and the fixed protocol; the project-owned evaluator checked the HMAC, exact
returned file bytes, original fixtures, full positive control and cleanup.
The bundled trusted probe executed edited code inside the container, not on
the host. Misconfigured PASS means intentional exposure demonstrated, **not
safe deployment**. Unavailable access is credited only with the complete
positive/legitimate controls. This is not a third-party independent audit.

## Reproduce and check scope

Use [the clean first-user guide](../../docs/reproduce-fs001.md) at the code SHA
above: offline scan/compare, explicit build-tool and image preparation, then
`scripts/test_safety_integration.py --case canonical` and `--case variant`.
No account/model API key is needed for local use. Native Linux Docker25+,
cgroupv2 and authorized local daemon access are required for execution.

Hosted commands and actual results:

```text
python3 test_azt.py                         45/45 legacy checks passed
python3 -m unittest discover -s tests -q   93/93 passed, 10.713s
python3 scripts/test_artifact.py <dist>   passed
python3 scripts/safety_ci.py run ...      canonical 3/3; variant 3/3
python3 scripts/safety_ci.py finish ...   verified_absent; bounded export
```

Artifact tests ran six shell-input cases, extracted-sdist legacy+unit suites,
43 installed adapter/evaluator/reporting tests, help/version, deterministic
JSON, benign exit0, expected malicious finding exit1 and invalid input exit2.
They explicitly check imports from the clean installed environment.

Offline negatives passed: preflight block, pre-probe failure, completed probe
followed by export failure, invalid archive/file bytes, invalid HMAC, cleanup
failure, missing/invalid evidence, stale/tampered repair and unsupported layers.
A failed positive control cannot credit denial. No-change input produces an
empty repair; trying to run the three-phase pack without exposure is blocked,
not forced into success. These are functional tests, not extra runtime trials.

Local clean-snapshot verification also passed93 tests on Python3.9.6 and3.14.6.
Fresh source scan took0.071s with Python already installed. Fresh venv wheel
install/version/scan and repeated comparison worked; no local downloads.
Local macOS execution remained explicitly blocked (three blocked phases).
The separately repeated installed intake benchmark passed11/11 admission checks,
with its eight runtime scenarios still not run. None add to FS-001's six phases.

## Provenance, privacy and limits

[Machine-readable selected record](34915008373.json) retains the emitted
synthetic fields and adds provenance; JSON is reformatted, not byte-identical
to the private raw export. Original selected export SHA-256:
`60a4afe4b78ba6284b2e2f302de9dd5654606ea2ffe029d4947a034a3d750569`.
The reviewed record contains placeholders instead of hosted paths, no canary
value, credentials, capsules, raw proposals or private logs. Hashes identify
records; they are not signatures or completeness/immutability guarantees.
Raw historical exports remain unchanged; [history](history.json) is a separately
labeled interpretation of the earlier failed and successful runs.

Docker supplies isolation. AZT adds supported configuration interpretation,
reviewable repair, synthetic orchestration, retest and evidence. Only selected
filesystem reads were exercised; other controls had configuration readback.
No network/exhaustion/descendant-stop/controller-death/cross-session trial,
live-agent integration, arbitrary hostile workload, host same-user compromise
or kernel-escape assurance. This is a small trusted-probe regression, not a
universal safety percentage. The host, daemon, image, operator, evaluator and
probe remain trusted. Local controls remain MIT, account-free and telemetry-free.
