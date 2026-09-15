# Change-review evidence, 0.1.11 candidate

Implementation source: [`0296facec2565668386c3c0d5dbacb734e6241e3`](https://github.com/ralfyishere/agent-zero-trust/commit/0296facec2565668386c3c0d5dbacb734e6241e3).
This is local offline verification, not runtime-containment evidence or an
independent-user study. Later presentation/evidence commits do not retroactively
change the identity of the artifacts below. Final PR checks build their own bytes.

## Build and tests

[Implementation build manifest](implementation-build.json): clean tracked source,
Python 3.11.15, setuptools 83.0.0, wheel 0.47.0, packaging 26.0. The legacy scanner
passed all 45 checks, units passed 137/137, and installed-wheel/extracted-sdist
verification passed, including the four-case lab. No new runtime trials.

| Artifact | SHA-256 |
| --- | --- |
| agent_zero_trust-0.1.11-py3-none-any.whl | `43cfa131a8ff36b75994ee19c0cac3a238b1181a366a52203a967276e096f0ec` |
| agent_zero_trust-0.1.11.tar.gz | `dd842022ee58feebc9f0c0fdfe05cb5f862759885fce02ab0bd1b83cfc608f17` |

Commands: `python3 test_azt.py`, `python3 -m unittest discover -s tests -v`,
`python3 scripts/test_artifact.py DIST`. The build used
`python3 scripts/release_candidate.py --output NEW_DIRECTORY` with its documented
existing build tools. The separate installed-wheel intake benchmark passed
11/11 admission/workflow checks, eight runtime scenarios not run. That is not
11 runtime checks and does not extend historical FS-001 evidence.

## Three clean-environment repetitions

Same wheel, same Darwin 25.6.0 ARM64 machine and trusted fixture source; fresh
virtual environments. These are maintainer repetitions, not independent users
or three platforms. Install used `pip --isolated install --no-cache-dir --no-index --no-deps WHEEL`.

| Python | Lab | Lab elapsed | Frozen evaluation | Evaluation elapsed |
| --- | --- | --- | --- | --- |
| 3.9.6 | [4/4 passed](lab-py39.json) | 4.219 s | [35/35 passed](evaluation-py39.json) | 0.254 s |
| 3.11.15 | [4/4 passed](lab-py311.json) | 1.518 s | [35/35 passed](evaluation-py311.json) | 0.118 s |
| 3.14.6 | [4/4 passed](lab-py314.json) | 1.741 s | [35/35 passed](evaluation-py314.json) | 0.127 s |

Commands: `python scripts/change_review_lab.py --cli INSTALLED_AZT --output NEW_DIRECTORY`
and `python scripts/evaluate_review.py --python INSTALLED_PYTHON --output NEW_FILE`.
Times include the helper's observed command execution, not interpreter provisioning
or installation; the simultaneous local repetitions are not a throughput study.
All 35 behavior cases ran, zero failures/skips in each measurement, including
10 benign/context cases. Those ten are varied behavior tests, not ten independent
benign repositories. Lab baseline and benign scans had zero findings (0/2 false
alerts on these two inputs); unchanged/benign comparisons had zero new findings.
The fixed corpus is too small to infer real-world accuracy.

A separate fresh local clone also followed the documented `venv`, `pip install
build`, `python -m build`, offline wheel install and lab path on Python 3.11.15.
It passed 4/4 (lab 1.468 s). The source clone was local rather than a remote
download; build 1.6.1, packaging 26.3 and pyproject_hooks 1.3.0 were explicit
installation downloads. This extra smoke build is not the identified wheel
above. Setuptools emitted non-blocking license-metadata deprecation warnings;
the MIT license was not changed. Provisioning/install latency was not measured.

The concerning change produced two new findings; the incomplete comparison
retained two unresolved observations. [Full redacted concerning comparison](concerning-changes.json)
and [actual text transcript](../../examples/change-review/transcript.txt) preserve
identities and limitations. [Reproduction](../../examples/change-review/README.md).

## Review and limitations

A bounded fresh-context model review found three semantic defects during local
development: unreadable paths looked deleted, contradictory deterministic reports
looked comparable, and JSON output could exceed its input bound. All were repaired
and covered by behavioral assertions before measurement. This was not a third-party
audit. Existing scanner misses remain visible in [COVERAGE](../../COVERAGE.md).

No new detection rules were claimed. Baseline comparison is the unchanged legacy
45-check suite (45/45 before and after); the 35 new cases measure features the old
CLI did not have, not a claim that detection accuracy improved. Native Windows,
live-agent behavior, authority enforcement, new Docker trials and hidden context
outside the selected reports are not tested here.

Selected records contain synthetic paths only and were inspected before publication.
Build/evaluation/lab JSON and transcript are copied from generated outputs; the
comparison is already a redacted derivative produced by AZT, not the raw scan.
The GIF highlights captured output with editorial pacing. Neither checksums nor
these self-reported records authenticate the evaluator or establish report truth.
Private logs, personal paths and continuity capsules are excluded.
