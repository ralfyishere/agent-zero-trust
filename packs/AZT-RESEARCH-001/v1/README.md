# AZT-RESEARCH-001/v1

Problem: inspect selected captured sources without treating their instruction,
role or approval claims as authority. Applicability is the fixed offline reference
worker and native-Linux Docker profile, not a live model or arbitrary code loader.

[Frozen expectations](expectations.json) precede the first runtime trial. The
[external evaluator](../../../scripts/test_research_integration.py) owns resources,
expected outcomes and evidence outside the evaluated workload. Our harness is
not an independent third-party audit.

| Property | Evidence route | Status before first hosted trial |
|---|---|---|
| T1 legitimate review | installed reference worker; all sources read/checked | locally policy-tested; OS not run |
| T2 forged authority | four forbidden proposals on benign input | policy-tested; OS not run |
| T3 direct read/network bypass | matched canary + internal sink controls | OS not run |
| T4 identity/replay/lease/role | broker tests; no caller identity token | locally policy-tested |
| T5 persistent influence | new mission IDs; two disposable scratch sessions | policy-tested; OS not run |
| T6 stop/controller crash | external Docker + host process checks | supervisor stub only; OS not run |
| T7 limits | frame/budget tests; finite scratch/fork/output probes | policy-tested; OS not run |
| T8 evidence failure | forged observations; audit/output errors + actual worker stop | policy-tested; OS not run |
| T9 input handling | safe intake, capture/encoding/path/shadowing regressions | locally tested |
| T10 usefulness/coverage | benign/concerning/partial local captures and lab | locally tested |

The final evidence index will preserve actual failed/passed/not-run outcomes;
this preparation table is not a result of execution.

## Reproduce

Use the [offline source lab](../../../docs/protected-research.md) first. Build and
install the exact reviewed candidate outside all input trees. No Docker is needed
for `scripts/research_lab.py --cli /absolute/path/to/azt --output /new/private/lab`.

For actual boundaries, explicitly prepare an approved official Python 3.12-slim
linux/amd64 image in a disposable native-Linux environment and record its digest
and immutable local image ID. The product and evaluator never pull it implicitly.
The [selected CI job](../../../.github/workflows/research.yml) separates setup
downloads from testing and is not triggered by forks or ordinary PR checks.

```sh
"$INSTALLED_PYTHON" -I scripts/test_research_integration.py \
  --image "$IMMUTABLE_IMAGE_ID" --output /new/private/evaluation
```

Only test-owned synthetic resources are used. The positive client receives one
generated canary and one internal Docker network; normal workers remain network
`none` and do not mount the canary. A separate sink records received challenges.
Canary challenge responses prove a selected read only with the positive control.
Resource errno reports are checked against independent scratch/cgroup readback.
Descendant stop is observed using Docker and host process state, not stdout.
Failures retain partial observations. Cleanup targets exact recorded names/IDs;
no daemon-wide prune, host ports or public network targets are used.

T4/T9/T10 are not counted as additional runtime cases. CPU/memory restrictions
receive configuration verification, not destructive pressure/escape tests. A
missing daemon or failed setup is blocked/not-run, never a credited denial.
The controller, evaluator, lease supervisor, approved image, daemon and host are
trusted. No live-model trials, syscall-complete logs or kernel-escape claims.
