# Controlled investigator: September 18, 2026

Tested code: `e1c66bd984863314c640e81b537990013b1b0091`, tree
`c3ddd0320ce09b9511fe5242c48bd98dbfca9b1e`, **0.1.16 unreleased**.
[Run 35311454473](https://github.com/ralfyishere/agent-zero-trust/actions/runs/35311454473)
used a standard ephemeral Ubuntu 24.04 runner, native Linux, Docker 28.0.4,
cgroup v2 and the recorded immutable Official Python image. No paid model,
real credential, personal-host runtime trial or external target was used.

## Distinct results, not one safety score

| Evidence level | Actual result |
|---|---|
| Offline scanner/unit/package | Scanner passed; 324 Linux unit tests passed, including three real test-owned loopback HTTP tests; installed wheel and extracted sdist/labs passed |
| Reference-profile regression | 13 passed, 0 failed, 0 not run; cleanup passed; new source, not inherited historical evidence |
| Isolated investigator + scripted HTTP service | 4 passed, 0 failed, 0 not run; cleanup passed |
| Live-model judgment and utility | **0 trials; blocked** by missing assigned, confirmed local-only native-Linux service |

The investigator's useful synthetic task completed in four inference exchanges
(0.734 s on this runner): all three sources read/checked, three required quote/
citation pairs present, four deliberate invalid proposals denied, zero unnecessary
denials, original fixture bytes unchanged. Rejected requests included an upload,
unknown source, fabricated quote and unmaintained next-step instruction. The
scripted response fixture supplies those proposals; **this is not a model making
decisions, an interpretation-accuracy result, or a persuasion benchmark**.

An invalid inference response caused a failed run after actual container start;
cleanup still passed. Controller SIGKILL during inference removed both observed
container processes in 0.089 s. A paused controller could not extend the separate
120-second profile: the independent supervisor removed both processes in 119.837 s
from the pause. These are selected measured outcomes, not universal timing
guarantees. Inference-server cancellation remains unverified.

The [selected machine-readable record](run-35311454473.json) records every case,
actual artifacts, source/module/evaluator identities, backend, image and outcome.
It omits raw logs, run-local containers/mission IDs and private paths. Raw-export-line
digests identify inputs to this derivative, not authenticated issuance or complete
observation. The full logs remain private; this summary is not byte-identical to
them or an independent audit. Later evidence-only commits do not claim a new
runtime test or a byte-identical rebuild.

## Exact hosted artifacts

| Filename | SHA-256 |
|---|---|
| `agent_zero_trust-0.1.16-py3-none-any.whl` | `ee36ed5a0fc0c68a8f0f5e4e93864f78bae2538c95f98820b100c47f5a9bde88` |
| `agent_zero_trust-0.1.16.tar.gz` | `644b325c8837c470942685d014d74226c34713976db1d1583079fce8ea6e620d` |

The separate clean macOS/Python 3.11.15 build tested the same code: 324 invocations,
**three HTTP tests skipped** because loopback listening was unavailable, not
credited as passed. Scanner and installed artifact checks passed. The wheel had
31 entries and sdist 289, with no private continuity/draft/personal-path entries.
Local wheel SHA-256 `a2bb63f1582f359d01023ed1fde55d442b663d93fd8f0a2a35de2d16a21547dc`;
local sdist `dd8b1f1a7bb56db7abb587b09737daeaebc8d48a4f589131c6eab5773dea170f`.
Build 0.347 s, scanner 0.280 s, units 10.916 s and installed-artifact verification
29.582 s on that host. These are observations, not cross-platform performance claims.

## Reproduce and review

- [Opt-in usage, local-service prerequisite and limits](../../docs/controlled-investigator.md).
- [Inert source bundle and frozen rubric](../../examples/protected-research/investigator/README.md).
- [Exact-SHA maintainer integration route](../../docs/protected-research.md#maintainer-integration-selection).
- Offline: `python3 test_azt.py`; `python3 -m unittest discover -s tests -q`;
  build using declared tooling, then `python3 scripts/test_artifact.py dist`.
- Actual integration: the selected installed Python runs
  `scripts/test_research_integration.py` and `scripts/test_investigator_integration.py`
  with explicit preloaded immutable `--image` and new external `--output` paths.

Cases were visible during development. The model-review collaborator was
unavailable; review was performed by the implementing assistant, not a third-party
auditor. The full task's [first failed reference attempt](../research-reliability/README.md)
remains preserved. FS-001 evidence is unchanged and no FS-001 trial was repeated.

Remaining limits: trusted Docker/kernel/host/supervisor/controller/evaluator/image
and inference service; no kernel-escape guarantee; bounded English detectors;
limited model context may produce an incomplete review of a larger capture;
valid citations do not prove the model's interpretation. No live web collector,
agent credentials, autonomous repairs, public submission or persistent permission.
