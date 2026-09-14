# AZT-FS-001 v1 — actual blocked execution record

These JSON documents and repair diff were exported from the installed 0.1.9
candidate, not hand-authored success logs. `artifact.json` identifies the exact
wheel SHA-256 and reproduction script. `evidence.json` binds module/configuration/
probe/policy hashes and reports the actual Darwin 25.6.0 arm64 environment,
Docker client 29.2.0 and absent local service. No server/image version was
observed. Configuration roots are redacted as `$CONFIG_ROOT`; no canary or
personal path is included. Local raw proposal records were not copied publicly.

| Phase | Container execution | Protected read | Legitimate task |
| --- | --- | --- | --- |
| Reviewed baseline | Blocked: local service unavailable | Unobserved | Unobserved |
| Deliberate misconfiguration | Blocked: local service unavailable | Unobserved | Unobserved |
| Repaired | Blocked: local service unavailable | Unobserved | Unobserved |

Zero of three container phases executed; zero passed; three blocked. The
installed-wheel operation exited 2 after 1.82s including clean installation.
The static comparison identified the new declared mount and produced
`repair.patch`, removing just that access. Repair bytes equal the reviewed
baseline for this fixture; unrelated settings remain. Runtime effectiveness
and legitimate-task completion have **not** been demonstrated.

Reproduce from the checkout using an already approved Linux Docker environment
and preloaded Python image:

```sh
python3 scripts/test_safety_integration.py --wheel dist/agent_zero_trust-0.1.9-py3-none-any.whl --output runtime-review-01 --image python:3.12-slim
```

Full prerequisites, synthetic inputs and limitations are in
[the pack](../../packs/AZT-FS-001/v1/README.md). The old 11-check intake evidence
in `scanner-0.1.8/` is a separate historical study and is not combined with these
phases. Public fixtures are `baseline.compose.json`, `candidate.compose.json`
and the bundled Python probe. Fresh successful runs will use different random
canaries/challenges/session identities; compare expected outcomes and source/
artifact identity, not byte-identical runtime reports.
