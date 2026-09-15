# Experimental runtime status

AZT-FS-001 has a completed canonical three-phase Docker/Linux run. The
[evidence index](../evidence/README.md) identifies the exact source, artifact,
observations and limitations. A later candidate is not verified merely because
it shares version 0.1.9. Follow the [clean reproduction](reproduce-fs001.md).

| Capability | State | Evidence / limit |
| --- | --- | --- |
| Strict Compose JSON mount comparison and narrow digest-bound repair | Implemented, offline-tested | Adapter, CLI and installed-artifact tests |
| Canonical synthetic read / repair / legitimate coding task | Implemented, execution-tested | Baseline unavailable, intentional exposure verified, repaired unavailable; exact result bytes, original integrity and cleanup |
| Frozen nested-source configuration variant | Implemented; consult exact run index for verification | Another input to FS-001, not another pack |
| Bounded I/O, archive validation and failure reporting | Implemented, unit-tested and exercised by canonical export | Failure injection is not a kernel isolation trial |
| Network, descendants, controller death, exhaustion, cross-session tests | Not tested | Control readback is not an exercised denial |
| Real coding-agent/cloud integration | Unsupported | No model calls, broker or provider credentials |
| General runner/session-management platform | Not implemented | Outside this release |

Operator configurations are data, not arbitrary user workloads. Runtime
orchestration substitutes synthetic resources and runs the fixed trusted probe.
A misconfigured phase PASS means the test demonstrated intentional exposure;
it does not approve the unsafe configuration. Denial is limited to the selected
canary check with successful positive and legitimate-task controls.

Docker supplies Linux isolation primitives. AZT contributes configuration
interpretation, a review-only repair, synthetic orchestration, retesting and
inspectable evidence. The operator, host/kernel, daemon, image, evaluator and
probe are trusted. Same-user host compromise, kernel escape resistance and
complete action observation are not established.

Native Linux Docker 25+, cgroup v2 and an explicitly prepared compatible image
are required. AZT never downloads images, starts a daemon or falls back to host
execution. The earlier macOS service block remains in the historical evidence;
it is not the current Linux result. The [earlier proposal](runtime-0.1.8.md) and
diagnostic-only `azt doctor` do not establish Docker availability.

Local scanning, policy, repair, checks and evidence remain account-free, without
telemetry. Optional future organizational services could consume these public
formats; none are needed to supply basic protection, and none ship here.
