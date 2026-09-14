# Runtime status: bounded pack implemented, execution verification blocked

`azt safety compare` works offline on Linux/macOS. `azt safety check` implements
one bundled, synthetic Docker test; **zero container trials are recorded here**.
The installed Docker 29.2.0 client was inspected and an actual local server
connection attempted. Its configured local Docker Desktop socket was absent:
unavailable service, not proof every possible execution route is unavailable.
No daemon was started, remote engine accessed or privileged component installed.
The selected profile supports native Linux only, not Docker Desktop/macOS.

The concrete owner action is to run the command in
[AZT-FS-001 v1](../packs/AZT-FS-001/v1/README.md) on an already authorized
native Linux Docker 25+ host with cgroup v2 and a preloaded approved Python
image. A blocked prerequisite returns non-success. A runtime release requires
all three actual phases and legitimate tasks to pass, with published raw evidence.

| Capability | State | Evidence |
| --- | --- | --- |
| Strict mount comparison and narrow digest-bound repair | Implemented, offline-tested | `tests/test_config.py`, `tests/test_safety.py` |
| Bounded process I/O and archive validation | Implemented, unit-tested | Real finite Python children and synthetic archives, not container trials |
| Three-phase Docker orchestration and external evaluator | Implemented, runtime unverified | `scripts/test_safety_integration.py`; local prerequisites blocked |
| Filesystem denial plus legitimate task after repair | Not yet demonstrated | Requires actual baseline/positive-control/repaired results |
| Network, descendants, controller death, exhaustion, cross-session tests | Deferred, not exercised | No inherited credit from Docker configuration or mocks |
| Real coding-agent/cloud integration | Unsupported | No model calls, broker or provider credentials |
| General runner, session management platform | Not implemented | Deliberately outside this bounded milestone |

Docker supplies the maintained kernel isolation primitives. AZT contributes
explicit interpretation, synthetic input mapping, repair/retest lifecycle and
inspectable evidence; it does not invent an isolation engine. The pack lists
required resource controls, observable outcomes and its trusted computing base.
The [historical bubblewrap proposal](runtime-0.1.8.md) and its diagnostic-only
`azt doctor` remain available but are not proof of Docker availability.

Local policy, tests, repair, evidence and essential control remain account-free.
Future optional organization services may consume exported evidence or distribute
reviewed policies; none grant privileges through model assertions or require a
hosted service for local safety. Those services are not implemented.
