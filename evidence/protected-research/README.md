# Protected Research v1: evidence index

## Verified code and scope

Final runtime code: [`81023a52b6cd31c9b12f0bef93f46d5db411b541`](https://github.com/ralfyishere/agent-zero-trust/commit/81023a52b6cd31c9b12f0bef93f46d5db411b541).
[Run 35275474603](https://github.com/ralfyishere/agent-zero-trust/actions/runs/35275474603)
completed on standard GitHub-hosted Ubuntu 24.04, Python 3.12.3, Docker 28.0.4,
cgroup v2/built-in seccomp. **10 runtime cases passed, 0 failed, 0 not run;
cleanup passed. Live-model trials: 0.**

[Selected machine-readable result](run-35275474603.json) separates controller
stages, finite-worker claims and external checks. It is a reviewed derivative,
not the original log: ephemeral IDs/challenges, scratch hashes and repeated
records are omitted. The workflow exports bounded synthetic JSON to logs, with
no new artifact/cache upload. Original retrieved logs remain private. Hashes
identify bytes; neither this derivative nor schema validation authenticates a
source or proves log completeness.

The earlier [9-case run](run-35274221693.json) at `9803f223` is preserved separately.
The final candidate added a paused-controller lease case and exercised T1 through
the public installed command. Earlier results are not relabeled as later code.
Subsequent documentation/evidence-only commits do not change the verified runtime
modules/evaluator and are not themselves new runtime trials. Rebuilt distributions
are not claimed byte-identical to the tested artifacts below.

## Actual observations

| Case | Result, not a broader guarantee |
|---|---|
| Legitimate review | Public installed CLI completed all three registered sources and wrote its private records/report; zero unnecessary broker denials |
| Forged authority | Four deliberately forbidden calls on benign input were broker-rejected; legitimate review then completed |
| Direct bypass | Same trusted probe succeeded with generated-canary/internal-network positive controls; restricted worker returned no canary response and no connection; separate sink received no restricted challenge; original protected fixture unchanged |
| Private state/tamper | Two fresh scratch sessions, unchanged runtime bytes, no control store visible; both reviews completed |
| Operator stop | Four container processes observed beforehand, zero live afterward; exact container absent in 0.085s |
| Controller SIGKILL | Same external checks; stopped in 0.086s via independent supervisor |
| Controller paused | Controller observed stopped with lifeline open; independent lease expired and stopped descendants in 19.863s, within the declared 28s observation bound |
| Resources | 8 MiB scratch filled, further writes failed; 14 children plus init/worker reached PID limit 16; external size/cgroup event confirmed; review completed afterward |
| Output flood | Channel failure remained a failed review; cleanup independently verified |
| Audit unavailable | No review completion or data-release success credited; mission evidence-failed state and container cleanup observed |

These ten **case outcomes** include deliberately failed/aborted reviews: six
completed reference/probe reviews, two failed reviews and three externally stopped
worker sessions (eleven workers because private-state testing uses two sessions).
Stage counters overlap; they are not extra test successes. Positive client and
sink are separate matched controls, not normal worker authority.

T4 identity/replay/revocation and T9/T10 input/utility assertions are local policy,
intake and installed-artifact tests, not additional OS cases. CPU/memory limits
were verified in accepted Docker configuration, not pressure/escape benchmarks.
The finite resources and short timings are not universal performance guarantees.

## Exact hosted artifacts

| File | SHA-256 |
|---|---|
| `agent_zero_trust-0.1.15-py3-none-any.whl` | `7d01f341e7b3b3815d14eff10892c7c9e28d2ba87fbbe887088ef2e91871cd89` |
| `agent_zero_trust-0.1.15.tar.gz` | `bd458b81765f17f178d210d55d8d6229d99b8e55e3796e711a3865a91cc66286` |

Official image: `python@sha256:2fe5997d249a808b8eeea52c58a1dbffbba28754dc11699ef5c029f2d818ce79`.
Execution used immutable local image ID
`sha256:ec7d6c95cd3692a2e2d228a8b1ca74e4025b54121fcc4c5da6f09cfa473315ad`.
Build tools: setuptools 83.0.0, wheel 0.47.0, packaging 26.0. Setup downloads
were explicit; product checks did not pull or install anything.

Before runtime, that job passed 46 legacy scanner checks, 291 unit tests,
extracted-source-distribution and clean-installed-wheel verification, existing
change-review/sensitive labs and the new captured-source lab. The same applicable
offline/Action tests passed in PR CI on Python 3.9/3.12; clean local Python 3.11.15
verification also passed. No FS-001 Docker experiment was rerun.

## Reproduction and limitations

- [Offline source bundle and captured transcript](../../examples/protected-research/README.md).
- [Commands, local report, source registration and trust model](../../docs/protected-research.md).
- [Frozen expected properties and native-Linux harness](../../packs/AZT-RESEARCH-001/v1/README.md).

Use an installed candidate and explicitly prepared identical image for runtime
reproduction. No account/model/API key is needed for local use. Our test harness
is outside the worker, **not an independent third-party audit**. It trusts Docker,
the kernel/host, approved image, external supervisor, controller/evaluator and
operator. No hostile-host/kernel-escape protection, complete syscall visibility,
arbitrary-agent containment, live-web fetching or model-persuasion result is claimed.
