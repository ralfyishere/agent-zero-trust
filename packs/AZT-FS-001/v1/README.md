# AZT-FS-001 v1: unintended credential-directory read mount

For a developer reviewing an unfamiliar agent workspace configuration, AZT
identifies a newly declared read path and proposes a narrow, reviewable repair.
The optional synthetic test checks that the selected repair removes access
while a small coding task still runs. **The canonical three-phase check has real
Docker/Linux evidence. See the [source/run index](../../../evidence/README.md);
this is not universal containment or a live coding-agent integration.**

## Applicability and authority

The adapter `compose-json-bind-v1` supports one explicitly named service in
standalone UTF-8 Compose JSON, at most 64 KiB/32 literal long-form bind mounts.
Only `image`, `volumes`, optional `/workspace` working directory and string
labels are accepted. No YAML, includes, overrides, interpolation, short mounts,
hooks, commands, plugins, implicit files, multiple services or host path discovery.
Missing/unsupported layers fail; operator must identify the complete intended
input. Resolution is lexical, not proof a real daemon grants access. Symlinks
in declared source directories are untested; AZT never opens those sources.

Static repair compares an explicit reviewed baseline with the candidate and
selected protected source. It removes added exposing mounts, or restores that
target's baseline mount, preserving unrelated candidate bytes/settings. Parent
mounts count; read-only still permits reading. The JSON proposal binds baseline,
original and repaired digests. Verification recomputes the proposal against the
caller-selected protected resource; stale or altered proposals fail. User
settings are never automatically edited. Review `repair.diff` and the complete
`repaired.compose.json`; run a fresh comparison after any manual change.
Relative sources in the proposed file retain the **original candidate's directory
context**. The output directory is for review, not a relocated runnable Compose
project. Apply an approved diff to that original context yourself; AZT does not
rewrite your real settings or authorize the change.

This pack's expectation/probe/remediation code is bundled in AZT modules, not
loaded from inspected repositories or this metadata directory. All sample
configurations are data. No marketplace, remote pack loader or model is involved.

## Reproduce static comparison (Linux/macOS, Python 3.9+)

From a source checkout, install into your own virtual environment, or run
`python3 azt.py` in place of `azt`. No hook is required:

```sh
azt safety compare --baseline packs/AZT-FS-001/v1/baseline.compose.json --candidate packs/AZT-FS-001/v1/candidate.compose.json --protected-source ./synthetic-vault --output review-01 --json
```

Output must be a **new** directory under an operator-owned parent without
group/world write permissions or symlink components. Use a different output
name for repeated checks. Exit 0 means comparison completed, not admission or
safe execution. Exit 1 means a runtime check failed; exit 2 means invalid input,
operational error or blocked prerequisites. JSON stdout is one document.

## Optional execution (native Linux only)

Requires an already authorized local Docker Engine 25+ Unix daemon, cgroup v2
with CPU quota, memory+swap and process limits, builtin seccomp, and a trusted
preloaded Linux Python 3.12 image with `/usr/local/bin/python3` and `/usr/bin/tar`. No image is
pulled or built by AZT. Docker access is powerful host authority: do not grant
it to an untrusted agent or weaken permissions to make this test run. Docker
Desktop/macOS, remote engines and other backends are unsupported by this profile.

Follow the exact clean-build and pinned-image setup in
[the reproduction guide](../../../docs/reproduce-fs001.md), then run:

```sh
python3 scripts/test_safety_integration.py --case canonical --wheel dist/agent_zero_trust-0.1.9-py3-none-any.whl --output runtime-review-01 --image docker.io/library/python@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea
```

Alternatively use `azt safety check` with the same explicit configuration flags
as `compare`. Both use only already-preloaded images; `--image` is an explicit
operator-approved runtime override, not execution of the declared service image.
The resolved image ID, engine version, source module hashes, configuration hashes,
probe hash and observed controls are exported. `artifact.json` adds the wheel
and reproduction-script hashes when using the integration script.

The three desired outcomes are baseline inaccessible / deliberately expanded
read mount accessible / repaired inaccessible, with legitimate work completing
in **each**. They are expectations, not canned results. A blocked prerequisite
returns three blocked phases, no acknowledged execution stages, and non-success. Static results
and old admission benchmark counts are never added to runtime counts.

## What actually executes and what is measured

The evaluator creates an unchanged arithmetic project and a fresh random
32-byte canary in a disjoint synthetic directory. All declared relative mount
sources are substituted into this temporary resource tree. No real user source
directory is mounted or copied. Only one new exposure and a fixed writable
`/workspace` declaration are supported in execution. Additional sources must be
read-only, disjoint from the coding project and outside runtime/control paths.
Missing fixture sources are created empty, not read from the host.

The same bundled probe runs under UID 65532 in each configuration. It receives
a public random challenge and path, never the canary. It attempts a bounded
read and returns HMAC-SHA256(canary, challenge). The evaluator checks the
response using its private copy; generic success/denial text cannot establish
read access. The positive control must succeed before either denial counts.
An unavailable read alone does not prove that arbitrary hostile code cannot
find another route. The bundled probe is trusted instrumentation, not a model.

Inside the container, the workload copies the fixed coding input into tmpfs,
repairs a subtraction bug, and runs the changed Python code. The evaluator
checks execution stdout, independently retrieves exact edited bytes through
Docker, and checks the original project and protected file remain unchanged.
It does not execute exported code on the host or apply results. Expectations,
repair, canary copy and evidence are outside the workload's mounts. Only the
canary file itself enters the deliberate positive-control mount.

## Enforcing component and residual limits

Docker/host Linux provide isolation; AZT adds strict configuration comparison,
synthetic orchestration, control readback, digest-bound repair and evidence.
Requested profile: network `none`, read-only image, dropped capabilities,
no-new-privileges, private IPC/cgroup namespaces, disabled image healthcheck,
0.5 CPU, 96 MiB RAM/no added swap, 32 processes, 1 MiB file limit,
4 MiB workspace + 4 MiB temporary tmpfs + 1 MiB shared memory, bounded output.
No home, Docker socket, SSH agent or host credential environment is forwarded.
The approved image is trusted; its files/environment are not arbitrary host
secrets. Workspace secrets would be a separate issue in a future real runner.

A separate root-UID, capability-dropped keeper ends the container after 20s;
the unprivileged probe has an 8s controller deadline. Cleanup uses `docker rm
--force` on the exact random test-owned name. On reported cleanup failure, stop
and let an operator remove that reported session with the same local endpoint.
The keeper is intended to bound controller-loss lifetime, but controller SIGKILL,
descendants, networking, exhaustion and cross-session channels are **not tested
by this case**. A `finally` block is not a supervisor-death guarantee.

The TCB is operator, host/kernel, daemon, approved image, evaluator and bundled
probe. A hostile process already running as the host user can alter evaluator
files and is outside this profile's claims. JSON evidence is inspectable, not
signed or immutable. Hashes identify inputs, not authenticated issuance or
complete observation. No syscall audit or universal prompt-injection claim.

Upstream references: [Compose service configuration](https://docs.docker.com/reference/compose-file/services/),
[Docker run controls](https://docs.docker.com/engine/containers/run/),
[resource constraints](https://docs.docker.com/engine/containers/resource_constraints/),
[tmpfs behavior](https://docs.docker.com/engine/storage/tmpfs/),
[seccomp](https://docs.docker.com/engine/security/seccomp/).

## Evidence and contributors

`evidence.json` separates declarations, workload claims, Docker observations and
external evaluator checks. No canary value is exported. `proposal.json` may
contain operator-selected configuration paths/settings: review before sharing.
Safety evidence v2 distinguishes overlapping [controller stages and terminal
outcomes](../../../docs/safety-reporting-v2.md); historical v1 is preserved.
The [frozen variant](variant/README.md) changes source/target layout, not the
probe or expected three-phase outcomes.
Reports remain local until explicitly shared; no automatic retention/deletion,
telemetry, accounts or hosted dependency. Delete your selected output directory
when no longer needed. Outputs are bounded and never overwrite an existing run.

For another reviewed case, submit a problem statement, strict applicability,
independent positive/legitimate controls and a failing regression first. Add a
bundled versioned evaluator only after maintainer review; do not let input
metadata select code or expectations. Networking and descendant-stop are next
possible cases, not existing evidence. MIT and Rafael Peña/contributor credit
remain unchanged.
