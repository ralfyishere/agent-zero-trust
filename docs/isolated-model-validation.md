# Disposable local-model trial — test branch only

**Current selection is one bounded full-model trial, not yet measured.** The
startup-only diagnostic passed in [run 35376037563](https://github.com/ralfyishere/agent-zero-trust/actions/runs/35376037563)
at `7179cc5848f105145862ad3526a3684dd5345510`: service/relay starts, fixed-version
readiness and both cleanup passes completed. No model work ran in that diagnostic.
The separately authorized test-branch selection now uses the existing full
experiment below: fixed model preparation, matched network control, one preload
and at most two synthetic investigations. This is not an automatic progression
from startup success or a claim that the model trial has passed. No retry follows
without a new test decision.

This is the explicitly authorized continuation of the 0.1.16 source experiment,
not a package release, production deployment or protection guarantee. The product
code, prompt, tools, 10-second requests, 120-second worker lease and existing
synthetic task assertions remain unchanged. No model runs on the developer's Mac.

## Setup versus investigation

Use only the reviewed exact-SHA `research.yml` dispatch on
`test/isolated-local-model`. The public repository's standard `ubuntu-24.04`
runner is a disposable 4-CPU/16GB VM, not a personal/self-hosted server. The job
has a 15-minute ceiling; no GPU, paid service, secrets, cache or artifact upload.
Only bounded sanitized results enter workflow logs. No third-party audit claim.

Explicit downloads, only on that runner:

- Existing setuptools83.0.0, wheel0.47.0 and packaging26.0 build dependencies.
- Docker Official Python linux/amd64, pinned to the existing tested manifest.
- Upstream `ollama/ollama`0.34.2 linux/amd64, resolved from its official repository,
  pinned manifest `sha256:c715bebf769913db6c82d96f8a8dfee989c4bdfe19fa7d700e3d41ee0ceb5461`.
- `qwen3:0.6b`, about523MB. Manifest SHA-256
  `7df6b6e09427a769808717c0a93cadc4ae99ed4eb8bf5ca557c90846becea435`;
  each model/config/template/license blob is hash/size checked. This small CPU
  model is a bounded compatibility/utility trial, not a representative evaluation.

Download setup uses a separate restricted container with temporary network access
and **no task sources or credentials**. Its 768MiB model volume is tmpfs-backed;
the download has a 300-second independent container deadline. It is removed before
inference. A read-only relay keeps that tmpfs mounted during the phase transition.

The inference container runs UID/GID65532, read-only root/model volume, no-network,
no published ports, all capabilities dropped, no-new-privileges, 3.5CPU/6GiB/128PID
limits, bounded scratch/logs and an independent420-second lifetime. Cloud mode is
explicitly disabled and its actual startup log checked. A fixed Python relay
shares only its network namespace; controller communication uses Docker stdin,
not an exposed model port. A narrow host-loopback bridge serves the unchanged
AZT adapter. Model text cannot select commands, routes, endpoint, model or files.
The ordinary protected planner remains in its own existing no-network container.

Before any task, a matched test-owned network sink establishes reachability from
an explicit positive client. The inference namespace must show only loopback and
fail that same connection. This is a selected connection test, not syscall tracing
or proof against kernel/daemon compromise. Docker, host, images, relay, controller
and evaluator are trusted components. The entire test uses synthetic material.

## Measurement and cleanup

One empty model preload, then at most two fresh investigations: limited legitimate
diagnostics, followed by the existing three-source conflict/peer-approval case.
No prompt tuning or retry after seeing results. Report task completion, exact
quote coverage, model proposals/denials and operational failures separately.
Live models need not make the four deliberately bad proposals of the scripted
test. Human interpretation quality remains distinct from citation matching.
Requests that cannot finish inside the current product bounds must fail visibly.

Normal cleanup removes exact recorded run-owned containers, the model volume and
internal test network and reads back their absence. An independent workflow
`always()` step repeats exact-ID/label-checked cleanup after interruption. New
image removal is attempted without force/prune; any remaining image layers die
with the disposable VM. No host service or model installation persists. Container
deadlines and VM disposal are backstops, not a claim that `finally` survives SIGKILL.
Only sanitized source/artifact/model identities, measured outcomes and bounded
synthetic observations are retained; no private checkpoints or hidden reasoning.

Primary references reviewed September18,2026:

- [Docker no-network behavior](https://docs.docker.com/engine/network/drivers/none/).
- [Shared container network namespaces](https://docs.docker.com/engine/network/).
- [Ollama CPU container](https://docs.ollama.com/docker) and
  [cloud-disable setting/log](https://docs.ollama.com/faq#how-do-i-disable-ollama-cloud-features).
- [Official model metadata](https://ollama.com/library/qwen3:0.6b).
- [Public standard runner resources/cost](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

## Preserved first attempt and pending correction

[Run 35348679506](https://github.com/ralfyishere/agent-zero-trust/actions/runs/35348679506)
tested source `33ed1ac5f2118c234db432ae8ae57cece20f8ff3`. Its offline build,
333 unit tests, scanner checks and installed wheel/source-distribution checks
passed. The live setup then stopped at **Docker container startup** during the
download stage. No model preload, investigation or network-control case ran.
The retained error did not distinguish service from relay startup or establish
the underlying daemon error. This is **blocked live validation**, not a passing
denial, a model-quality result or evidence of model isolation.

Both cleanup passes reported removal of recorded resources and the two pulled
images. Those original observations are preserved, not rewritten as results of
the correction below. No model was installed on a personal machine.

The local follow-up prepares fixed-role startup progress and finite diagnostic
categories; it omits raw daemon messages, paths and labels. Unknown errors remain
unclassified. These categories assist diagnosis, not prove a root cause. It also
requires a **successful daemon listing** to establish cleanup absence: failed
lookup is not missing-resource evidence. Repeated fallback cleanup uses a new
private client directory, and image cleanup cannot abort remaining evidence
handling. Existing images are not selected for deletion. No broad prune is used.

Cleanup and evidence export are separate `always()` workflow steps. An experiment
failure stays non-success even when cleanup succeeds; a cleanup failure cannot
prevent the evidence-export step from being attempted. The original raw run and
its artifact identities stay separate from any subsequent build.

These follow-up changes have offline regression coverage, **not a new Linux or
live-model result**. The next approved run must establish startup, utility,
matched controls and cleanup under the unchanged restrictions. Nothing here
authorizes a retry or represents a completed protected model integration.

## Second attempt and local-only diagnostic hardening

[Run 35367305211](https://github.com/ralfyishere/agent-zero-trust/actions/runs/35367305211)
tested `3911d6981f0ed81f4f42a313cecc1b0314cb4fb5`. Its 46 scanner checks,
343 unit tests and installed wheel/source-distribution checks passed. The
**download-service start acknowledgement failed** before a model pull request,
preload, network control or either live investigation. The retained 257-byte
stderr identity was unclassified; its hash cannot reconstruct the error or
establish the underlying cause. Zero live-model sessions ran. Both cleanup
passes verified the recorded container, model volume and two newly pulled images
absent through successful daemon listings. The separate cleanup job step passed;
the experiment and its evidence-export step correctly remained non-success.
These are setup/cleanup observations, not a model or isolation result.

The local diagnostic hardening changes this test helper, tests and this document;
the startup-only selection below also updates the test-branch workflow:

- Startup diagnostics use a versioned fixed-vocabulary projection of at most
  8 KiB of daemon stderr. Ordered markers retain known operational layers and
  OS error phrases without copying arbitrary text, paths, recipients, labels or
  arguments. Truncation is explicit. Unmatched content remains unknown; these
  hints are not a root-cause determination or an anonymized raw transcript.
- A failed start receives one read-only, two-second `container inspect` request
  for selected state fields. Status/running/OOM/exit code and the same projection
  of `State.Error` are separate from the start acknowledgement. A current state
  is not proof of no prior execution. No `exec`, restart, container-log request,
  config/environment export or new authority is introduced. Missing/malformed
  state remains unavailable, and collection failure cannot replace the original
  error or prevent cleanup. See [Docker inspect](https://docs.docker.com/reference/cli/docker/container/inspect/)
  and the tested daemon's [state fields](https://github.com/moby/moby/blob/v28.0.4/api/types/container/container.go).
- Generated resource names are recorded **before** create calls. If a create
  reply is lost, cleanup resolves the exact name with matching daemon label/name
  and ID; it does not guess an ID or broadly prune. A ledger-write failure before
  creation prevents that operation. Per-resource ownership verification failure
  skips that removal, records failure, and still attempts other exact resources.
  Successful daemon readback is still required to claim absence.

Offline synthetic regressions exercise these failure paths; they do not run
Docker or a model and do not retroactively strengthen either historical run.
The image family/digests, workload/probe/rubric, permissions, resource limits,
deadline, cloud disable and network restrictions are unchanged. No additional
remote attempt is implied or authorized by this document. Live validation
remains blocked pending a separately authorized run and actual observations.

## Startup-only diagnostic (prepared, not executed)

The next diagnostic reuses the **same download-service configuration**, including
the bridge network, UID/GID, fixed images, tmpfs/volume, entrypoint, resource bounds
and independent container deadlines. It does not weaken a failing restriction or
substitute another backend. Only the two already pinned images and existing build
tools are prepared; **no model-weight download is requested**. The bridge-enabled
setup is not a no-network inference profile. No claim of zero network activity is
made merely because the controller issues no model requests.

The controller follows image preparation → backend check → empty model volume →
service start → fixed relay start → configuration readback → bounded
`GET /api/version` readiness → exact-resource cleanup. The usual relay's fixed
readiness route is reused; no host HTTP listener or task worker is created.
This is a maintainer diagnostic, not a new product command:

```sh
# Only within the reviewed disposable GitHub Linux job, never a personal host.
python -I scripts/test_live_model.py --startup-only --output /new/private-output
```

`azt.model-startup-diagnostic.v1` labels this distinct scope. Its stages record
controller progress; configuration readback is not a tested isolation boundary.
Validated readiness exports only the expected version, not arbitrary service
response text. Model/session counters remain zero and cases remain empty. Exit
0 / status `passed` means **only this startup diagnostic and resource cleanup
completed**, not that a live-model investigation or network control passed.
Failure returns 2, keeps completed stages, and cannot skip cleanup. A readiness
failure after start gets one bounded State readback before removal. An unfamiliar
daemon error can still remain unresolved; the fixed-vocabulary projection is not
a root-cause guarantee. This diagnostic also requires successful readback of
new-image removal for a pass; any retained image is reported and leaves the
diagnostic non-success even though eventual disposable-VM teardown is a backstop.

The workflow retains manual exact-SHA selection, its standard runner and finite
timeout, no secrets/artifact uploads, and separate `always()` cleanup/export.
Offline mocked regressions verify orchestration, no fallthrough into model work,
failure stages, safe output and cleanup failure semantics. They do not establish
that Docker started or the selected image became ready. No further run is
authorized by these documentation or workflow edits.

## Startup diagnostic result and logging correction (not yet retested)

[Run 35374300274](https://github.com/ralfyishere/agent-zero-trust/actions/runs/35374300274)
tested source `dfddf864564542320b6d5fc92bb8bf5e5cf7f718`. The build, 46 scanner
checks, 364 unit tests (no skips), and installed wheel/source-distribution tests
passed. Startup again failed before acknowledgement, relay or readiness. No model
weights, preload or inference were requested. Both cleanup passes verified the
recorded container, volume and two downloaded images absent. This is a failed
startup diagnostic, not live-model or isolation evidence.

The new State readback enabled a precise diagnosis: the harness requested the
Docker **local** logger with `max-file=1`, while leaving compression enabled by
default. Docker28.0.4 [rejects that combination](https://github.com/moby/moby/blob/v28.0.4/daemon/logger/local/config.go#L28)
during logger initialization. The 128-byte error reconstructed from the upstream
logger and task-creation wrappers matches the recorded State.Error SHA-256
`0a42d7da1594e76b554d61efc00051df13e55733b0d0205efb057703e485b3ac` exactly.
This identifies this failure without claiming the earlier discarded errors were
independently recovered or that subsequent startup stages will succeed.

The local correction explicitly sets `compress=false`, retaining `max-file=1`
and `max-size=1m`. This changes neither user/capabilities, filesystem/network
access, model selection, nor resource/lease limits. Log size is a rotation
threshold, **not a hard disk quota**. Offline argument regressions cover all fixed
container roles. A new Linux startup result is still required; none is implied
by the local fix or the successful offline tests. No automatic retry follows.

## Verified startup; separately selected model trial

The subsequent [startup-only run 35376037563](https://github.com/ralfyishere/agent-zero-trust/actions/runs/35376037563)
tested `7179cc5848f105145862ad3526a3684dd5345510` and passed in 44.807 seconds
(diagnostic wall time). All seven startup stages completed; service version
`0.34.2` was validated. Both cleanup passes verified two containers, one empty
model volume and both newly downloaded images absent. The build also passed
46 scanner checks, 365 unit tests without skips, and installed wheel/source-
distribution tests. Earlier failed runs remain separate historical results.

This verifies the logger correction and bridge-network **startup profile**,
not model utility, isolated inference or network prevention. All model counters
were zero. The new selection removes only the workflow's `--startup-only` flag;
the helper, model/image identities, prompts, task fixtures, assertions, isolation,
timeouts and cleanup are unchanged. A finite model trial must establish its own
outcomes and artifacts. Setup failure is not a tested denial; model refusal or
incomplete citation coverage is not successful legitimate-task completion.
