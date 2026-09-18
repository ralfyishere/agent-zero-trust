# One disposable live-model validation — test branch only

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
