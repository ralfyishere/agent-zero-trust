# Reproduce the experimental filesystem regression

Use a trusted checkout at the verified code SHA linked in [the evidence index](../evidence/README.md).
Do not build the unfamiliar repository you intend to scan. AZT0.1.9 is an
unreleased candidate; PyPI may contain an older version.

## First offline result (Python3.9+, Linux/macOS)

```sh
python3 azt.py scan corpus/benign-repo --json
python3 azt.py safety compare --baseline packs/AZT-FS-001/v1/baseline.compose.json --candidate packs/AZT-FS-001/v1/candidate.compose.json --protected-source ./synthetic-vault --output review-01 --json
```

Both exit0. The first is a complete benign static scan; the second identifies
one added read-only mount and emits a review-only diff removing it. Neither
executes repository code. Use a new output name for each check, under a directory
you own that is not group/world writable and has no symlink components. An
already-correct baseline compared with itself needs no repair. Unsupported
layers are errors, not all-clears. No hook, account, credentials or model needed.

## Build and test a clean candidate

Run in a clean trusted checkout, not a dirty directory with unrelated files.
Explicit setup downloads (skip if already provisioned):

```sh
python3 -m venv .venv-build
.venv-build/bin/python -m pip --isolated --no-cache-dir install --only-binary=:all: --no-deps setuptools==83.0.0 wheel==0.47.0 packaging==26.0
.venv-build/bin/python -c 'import setuptools.build_meta as b; b.build_wheel("dist"); b.build_sdist("dist")'
python3 scripts/test_artifact.py dist
python3 -m venv .venv
.venv/bin/python -m pip install --no-index --no-deps dist/agent_zero_trust-0.1.9-py3-none-any.whl
.venv/bin/azt --version
.venv/bin/azt scan corpus/benign-repo --json
```

Use a fresh dist directory (one wheel and one sdist). Artifact tests create their
own clean environment and verify installed imports, examples, failures and the
extracted sdist. The scanner itself has only standard-library dependencies.

## Optional real execution (native Linux only)

Requires an already authorized local Docker Engine25+ Unix daemon, cgroupv2
CPU/memory/swap/pids controls, builtin seccomp and linux/amd64. Docker access
is powerful host authority; do not grant it to an untrusted agent or change
permissions to make this command work. No Docker Desktop/macOS support claimed.
Python3.12 and `/usr/bin/tar` in the approved image supply the fixed workload and
result export. Missing tools fail; no installation or uncontained fallback.

Explicit image preparation (a network download, outside the safety check):

```sh
docker --host unix:///var/run/docker.sock pull --platform linux/amd64 docker.io/library/python@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea
python3 scripts/test_safety_integration.py --case canonical --wheel dist/agent_zero_trust-0.1.9-py3-none-any.whl --image docker.io/library/python@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea --output canonical-review-01
python3 scripts/test_safety_integration.py --case variant --wheel dist/agent_zero_trust-0.1.9-py3-none-any.whl --image docker.io/library/python@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea --output variant-review-01
```

The image digest belongs to official Python3.12-slim. The helper resolves and
executes by immutable local image ID, never pulls. Each case creates fresh
synthetic resources. Inspect evidence.json/artifact.json: selected canary read
unavailable/exposed/unavailable; exact edited-file and coding-task verification;
fixture integrity and cleanup. A misconfigured phase PASS means the deliberate
exposure was demonstrated, not permission to deploy that configuration.

This is a trusted bundled probe, not arbitrary user code or a live cloud agent.
Docker supplies isolation; AZT interprets declared mounts, proposes the narrow
repair, substitutes synthetic resources, retests and preserves inspectable
evidence. Only this read property is exercised. Network, exhaustion, descendant
stop, controller death and cross-session tests remain outside this release.
