# agent-zero-trust

[![ci](https://github.com/ralfyishere/agent-zero-trust/actions/workflows/ci.yml/badge.svg)](https://github.com/ralfyishere/agent-zero-trust/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/agent-zero-trust)](https://pypi.org/project/agent-zero-trust/)
[![license](https://img.shields.io/github/license/ralfyishere/agent-zero-trust)](LICENSE)

Before you open an unfamiliar repository in a coding agent, AZT inventories
its instruction and execution surfaces, flags known suspicious patterns,
shows what it could not inspect, and lets you record the snapshot you reviewed.

The repository being inspected cannot silently suppress its own findings.
Operator exceptions come from an explicit external policy, name an exact rule
and path, and apply only to the reviewed file's SHA-256 digest. Suppressed
findings remain visible with their reasons and policy provenance.

This checkout prepares **0.1.9, unreleased**. The stable capability remains a
deterministic, offline scanner with no model or runtime dependencies.
Linux and macOS with Python 3.9+ are supported; Windows is currently unsupported.
The optional admission hook is a workflow aid. A new experimental safety pack
compares explicit mount configurations and proposes repairs. Its Docker execution
path is implemented but **runtime integration remains unverified**.

## Try it without installing

From this checkout:

```sh
python3 azt.py scan corpus/benign-repo
python3 azt.py scan corpus/malicious-markdown
```

The benign fixture exits 0. The malicious fixture exits 1 and includes
`net.pipe_shell` at HIGH severity. These are static detections: no fixture
command is executed and no destination in the corpus is contacted.

Run the reproducible local evidence demo:

```sh
python3 scripts/containmentbench.py
```

It uses temporary synthetic inputs and reports intake/admission outcomes
separately from runtime cases that have not been run. This project benchmark
is not a certification or a model safety score. See [evidence](docs/evidence.md).

To install the candidate checkout in an isolated Python environment:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/azt scan /path/to/unfamiliar-repo --json
```

Installation may need network access or cached build dependencies. Scanning
does not. Build and install AZT's trusted checkout; never install the repository
you are inspecting merely to scan it. The published PyPI package can lag this
unreleased checkout.

With an already-built local wheel, installation also works offline:
`.venv/bin/python -m pip install --no-index --no-deps dist/agent_zero_trust-0.1.9-py3-none-any.whl`.
See [packaging instructions](CONTRIBUTING.md) to create that wheel.

## Read the result

`azt scan PATH --json` emits one JSON document. It includes the inventory,
active findings, suppressed findings, target-requested exceptions, policy
provenance, input manifest, inspected/skipped paths and inspection errors.

| Exit | Meaning |
| --- | --- |
| 0 | Complete within the declared scope; no active finding meets the threshold |
| 1 | Complete inspection; an active finding meets the threshold |
| 2 | Incomplete inspection, invalid input/policy, or another operational error |

The default threshold is HIGH. Use `--fail-on medium` or `--fail-on any`
for stricter review. A MEDIUM finding can therefore coexist with exit 0.
Read the scope and findings; a passing result is not a safety guarantee.

Built-in dependency, VCS and build exclusions remain visible. Unsupported
file extensions may be hashed without content analysis. Relevant unreadable
files, symlinks, special files, malformed supported JSON, unsupported text
encodings and exceeded work limits prevent admission. Raw excerpts are omitted
from reports to avoid copying credentials or terminal-control sequences into logs.

The scanner inventories agent instruction files, skills, hooks, MCP settings,
package lifecycle scripts and other automation surfaces. Coverage varies by
format: [supported files and analysis depth](docs/supported-agent-files.md),
[detection and known misses](COVERAGE.md).

## Optional snapshot admission

From an operator terminal, before starting the coding agent:

```sh
azt install-hook /path/to/repo --state-dir /absolute/operator/azt-state
azt scan /path/to/repo --gate --state-dir /absolute/operator/azt-state
azt gate-check /path/to/repo --state-dir /absolute/operator/azt-state --json
```

Use an existing parent directory outside the target. AZT creates the state
directory with mode 0700; existing state must already have that mode and belong
to the operator. Paths must not traverse symlinks. If you use `--policy` or a
different `--fail-on`, use the same values at installation, admission and checking.

The receipt authenticates an admitted snapshot with HMAC-SHA256 and binds the
workspace identity, content manifest, scope, scanner code/version, effective
policy, threshold and expiry. Default lifetime is 60 minutes; the maximum is
24 hours. Content hashes and HMAC authentication are different properties.

An in-scope edit invalidates the current check, including an ordinary authorized
edit. Review the changed tree and repeat `scan --gate` from the operator terminal.
This snapshot lifecycle can interrupt editing; it is not continuous enforcement.

The generated Claude Code hook configuration and local command lifecycle are
tested. End-to-end operation inside Claude Code is not verified. Other settings
or agent behavior may disable or bypass hooks. A hostile process running as the
operator can change the hook or read the HMAC key, so it can defeat this workflow
gate. An external directory alone does not isolate authority.

Legacy `.claude/.azt-intake-pass` files are never accepted. See the
[migration guide](docs/migration.md) and [threat model](docs/threat-model.md).

## CI

The action defaults to the scanner in the action checkout, including unpublished
candidate changes. Pin an owner-reviewed full commit SHA in production.
The optional `version` input selects an explicit PyPI override; an empty value
uses the action checkout. Inputs are passed as data, not interpolated shell code.

Our CI checks corpus regressions and installs the built candidate wheel in a
clean environment. Its repository self-scan publishes unfiltered findings for
review; it is not an admission check. Candidate-controlled fixture metadata or
ignore files do not authorize suppressions. See [release readiness](docs/release-readiness.md)
for the trusted-policy and owner-side review requirements.

## Review a changed agent read path

For a developer reviewing an agent workspace configuration, AZT makes spotting
and repairing a newly exposed directory easier by comparing literal bind mounts
and generating a digest-bound diff—work otherwise done by tracing mount paths
and editing configuration manually. This is declared-access analysis, not proof
of effective access on your machine.

```sh
python3 azt.py safety compare --baseline packs/AZT-FS-001/v1/baseline.compose.json --candidate packs/AZT-FS-001/v1/candidate.compose.json --protected-source ./synthetic-vault --output review-01 --json
```

This identifies the added read-only credential mount and proposes removing it,
preserving unrelated settings. Original files stay unchanged. Outputs contain
the comparison, `repair.diff`, `proposal.json` and `repaired.compose.json` for
review. Repeat with a new output name; no hook or admission receipt is required.
Only one explicit standalone Compose JSON subset is supported. Unsupported
layers fail rather than producing an all-clear.

[AZT-FS-001 v1](packs/AZT-FS-001/v1/README.md) also provides a synthetic
baseline/misconfigured/repaired execution check with a canary challenge and
legitimate coding-task control. It requires an approved native Linux Docker
environment. Docker supplies isolation; AZT adds configuration interpretation,
synthetic orchestration, repair and evidence. **Zero container trials have run
in this development environment.** A missing backend is blocked, not a passed
denial. There is no verified cloud coding-agent integration.

## Runtime status

`azt doctor --json` is a read-only prerequisite report and currently exits 2
on every platform. It reports the historical bubblewrap proposal, not Docker
pack availability. The pack performs its own real prerequisites check when
explicitly invoked with `safety check`. There is no general `azt run`,
`inspect` or `kill`, and no completed runtime isolation trial. Current support is in
[runtime status](docs/runtime.md). An offline fixture is not a cloud coding-agent integration.

## Contribute

Useful first contributions are a minimal missed detection, a false-positive
regression, a supported-format analysis test, or an independently reproduced
failure. Include the command, version and actual output; use synthetic data.
See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

AZT is maintained and created by Rafael (Ralph) Peña. Credit also belongs to
contributors who report, reproduce and repair failures. The scanner engine
originated in [rulebench](https://github.com/ralfyishere/rulebench).
Related projects retain separate roles:
[rules-with-receipts](https://github.com/ralfyishere/rules-with-receipts)
for operating discipline, [rulebench](https://github.com/ralfyishere/rulebench)
for behavioral testing, and [agent-failure-modes](https://github.com/ralfyishere/agent-failure-modes)
for failure taxonomy. AZT does not vendor another copy of their engines.
[Piénsalo](https://github.com/ralfyishere/piensalo) is optional, separate
context/continuity tooling; see the [manual checkpoint note](docs/optional-continuity.md).

MIT — see [LICENSE](LICENSE). Local scanning, policy and evidence require no
account, telemetry or company service. Optional future organization services
can build on these local interfaces without charging for essential protection.
For attribution, see [CITATION.cff](CITATION.cff).
