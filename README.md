# Agent Zero Trust

![Agent Zero Trust. Inspect before you delegate. Offline repository intake for AI coding agents.](https://raw.githubusercontent.com/ralfyishere/agent-zero-trust/main/assets/launch/hero.png)

Open-source repository intake for AI coding agents, with experimental access-check and repair tools.

A repo is no longer just code. It is an instruction environment. Before you open
an unfamiliar repository in a coding agent, inspect the instructions, hooks,
configuration and setup commands that could influence it.

AZT is a deterministic, offline scanner. It flags known suspicious patterns,
reports inspection gaps, and keeps the target from silently choosing its own
exceptions. No model, account, telemetry or runtime dependency is required.

[Released package](https://pypi.org/project/agent-zero-trust/) · [CI](https://github.com/ralfyishere/agent-zero-trust/actions/workflows/ci.yml) · [MIT](https://github.com/ralfyishere/agent-zero-trust/blob/main/LICENSE)

Released: **0.1.10**. This branch prepares **0.1.11**, not yet published.

## Install and scan

Python 3.9+ on Linux or macOS. Installation downloads the package; scanning runs
offline and does not execute the target's code. Native Windows is unsupported.

```sh
python3 -m venv .venv-azt
.venv-azt/bin/python -m pip --isolated install --index-url https://pypi.org/simple --no-deps agent-zero-trust
.venv-azt/bin/azt --version
.venv-azt/bin/azt scan /path/to/authorized-repository
```

Use a repository you are authorized to inspect. Add `--json` for scope, findings,
manifest and policy provenance. Exit codes: **0** passes the selected threshold;
**1** has findings that meet it; **2** means incomplete inspection or an error.
A clean scan is not proof of safety. You do not need to install a hook.

## New in the 0.1.11 candidate: what changed?

For a developer returning to an unfamiliar repository, AZT compares two saved
scans so changes to instructions, configuration, findings and inspection scope
are visible together. Review the finding's offline guidance and export a local
report instead of manually comparing two long scan outputs.

```sh
azt scan /path/to/project --json > before.json
# Make your authorized project change; keep reports outside the project.
azt scan /path/to/project --json > after.json
azt changes --before before.json --after after.json
azt explain net.pipe_shell
azt changes --before before.json --after after.json --format html --output review.html
```

Scan exits 1 and 2 still mean findings and incomplete inspection. Save and review
those reports, too. Comparison exits 0 when it completes, even if it finds changes
or reduced comparability; 2 means invalid input/output. It never approves changes.
“No longer observed” is not “proven fixed.” There is no automatic repair or watcher.

[Try the four-case offline lab](https://github.com/ralfyishere/agent-zero-trust/blob/feat/public-change-review/examples/change-review/README.md), including a
benign edit and an incomplete comparison. Use the candidate installation there;
the released 0.1.10 package does not have these commands. No Docker or hook needed.

| Capability | Support |
| --- | --- |
| Repository intake, visible exceptions and inspection gaps | Existing deterministic scanner; Python 3.9+, Linux/macOS |
| Saved scan comparison, rule guidance, static JSON/text/HTML export | 0.1.11 candidate; bounded scan-v1 inputs; offline |
| Optional FS-001 configuration check/repair/retest | Existing experimental synthetic Docker/Linux case; historical evidence only |
| General agent containment, continuous authorization, live model integration | Not provided |

## See a real scan

![Recorded PyPI 0.1.9 scan: a synthetic pipe-to-shell instruction is flagged, and a target-owned ignore request does not suppress it.](https://raw.githubusercontent.com/ralfyishere/agent-zero-trust/main/assets/launch/scan.gif)

This is captured output from the published 0.1.9 wheel, scanning inert synthetic
text. It never fetched or ran the command. Selected lines:

```text
FINDINGS: 1 HIGH, 1 MEDIUM
  [HIGH  ] net.pipe_shell  README.md:1
EXCEPTIONS: 1 target requests (not applied); 0 trusted suppressed findings
DECISION: deny
```

[Run the tiny demo, read the transcript, or view the static frame](https://github.com/ralfyishere/agent-zero-trust/blob/main/docs/demo.md).

## What changed in 0.1.9

The scanner's own trust boundary needed scrutiny, too. Target `.azt-ignore`
content no longer suppresses findings. Operator exceptions must come from an
explicit external policy and name an exact rule, path, content hash and reason.
Suppressed findings stay visible. Incomplete inspection cannot quietly pass.

An optional workflow gate now authenticates a receipt for a specific reviewed
snapshot. Edits can invalidate that receipt and require operator re-admission.
The hook and a key accessible to the same user do **not** contain hostile code.

[Upgrade and migration](https://github.com/ralfyishere/agent-zero-trust/blob/main/docs/migration.md)
 · [Release notes](https://github.com/ralfyishere/agent-zero-trust/blob/main/CHANGELOG.md)
 · [Why I’m strengthening Agent Zero Trust](https://github.com/ralfyishere/agent-zero-trust/blob/main/docs/a-readme-is-not-a-permission-slip.md)

## Optional: test one access change and its repair

The experimental **AZT-FS-001** pack compares an explicit, supported subset of
Compose JSON bind mounts. It identifies selected added read access and proposes
a minimal, digest-bound configuration diff for review. Static comparison needs
no Docker and does not execute the supplied configuration.

On supported native Linux Docker hosts, a bundled trusted probe tests the change
using fresh synthetic resources, applies the proposed repair to its disposable
test plan, and retests while a small coding task runs. It does not test your real
credentials or launch a live coding agent. Docker supplies the isolation; AZT
adds configuration interpretation, repair, orchestration and reviewable evidence.

![Recorded synthetic FS-001 test: baseline access unavailable, deliberate exposure demonstrated, repaired access unavailable; legitimate task verified in each phase.](https://raw.githubusercontent.com/ralfyishere/agent-zero-trust/main/assets/launch/fs001.png)

The accepted record covers **two configuration inputs for one case**, three
phases each. Both retained original fixtures and completed cleanup. A passing
misconfigured phase means the test demonstrated intentional exposure, not that
the unsafe configuration is approved for deployment. Denial is credited only
with the positive control and legitimate-task checks.

[Exact evidence and limitations](https://github.com/ralfyishere/agent-zero-trust/blob/main/evidence/fs001-0.1.9/README.md)
 · [Offline comparison and optional Linux reproduction](https://github.com/ralfyishere/agent-zero-trust/blob/main/docs/reproduce-fs001.md)

## Know the boundary

The scanner detects known shapes, not every prompt injection or cross-file
intention. Inventoried formats are not necessarily fully parsed. The public
known-miss ledger predates this update and remains part of the project.
FS-001 is a selected trusted-probe check, not universal containment, a model
evaluation or an independent security audit. Other execution-boundary scenarios
remain untested. The legacy `doctor` command concerns a deferred general runtime
proposal, not FS-001's Docker prerequisite check.

[Coverage and known misses](https://github.com/ralfyishere/agent-zero-trust/blob/main/COVERAGE.md)
 · [Supported files](https://github.com/ralfyishere/agent-zero-trust/blob/main/docs/supported-agent-files.md)
 · [Threat model](https://github.com/ralfyishere/agent-zero-trust/blob/main/docs/threat-model.md)
 · [Security reporting](https://github.com/ralfyishere/agent-zero-trust/blob/main/SECURITY.md)

## Help make it useful

Try an authorized scan. Report a missed detection, false positive or confusing
result with a minimal synthetic fixture and the command you ran. Reproduce the
documented case before generalizing its result.

[Contribute](https://github.com/ralfyishere/agent-zero-trust/blob/main/CONTRIBUTING.md)
 · [Open an issue](https://github.com/ralfyishere/agent-zero-trust/issues)
 · [Use the Action](https://github.com/ralfyishere/agent-zero-trust/blob/main/docs/demo.md#github-action)
 · [Public principles](https://github.com/ralfyishere/agent-zero-trust/blob/main/docs/principles.md)

Created by Rafael (Ralph) Peña, with credit to contributors and upstream work.
The original engine came from [rulebench vet](https://github.com/ralfyishere/rulebench).
[MIT](https://github.com/ralfyishere/agent-zero-trust/blob/main/LICENSE).
[Citation metadata](https://github.com/ralfyishere/agent-zero-trust/blob/main/CITATION.cff).

**Delegate work. Retain control.**
