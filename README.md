# AZT · Agent Zero Trust

**Know what changed. Before you delegate.**

Project instructions can shape what your AI coding agent does—even when you
didn't write them. AZT helps you **spot changes, understand warnings and keep
a review**. Free, offline and open source.

[![PyPI](https://img.shields.io/pypi/v/agent-zero-trust?color=2979ff)](https://pypi.org/project/agent-zero-trust/)
[![CI](https://github.com/ralfyishere/agent-zero-trust/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ralfyishere/agent-zero-trust/actions/workflows/ci.yml)
[![Python](https://img.shields.io/pypi/pyversions/agent-zero-trust?color=2979ff)](https://pypi.org/project/agent-zero-trust/)
[![MIT license](https://img.shields.io/github/license/ralfyishere/agent-zero-trust?color=2979ff)](LICENSE)

[Scan your project](#scan-your-project) · [Reproduce the demo](#reproduce-the-demo) · [Read the evidence](#evidence-and-scope)

<picture>
  <source media="(prefers-reduced-motion: reduce) and (max-width: 600px)" srcset="https://raw.githubusercontent.com/ralfyishere/agent-zero-trust/7e3abdfb7a7c435fa7b66331ddf187804b23369d/assets/landing/sequence/mobile.png">
  <source media="(prefers-reduced-motion: reduce)" srcset="https://raw.githubusercontent.com/ralfyishere/agent-zero-trust/7e3abdfb7a7c435fa7b66331ddf187804b23369d/assets/landing/sequence/desktop.png">
  <source media="(max-width: 600px)" srcset="https://raw.githubusercontent.com/ralfyishere/agent-zero-trust/7e3abdfb7a7c435fa7b66331ddf187804b23369d/assets/landing/sequence/mobile.gif">
  <img src="https://raw.githubusercontent.com/ralfyishere/agent-zero-trust/7e3abdfb7a7c435fa7b66331ddf187804b23369d/assets/landing/sequence/desktop.gif" alt="Illustrated recorded CLI workflow, not an AZT graphical interface: an AGENTS.md instruction changes in place, is highlighted, and produces two findings. Guidance says to review the source before using it; the review can be exported locally. The target instruction is never executed.">
</picture>

[Animation](https://raw.githubusercontent.com/ralfyishere/agent-zero-trust/7e3abdfb7a7c435fa7b66331ddf187804b23369d/assets/landing/sequence/desktop.gif) · [Still image](assets/landing/sequence/desktop.png) · [Mobile still](assets/landing/sequence/mobile.png) · [Transcript and reproduction](examples/change-review/README.md)

Illustrated demonstration of the [recorded CLI workflow](assets/landing/sequence/README.md),
not a shipped graphical interface or live-agent test. Repeats every 22 seconds with a reset;
pacing is editorial. No target instruction is executed.

> I use AI to build, and I take its risks seriously. AZT is my contribution
> to helping people use it with less blind trust.
> — [Rafael (Ralph) Peña · Why I'm building this](#why-i-built-azt)

<a id="run-a-scan"></a>

## Scan your project

Python 3.9+ on Linux or macOS; native Windows is unsupported. Installation
downloads the released package. Scanning and change review then run offline:
no account, model calls, telemetry, Docker or hook needed.

Start in the specific project directory you want to inspect. The temporary
environment and reports belong **outside** that directory; don't scan your home,
whole disk or a parent directory containing the temporary review folder.

```sh
AZT_PROJECT=$(pwd -P)
AZT_REVIEW=$(mktemp -d)
AZT_REVIEW=$(cd "$AZT_REVIEW" && pwd -P)
cd "$AZT_REVIEW"
python3 -m venv "$AZT_REVIEW/venv"
. "$AZT_REVIEW/venv/bin/activate"
python -m pip --isolated install \
  --index-url https://pypi.org/simple --no-deps \
  agent-zero-trust==0.1.12
azt --version
azt scan "$AZT_PROJECT"
```

Inspect only projects you are authorized to scan. AZT reads their contents;
it never runs their instructions. Keep this activated terminal for later checks.
Setup runs from the new review directory, not from the inspected project.
`pwd -P` avoids temporary-path symlink aliases on macOS.

Scan exits: **0** passes the selected threshold; **1** has findings meeting it;
**2** means incomplete inspection or an error. A clean scan is not proof of safety.

<details>
<summary>Save a baseline, then compare after you edit</summary>

Before editing, save a scan outside the project:

```sh
azt scan "$AZT_PROJECT" --json > "$AZT_REVIEW/before.json"
```

After making your intended project changes, scan again, compare and export:
use a rule ID from your findings with `azt explain` (`net.pipe_shell` is an example).

```sh
azt scan "$AZT_PROJECT" --json > "$AZT_REVIEW/after.json"
azt changes --before "$AZT_REVIEW/before.json" \
  --after "$AZT_REVIEW/after.json"
azt explain net.pipe_shell
azt changes --before "$AZT_REVIEW/before.json" \
  --after "$AZT_REVIEW/after.json" \
  --format html --output "$AZT_REVIEW/review.html"
```

Run interactively, without `set -e`. Open `review.html` locally. Use a fresh
output filename for each export. Comparison exits **0** when it completes—even
with changes or reduced comparability—and **2** for invalid input/output. It
does not approve the change. [JSON/text exports and advanced syntax](docs/change-review.md#guidance-and-exports).

</details>

<a id="see-change-review"></a>

## Reproduce the demo

**[Sensitive-request review](examples/sensitive-request/README.md)** helps you
spot helpful-looking instructions asking for shell history, environment
dumps or authentication material. Use the same scan → compare → explain → export
workflow; AZT never collects the requested diagnostics or sends them.

Using GitHub? The [source-candidate Action](docs/github-action.md) adds a concise
review summary and optional explicit base/head comparison. A green HIGH-threshold
job can still contain MEDIUM findings; it is not an approval.

**This instruction asks your agent to download and run a remote script.**
**Review the source before using it.** That is the reason for review—not a
claim that the source is malicious.

[Run the four-case synthetic lab](examples/change-review/README.md#install-and-reproduce-version-0111)
for the complete setup and scan → compare → explain → export commands. It uses
inert example text, not your project or real credentials; the suspicious
instruction is never executed. The lab keeps its environment and reports
outside its fixture trees.

The illustrated `AGENTS.md` edit has **two new findings**: `net.pipe_shell`
(HIGH: download piped directly into an interpreter) and `net.fetch_unknown`
(MEDIUM: a download host outside the rule's allowlist). The benign edit has
**none**; incomplete inspection retains **two unresolved observations**.
The graphic uses the recorded **0.1.11 candidate** at
[`0296face`](https://github.com/ralfyishere/agent-zero-trust/commit/0296facec2565668386c3c0d5dbacb734e6241e3),
not new execution evidence. [Transcript](examples/change-review/transcript.txt) · [Visual provenance](assets/landing/sequence/README.md).

## Four steps, one review

| Step | What you get |
| --- | --- |
| **Scan** | “What deserves a closer look?” Known suspicious patterns in project text and supported settings, plus what AZT couldn't inspect. |
| **Compare** | “What changed since my last check?” Changed files, new or remaining findings, and changes to the rules or scope of the review. |
| **Explain** | “Why does this matter, and what can I check next?” Guidance for each rule, including legitimate uses and inspection limits. |
| **Export** | “How do I keep or share this review?” Readable text, a local HTML report or structured JSON. Nothing is uploaded. |

**New to security or vibe coding?** Start with the example above; you don't need
to recognize a rule ID to ask what changed. **Building an agent workflow?**
Use saved JSON reports and the [CLI contract](docs/change-review.md); a report
is information, not permission for an agent to approve itself. **Working in
cybersecurity?** Review the [matching method and evidence](evidence/change-review/README.md),
policy provenance and [known misses](COVERAGE.md).

Saved reports are snapshots, not automatic monitoring. Target `.azt-ignore`
requests cannot silently suppress findings. Explicit operator exceptions remain
visible and bound to reviewed content. [Migration and policy details](docs/migration.md).

## Why I built AZT

AI risk isn't only a conversation about the distant future. In its
[August 26, 2026 incident account](https://openai.com/index/hugging-face-incident-and-the-road-ahead/),
OpenAI described models crossing technical boundaries during internal
cybersecurity evaluations with reduced safeguards. That is a documented incident
in a particular setting—not evidence that AZT would have prevented it.

I started AZT in July with a smaller, practical insight: a repository—your
project's files—is an **instruction environment**, not just code. The broader
AI-risk discussion pushed me to strengthen that existing work, question AZT's
own assumptions, and make its checks and evidence easier for others to inspect.

I want people to benefit from AI without giving it blind trust. This is my
contribution to that effort: a free tool for reviewing what could influence a
coding agent, with open code and examples people can challenge and improve.
It doesn't solve the whole problem. It gives us one useful place to start.

[AI Is Getting More Powerful. Blind Trust Is Not a Safety Strategy.](docs/a-readme-is-not-a-permission-slip.md)

## Evidence and scope

“No longer observed” is **not** “proven fixed.” Missing inputs, incomplete
inspection or changed rules can limit comparison. Reports and their hashes
are not authenticated evidence. Exported excerpts are omitted, but paths and
labels can still be sensitive: review before sharing.

AZT detects known patterns, not every prompt injection or cross-file intention.
Recognized files are not necessarily fully parsed. No live-agent integration,
continuous authorization or general containment is provided.

[Change-review evidence and methodology](evidence/change-review/README.md) · [Rule guidance and matching](docs/change-review.md) · [Coverage and known misses](COVERAGE.md) · [Supported files](docs/supported-agent-files.md) · [Release notes](CHANGELOG.md)

### Optional: snapshot gate and experimental access check

The [snapshot gate](docs/migration.md) is an opt-in workflow aid; edits require
operator re-admission. A same-user hook or signing key is not a sandbox.

**AZT-FS-001** separately compares selected Compose JSON mounts and proposes a
reviewable repair. Its historical Docker/Linux evidence is a synthetic
trusted-probe experiment—not a live-agent evaluation or general containment.
Docker supplies isolation. A passing misconfigured phase demonstrates intentional
exposure, not approval of an unsafe configuration.
[Exact evidence](evidence/fs001-0.1.9/README.md) · [Prerequisites and reproduction](docs/reproduce-fs001.md).

## Help make the next review better

Bring a minimal synthetic example, not private repository content. The small
[contributor queue](docs/change-review-contributions.md) has three testable tasks:
reproduce a comparison regression, clarify one rule's legitimate context, or
repeat the four-case lab on another supported Linux installation.

[Contribute](CONTRIBUTING.md) · [Report a security issue](SECURITY.md) · [Open a reproducible issue](https://github.com/ralfyishere/agent-zero-trust/issues) · [Use the Action](docs/demo.md#github-action)

Created by **Rafael (Ralph) Peña**, with credit to contributors and upstream work.
The original engine came from [rulebench vet](https://github.com/ralfyishere/rulebench).
[MIT](LICENSE) · [Citation](CITATION.cff) · [Public principles](docs/principles.md).

**Delegate work. Retain control.**
