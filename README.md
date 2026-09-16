# AZT · Agent Zero Trust

**Know what changed. Before you delegate.**

Your coding agent reads more than code. A README, setup guide or project
instruction can ask it to run a command—or ask you to share sensitive information.
AZT helps you **see what changed, understand what is being asked, and save a
readable report before deciding what to trust**.

For people building with AI, from their first app to a security review.
Free. Offline after installation. No account, model API or telemetry.

[![PyPI](https://img.shields.io/pypi/v/agent-zero-trust?color=2979ff)](https://pypi.org/project/agent-zero-trust/)
[![CI](https://github.com/ralfyishere/agent-zero-trust/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ralfyishere/agent-zero-trust/actions/workflows/ci.yml)
[![Python](https://img.shields.io/pypi/pyversions/agent-zero-trust?color=2979ff)](https://pypi.org/project/agent-zero-trust/)
[![MIT license](https://img.shields.io/github/license/ralfyishere/agent-zero-trust?color=2979ff)](LICENSE)

[Try it](#scan-your-project) · [Who it's for](#who-its-for) · [See the examples](#reproduce-the-demo) · [Use in GitHub](#bring-the-review-to-a-pull-request) · [Help build it](#help-make-the-next-review-better)

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

## Who it's for

| You are… | You want to know… | Start here |
| --- | --- | --- |
| **A vibe coder or AI-assisted builder** | “This starter project says to run something. What am I agreeing to?” | Scan the project, then read a warning in plain English. |
| **A developer building an agent workflow** | “What changed in the instructions since we last reviewed them?” | Save two scans and compare. Export JSON for your own tooling. |
| **A security reviewer or researcher** | “What supports this finding, and what did the scanner miss?” | Inspect the scope, rule guidance, policy provenance and reproducible cases. |
| **An open-source maintainer** | “Does this PR add instructions our contributors should examine?” | Use the pinned Action to review explicit base/head snapshots. |

**You don't need to speak security.** Start with: *What is this asking me to run,
share or trust?* AZT gives you a place to look, not a decision to obey.

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
  agent-zero-trust==0.1.13
azt --version
azt scan "$AZT_PROJECT"
```

Inspect only projects you are authorized to scan. AZT reads their contents;
it never runs their instructions. Keep this activated terminal for later checks.
Setup runs from the new review directory, not from the inspected project.
`pwd -P` avoids temporary-path symlink aliases on macOS.

Scan exits: **0** passes the selected threshold; **1** has findings meeting it;
**2** means incomplete inspection or an error. A clean scan is not proof of safety.
The default threshold is HIGH: a MEDIUM warning can be worth reviewing even when
the exit code is 0. [What's in the released 0.1.13](https://github.com/ralfyishere/agent-zero-trust/releases/tag/v0.1.13).

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

### 1. A setup instruction changes

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

### 2. A helpful-looking request asks for sensitive information

“Upload your API keys” is a different request from “Send only the Python version;
do not include API keys.” AZT's sensitive-request review distinguishes these
supported examples and explains the possible consequence **without looking for
your actual keys**.

<picture>
  <source media="(prefers-reduced-motion: reduce) and (max-width: 600px)" srcset="https://raw.githubusercontent.com/ralfyishere/agent-zero-trust/5e50626c0b5b6a0576b3c645581cfc04e16cf6dc/assets/landing/sensitive/mobile.png">
  <source media="(prefers-reduced-motion: reduce)" srcset="https://raw.githubusercontent.com/ralfyishere/agent-zero-trust/5e50626c0b5b6a0576b3c645581cfc04e16cf6dc/assets/landing/sensitive/desktop.png">
  <source media="(max-width: 600px)" srcset="https://raw.githubusercontent.com/ralfyishere/agent-zero-trust/5e50626c0b5b6a0576b3c645581cfc04e16cf6dc/assets/landing/sensitive/mobile.gif">
  <img src="https://raw.githubusercontent.com/ralfyishere/agent-zero-trust/5e50626c0b5b6a0576b3c645581cfc04e16cf6dc/assets/landing/sensitive/desktop.gif" alt="Illustrated recorded sensitive-request review: an API-key sharing instruction receives a MEDIUM review finding; a version-only request that excludes sensitive information does not. Maintained guidance and a local report help a human decide what to share. No keys are collected or sent.">
</picture>

[Motion-free view](assets/landing/sensitive/desktop.png) · [Mobile still](assets/landing/sensitive/mobile.png) · [Inputs, actual output and reproduction](assets/landing/sensitive/README.md)

Illustrated CLI results, not a graphical AZT app, live agent or blocked upload.
`request.sensitive_disclosure` is MEDIUM; default HIGH-threshold exit 0 does **not**
mean there is nothing to review. Supported English requests can name shell
history, environment dumps, tokens or private-key material. Those materials
*may* contain sensitive information; AZT does not establish that secrets exist
or were disclosed. [Try the sensitive-request lab](examples/sensitive-request/README.md).

### 3. Keep something you can actually review

Export the scan or comparison as a local HTML report, readable text or JSON.
The image below shows the top of an actual synthetic scan export—not a proposed
dashboard. The [full local record](assets/landing/sensitive/report.html) carries
the scope, finding and maintained guidance together.

<picture>
  <source media="(max-width: 600px)" srcset="https://raw.githubusercontent.com/ralfyishere/agent-zero-trust/5e50626c0b5b6a0576b3c645581cfc04e16cf6dc/assets/landing/sensitive/report-mobile.png">
  <img src="https://raw.githubusercontent.com/ralfyishere/agent-zero-trust/5e50626c0b5b6a0576b3c645581cfc04e16cf6dc/assets/landing/sensitive/report-desktop.png" alt="Top of the actual local HTML export for the synthetic sensitive-request scan, showing the request, uncertainty and next step. The full record includes scope and severity. This is a local file, not a hosted dashboard.">
</picture>

Continue in the quickstart's activated terminal. Save a scan and export it with
new filenames (a scan exit of 1 still produces a report; run without `set -e`):

```sh
azt scan "$AZT_PROJECT" --json > "$AZT_REVIEW/report-scan.json"
azt report --input "$AZT_REVIEW/report-scan.json" \
  --format html --output "$AZT_REVIEW/scan-review.html"
```

Open the file locally. Nothing is uploaded by the export command. Raw excerpts
are omitted by default, but paths and labels can still be sensitive: review a
report before choosing to share it.

## Four steps, one review

| Step | What you get |
| --- | --- |
| **Scan** | “What deserves a closer look?” Known suspicious patterns in project text and supported settings, plus what AZT couldn't inspect. |
| **Compare** | “What changed since my last check?” Changed files, new or remaining findings, and changes to the rules or scope of the review. |
| **Explain** | “Why does this matter, and what can I check next?” Guidance for each rule, including legitimate uses and inspection limits. |
| **Export** | “How do I keep or share this review?” Readable text, a local HTML report or structured JSON. Nothing is uploaded. |

Saved reports are snapshots, not automatic monitoring. Target `.azt-ignore`
requests cannot silently suppress findings. Explicit operator exceptions remain
visible and bound to reviewed content. [Migration and policy details](docs/migration.md).

## When to reach for AZT

- **Before opening an unfamiliar project with a coding agent.** Review project
  instructions, setup text and supported configuration before relying on them.
- **After a template, dependency guide or contributor instruction changes.**
  Compare saved scans to see which observations are new, remain or lost supporting
  evidence. AZT is not a package-vulnerability database or automatic watcher.
- **Before sharing “diagnostics” requested by a project.** Check whether the
  request asks for broad environment/configuration material or narrowly relevant
  information. An “official” label does not authorize disclosure.
- **During a pull-request review.** Keep the instruction change and its review
  context close together, without a bot posting comments or installing target code.
- **When you find a miss or a false alarm.** Turn it into a minimal synthetic
  example others can test, instead of sharing private files or real credentials.

## Bring the review to a pull request

The existing GitHub Action can scan one supplied checkout, or compare two
explicit base/head snapshots using the same scanner. Its job summary shows
inspection scope, findings by severity, the selected threshold and a next step.

In the [recorded synthetic Action check](https://github.com/ralfyishere/agent-zero-trust/actions/runs/35122542431/job/104883609544),
the candidate introduced one MEDIUM sensitive-request finding. The HIGH-threshold
check stayed green—and the finding remained visible. **Green is not approval.**

**[Copy the reviewed, pinned base/head workflow →](docs/github-action.md#explicit-current-base-to-pr-head-comparison)**

Checkout happens separately from inspection. No PR comment bot or extra write
permission is required. Summaries and logs follow your GitHub workflow's
visibility; `job-summary: false` opts out of summary content. An ordinary PR
workflow can itself be edited by a PR: this is review assistance, not an immutable
security gate. [Inputs, outputs and trust boundary](docs/github-action.md).

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

**You can contribute without being a security expert.** We need real questions,
clear explanations and reproducible examples—not just more rules.

| What we need | A useful first contribution |
| --- | --- |
| **First-run feedback** | Try a lab on supported Linux or macOS. Tell us the exact version, step and unexpected result. |
| **Fewer false alarms** | Share a minimal legitimate example and why the request or command is necessary. Use fictional data. |
| **Better coverage** | Pair one missed suspicious instruction with a benign control and a failing test. Keep known limits visible. |
| **Clearer guidance** | Improve one explanation so someone new to AI-assisted coding can make a useful next decision. |
| **Reproducible scrutiny** | Check the published examples, scopes and artifact identities. Corrections are contributions. |

**[Find your first contribution →](docs/community.md)** · [Three scoped coding tasks](docs/change-review-contributions.md)

Please don't paste real keys, full environment dumps, shell history, customer
logs or private repository contents into an issue. Start with inert synthetic
text; use the [security reporting route](SECURITY.md) for sensitive vulnerabilities.

[Contributing guide](CONTRIBUTING.md) · [Open a reproducible issue](https://github.com/ralfyishere/agent-zero-trust/issues) · [Report a false positive](https://github.com/ralfyishere/agent-zero-trust/issues/new?template=false-positive.md) · [Coverage and known misses](COVERAGE.md)

## A few practical questions

<details>
<summary>Does this work with the coding agent I already use?</summary>

The core inspects project files before you rely on them. It does not require an
agent plugin or a model provider. Check the [supported file/format list](docs/supported-agent-files.md):
recognizing a file does not mean every setting or behavior is structurally analyzed.
AZT does not observe your live agent session.

</details>

<details>
<summary>Does a warning mean the project is malicious?</summary>

No. A documented installer may legitimately download code, and a support request
may have a legitimate purpose. A finding explains what deserves review, with
context and limits. Use `azt explain RULE_ID`; inspect the source and give only
the access or diagnostics you actually intend.

</details>

<details>
<summary>Can I use it on a private project? What gets sent?</summary>

Yes, for projects you are authorized to inspect. After installation the local
scan, comparison, explanations and exports work offline without an account or
telemetry. No target instructions are executed. You control where reports are
saved and whether to share them. GitHub Action use is different: its configured
summaries and logs are hosted on GitHub under the workflow's visibility.

</details>

<details>
<summary>Will AZT stop an agent from doing something later?</summary>

Not through this scan-and-review workflow. It inspects snapshots, not every
future action. A hash or report is not an authorization. The opt-in gate and
separate experimental filesystem case have narrower, explicit limits described
[above](#optional-snapshot-gate-and-experimental-access-check).

</details>

Created by **Rafael (Ralph) Peña**, with credit to contributors and upstream work.
The original engine came from [rulebench vet](https://github.com/ralfyishere/rulebench).
[MIT](LICENSE) · [Citation](CITATION.cff) · [Public principles](docs/principles.md).

**Delegate work. Retain control.**
