# Scanner-hardening release review

Status clarification, September 15, 2026: this historical 0.1.8 work was
incorporated into published 0.1.9, not released independently. Statements below
describe the earlier handoff, not today's publication state.

Historical 0.1.8 handoff: this preserves the prior scanner milestone, not current
0.1.9 artifact results. See [safety release readiness](safety-release-readiness.md).

Recommendation: **ready for the scanner-hardening release only**, subject to
owner review and hosted CI. Version 0.1.8 is an unreleased candidate. No tag,
commit, PR, package publication, repository setting or announcement was created
by this assignment. The branch is `fix/trusted-intake-evidence`.

For a developer opening an unfamiliar repository in an AI coding agent, AZT
makes initial intake easier to review by inventorying known influence surfaces,
reporting deterministic findings and inspection gaps, and binding explicit
operator exceptions and admission receipts to inspected content, which they
would otherwise have to enumerate, audit and track manually.

That is a workflow and verification improvement. No upstream sandbox protection
is attributed to AZT: no execution backend runs in this candidate. Planned Linux
bubblewrap namespaces and systemd/cgroup controls belong to those upstream
projects and the kernel. AZT would add a reviewed profile, intake, lifecycle and
observable evidence only after the [runtime acceptance tests](runtime.md) work.

## Baseline

Inspected clean `main` at `60dbd75f2e66437fb6d0043c505e8053cac24969`.
Package and action default: 0.1.7; Python requirement: >=3.9; CI: 3.9/3.12.
Public CLI: `scan`, `install-hook`, `gate-check`, help/version.
Release workflow built on release publication or manual dispatch and published
through the `pypi` environment with OIDC only for the release event.

Baseline `python3 test_azt.py` passed all 45 checks; self-scan exited 0 with
zero findings because the repository's wildcard ignore file hid its own content.
Temporary reproductions established wildcard suppression (zero HIGH findings),
valid-looking forged JSON accepted (exit 0), and malformed MCP config silently
passing (exit 0). Those original checks did not establish a secure gate.

## Compact implementation checklist

| State | Item | Evidence or reason |
| --- | --- | --- |
| Implemented / verified | Target policy has no authority; exact external exceptions retain findings | Intake regressions and synthetic benchmark |
| Implemented / verified | Authenticated snapshot receipts, expiry and re-admission | Forgery, replay, edit/add/remove/mode, policy, engine and scope tests |
| Implemented / verified | Bounded safe file reads and visible incompleteness | Symlink/hardlink/FIFO, malformed JSON, encoding/size/depth/work-limit tests |
| Implemented / verified | JSON and package CLI behavior | Installed wheel, exact exits, deterministic output, action argument tests |
| Implemented / verified | Source benchmark and schema exports | Actual generated evidence; zero runtime claims |
| Implemented / verified locally | Generated workflow hook command lifecycle | Direct shell command test; disabled local/project hooks rejected |
| Implemented / unverified in application | Claude hook integration | No coding-agent application session run |
| Implemented / verified locally | Read-only runtime doctor | Darwin unsupported, non-success; Linux branches mocked |
| Blocked | Runtime launch, stop, limits, exported workload results and A/B/C comparison | No provided Linux boundary test environment; no launcher shipped |
| Deferred | Native Windows safe traversal | Requires handle-based implementation and tests; no unsafe fallback |
| Deferred | Devcontainer/TOML/YAML structural coverage, DNS-table refinement | Published coverage ledger and contributor tasks |
| Owner action | Hosted CI, actual release, reporting/settings review | No external publication or configuration authority exercised |

## Verification and reproducibility

Run from the trusted checkout:

```sh
python3 test_azt.py
python3 -m unittest discover -s tests -v
python3 scripts/containmentbench.py
python3 -m build
python3 scripts/test_artifact.py dist
python3 scripts/containmentbench.py --wheel dist/agent_zero_trust-0.1.8-py3-none-any.whl --output /tmp/azt-release-evidence-new
git diff --check
```

Local development platform: Darwin 25.6.0. Python 3.9.6 and 3.14.6 passed all
45 corpus/unit checks and all 38 new unittest cases (29 intake, 9 prerequisite
diagnostics). The final unittest runs took 11.405 and 5.359 seconds respectively.
Installed-wheel smoke checks also passed on Python 3.11; six action argument
cases passed on each interpreter. Source-distribution testing caught a missing
top-level test/action file; the manifest now includes them and artifact CI
extracts and runs the source corpus before testing the wheel.
Exact final counts, elapsed time and source/artifact digests are recorded with
the [synthetic evidence package](../evidence/README.md). The benchmark's disabled
runtime cases are not counted as passing containment tests.

The installed-wheel reproduction passed 11/11 checks in 2.3528 seconds, including
forgery of an existing authenticated receipt, with zero runtime trials and eight
runtime scenarios not run. The legitimate fixed arithmetic program returned
`5 0`; the evaluator confirmed the original synthetic source was unchanged.

The local `build` frontend was unavailable and its dependency installation
failed due to unavailable sandbox DNS. The installed Python 3.11 build backend
was available (setuptools 83.0.0, wheel 0.47.0), so the declared backend was
executed directly to build both artifacts offline:

```sh
python3.11 -c 'import setuptools.build_meta as b; b.build_sdist("dist"); b.build_wheel("dist")'
```

Wheel installation tests use `--no-index --no-deps` in a clean temporary venv,
check installed import location, help/version, repeated JSON, benign exit 0,
malicious exit 1 with `net.pipe_shell`, and invalid target exit 2 with JSON.
Action shell tests pass shell metacharacters as data and reject malformed
versions/severities. These do not pretend the GitHub service actually ran the
workflow. Existing setuptools license-metadata deprecation warnings are left
for a compatibility-aware packaging update; the MIT license is unchanged.

First-time-use check: the README's source quickstart reached the clean result
in 0.057 seconds and the expected malicious result in 0.104 seconds total on
this host. Fresh-venv source installation failed after 1.807 seconds because
build isolation could not obtain `setuptools>=61` with DNS unavailable. The
README now gives a local-wheel alternative; the clean offline wheel installation
passed. These timings describe this machine, not performance promises.

## Adversarial review

Two bounded local workers reviewed CI/packaging/docs and runtime prerequisites/
P0 code; the primary implementer reviewed their diffs and reran verification.
This is project-owned review, not independent third-party assurance. Review
found additional hardlink-policy, disabled-hook and swallowed-deadline cases;
each received a fix and regression.

Assume a program is hostile and ignores instructions: AZT currently provides
no component that prevents secret reads, host writes, outbound communication,
policy/key access by same-user code, or descendants surviving shutdown. Those
answers require the unimplemented runtime profile. The controls actually tested
are scanner descriptor handling, policy validation, HMAC verification and CLI
decisions. The harness observes exact exits and known outputs, not every action.

The scanner is not an atomic snapshotter. Concurrent hostile writers, compromised
host/kernel/Python/AZT/operator, disabled application hooks, excluded content,
unsupported semantics and unrecognized patterns remain limits. Reading all
current files on every gate check can interrupt ordinary coding. These limits
are stated in the README, migration guide and threat model.

## Review-ready PR draft

Title: **Harden repository intake policy and snapshot admission; publish reproducible evidence**

Body:

> An inspected repository could suppress its own findings through `.azt-ignore`,
> and the intake gate accepted unauthenticated pass JSON. Read and configuration
> failures could also disappear from a passing scan.
>
> This change removes target suppression authority, adds explicit external
> file-digest-bound exceptions with visible provenance, reports bounded scan
> scope/completeness, and replaces legacy state with authenticated external
> snapshot receipts. Forged, stale, changed and cross-workspace admission is
> rejected; authorized edits have a tested operator re-admission path. The
> scanner remains offline and stdlib-only.
>
> Regression coverage includes unsafe files, malformed configuration/policy,
> output safety, hook setup, deadline handling and evidence-store errors. Built
> wheel CLI checks distinguish expected findings from crashes; action inputs
> remain data and CI self-scan exports unfiltered review evidence. Documentation,
> schemas, migration, citation and a synthetic local benchmark match the shipped
> behavior. Linux runtime integration is explicitly blocked: only a non-success
> prerequisite doctor ships, with no launcher or containment claim.
>
> Breaking behavior: `.azt-ignore` is informational, gate operations require an
> external private state directory, legacy markers are rejected, relevant scan
> gaps exit 2, excerpts are omitted, native Windows traversal is unsupported,
> and the action defaults to its checkout. See migration and release evidence
> for actual commands, counts and residual limitations.

## Owner release checklist

- Review P0 code, test fixtures, generated evidence and migration together.
- Run hosted Linux CI (3.9 and 3.12), source distribution reproduction and
  candidate action installation; no credentials are needed for untrusted PRs.
- Rebuild artifacts after all source changes, rerun the wheel benchmark and
  verify evidence hashes. Do not distribute a stale candidate under a reused tag.
- Review the immutable action pins against upstream changelogs and commit links
  when updating them. Current pins were checked against upstream release commits.
- Decide protected admission workflow/policy ownership outside PR-controlled
  execution if admission is required. The current self-scan is a review artifact,
  not a security approval. No broad repository exception is installed.
- Verify repository private vulnerability reporting, `pypi` environment approval
  rules, PyPI trusted publisher identity and branch protection before release.
  These settings were not inspected or modified by this assignment.
- Approve version 0.1.8, final release notes and attribution. Create a matching
  release tag only after review; publication remains an owner operation.
- Keep runtime language blocked until actual kernel boundary tests, positive
  controls, benign completion and controller-death cleanup are reproduced.

The strongest truthful demonstration is an unfamiliar tree trying to grant
itself `* *` exceptions and forge a pass marker, followed by visible denial and
a successful reviewed edit/re-admission. A skeptical engineer may reject the
project because regex intake misses semantic attacks and the hook cannot
contain code already running with the user's authority. Better evidence is
outside reproductions plus one measured Linux profile with fair baseline and
backend comparisons. The next repeat-user milestone is that bounded offline
Linux run producing a useful reviewable diff and reliable stop behavior.

The public formats preserve optional organization integrations without creating
an account requirement or reserving essential local safety for paid users.
[Public principles](principles.md) state that commitment without speculative
commercial machinery.
