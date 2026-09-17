# Repository review in GitHub Actions

The Action scans a supplied checkout and writes a bounded job summary. It uses
the same offline scanner, maintained guidance and saved-report comparator as the
CLI. MEDIUM findings are visible even when the default HIGH threshold leaves a
job green. Green means the selected failure threshold was not reached within the
reported scope—not safe, approved, no findings or attack blocked.

This integration shipped with [0.1.13](https://github.com/ralfyishere/agent-zero-trust/releases/tag/v0.1.13).
The current example pins the reviewed [0.1.14 source](https://github.com/ralfyishere/agent-zero-trust/commit/fce49dd727f1be4ba4407394a6b4f544e763ef20),
including its sensitive-request precision improvements. Published 0.1.12 retains
its earlier Action behavior. The standalone scanner remains account-free and
does not require GitHub, Docker or a model.

## Explicit current-base to PR-head comparison

This ordinary `pull_request` example acquires the event's current base commit and
actual head commit, **not a merge-base or GitHub's synthetic merge commit**.
Checkouts and scanning are separate. The scanner/helper come from the pinned AZT
Action, never from the inspected PR. Use a standard Ubuntu 24.04 hosted runner;
the Action uses its `/usr/bin/python3` with stdlib venv/pip support. Initial
checkout and trusted-package/build-tool installation need network access;
the two scans, guidance and comparison make no network calls.

```yaml
name: Review instruction changes
on: [pull_request]
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          repository: ${{ github.repository }}
          ref: ${{ github.event.pull_request.base.sha }}
          path: snapshots/base
          fetch-depth: 1
          persist-credentials: false
          submodules: false
          lfs: false
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          repository: ${{ github.repository }}
          ref: ${{ github.event.pull_request.head.sha }}
          path: snapshots/head
          fetch-depth: 1
          persist-credentials: false
          submodules: false
          lfs: false
      - uses: ralfyishere/agent-zero-trust@fce49dd727f1be4ba4407394a6b4f544e763ef20 # v0.1.14 source
        with:
          base-path: snapshots/base
          path: snapshots/head
          base-label: ${{ github.event.pull_request.base.sha }}
          head-label: ${{ github.event.pull_request.head.sha }}
          fail-on: high
```

By default, the scanner, formatting helper and report validator all come from
this pinned Action checkout. This source identity is not the hash of a PyPI wheel;
the Action installs from its reviewed source rather than downloading that wheel.
The base repository's PR ref makes its head commit available there; the example
does not select additional repositories from target text. Missing/unavailable
commits fail checkout instead of silently switching inputs. Do not use a branch
name or load `uses: ./` from an untrusted PR. Never bypass fork-workflow approval.

## Inputs and status

| Input | Default | Meaning |
| --- | --- | --- |
| `path` | `.` | Candidate checkout; relative to GitHub workspace, or explicit absolute path |
| `base-path` | omitted | Optional separate baseline checkout; no implicit Git fetch/clone |
| `fail-on` | `high` | `high`, `medium`, or `any`; candidate threshold still applies to persisting findings |
| `version` | omitted | Install scanner from this trusted Action checkout; numeric PyPI version or `latest` remains an explicit override |
| `job-summary` | `true` | Set `false` to omit summary content from both the job summary and log |
| `head-label`, `base-label` | omitted | Optional full 40-character commit labels supplied by caller; not authentication |

One private external virtual environment installs the selected scanner once for
both scans. `latest` is not reproducible; prefer the reviewed Action's default or
an exact supported package version. Older overrides lacking a supported scan
contract return 2, not a fabricated empty report. The helper uses this Action's
review validator/catalog; scanner and engine identities remain in the summary.
The Action retains the default trusted policy: target `.azt-ignore` requests do
not authorize exceptions. It does not add a policy-discovery or approval system.

Exit 0: candidate inspection completed and its selected threshold was not reached.
Exit 1: candidate findings met/exceeded that threshold (summary still produced).
Exit 2: preparation, scanning/validation, requested comparison, or summary
presentation failed. A HIGH finding in the baseline alone is not an operational
error. A missing baseline cannot become an empty clean baseline; useful candidate
findings remain visible. Unsafe/nested input layouts are rejected before tooling.

Reduced comparison alone remains informational, as with `azt changes`: changed
scope or unresolved supporting context is displayed, never called a repair.
Incomplete scans or differing engine/version/policy/threshold between the two
operations return 2. No-longer-observed findings are not proven fixed. There is
no delta-only admission policy and no receipt is issued.

## What the summary shows—and omits

Each side has an input-manifest digest, scanner/engine/rules/policy identity,
inspection/skips/errors counts, findings by severity, threshold and actual scan
exit. Explicit caller commit labels are separate from content identities; omitted
or malformed labels remain unknown. A single snapshot never labels findings new.
Comparisons show new/persisting/no-longer-observed/unresolved counts, dependency
changes, reduced comparability and a practical local review step.

At most 12 findings per snapshot and 12 comparison reasons are displayed; totals
and omitted-display information remain visible. Formatting is capped at 48 KiB,
well below GitHub's per-step limit. This does not shorten the underlying scan.
Raw excerpts, recipient values, source-supplied descriptions, full event payloads
and error/skip paths are omitted. Display labels escape non-ASCII and Markdown/
HTML/link/image/mention/control punctuation visibly; suspect links are not active.
Paths can still be sensitive. Export a local report for full inspection scope.

Enabling summaries places this derivative in **GitHub summaries and logs under
workflow visibility**. It is not the raw report, and local analysis does not mean
GitHub receives no output. The Action does not upload reports/artifacts, post
comments, push code, or create result pages. Setup failures emit only a categorical
stage and status, never raw package/target output. `job-summary: false` leaves
controlled status counts in logs, not finding paths or summary content.

## Trust boundary

Snapshots must be separate, non-nested directories. The scanner environment and
temporary reports stay outside both. Python starts isolated from target imports;
the initial shell uses absolute host tools with shell startup hooks unset. Scanner
subprocesses use fixed argument arrays, a cleared environment and external cwd.
No target setup/build hooks, modules, Git hooks, submodules, LFS, package installs,
or remote instructions are executed. Commands have deadlines and bounded captured
output; failures never become a clean scan. No real secrets are needed in tests.

The workflow, pinned Action/package, runner and preceding trusted setup remain
trusted. This is not containment of another hostile process already running on
the runner. A PR can edit an ordinary PR workflow; this is review assistance, not
an immutable required check or universal merge gate. Do not use
`pull_request_target`, privileged `workflow_run`, write/OIDC permissions, referenced
secrets or personal self-hosted servers for this example. Respect fork approvals.

Maintainer CI deliberately uses `uses: ./` to **test AZT's candidate code**, not as
the consumer pattern. It also runs synthetic expected-failure assertions rather
than treating a crashed install or skipped scan as detection. No FS-001 trial is
run by this integration.

## First-use and synthetic bug reports

1. Review the pinned source and use the ordinary read-only workflow example.
2. Start with a benign checkout; inspect version, scope and input identity.
3. Try the bundled inert Action lab; expect MEDIUM below HIGH, not a blocked attack.
4. Review a finding with `azt explain request.sensitive_disclosure` locally.
5. For a bug, provide AZT version/pin, command/inputs, actual statuses and a minimal
   synthetic text plus benign contrast. Do not submit keys, environment dumps,
   shell history, complete private logs or customer material.

Upstream behavior reviewed against GitHub's [workflow commands](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands),
[secure use guidance](https://docs.github.com/en/actions/reference/security/secure-use),
and [script injection documentation](https://docs.github.com/en/actions/concepts/security/script-injections).
