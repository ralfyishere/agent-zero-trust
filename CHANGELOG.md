# Release notes

## 0.1.14 — sensitive-request precision and clearer review summaries

- Refine selected token-measurement wording without treating credential-like
  token requests as harmless. Keep MEDIUM severity and the default HIGH threshold.
- Count identical repeated references and same-block recipient mentions once;
  retain ambiguity between different supporting contexts and distinct recipients.
- Distinguish an unsupported additional reference hop from a detected cycle
  without expanding the one-hop inspection boundary.
- Revise the analyzer method to `sensitive-request-v1.2`; keep v2 report formats
  and explicit older-record support. New status values can require an updated
  reader; optional snapshot-gate receipts require explicit re-admission.
- Correct active release-status guidance while preserving historical captures.
  Add an offline documentation-drift check for the reviewed published install pin
  and external-environment quickstart. It does not query package availability.
- Lead terminal and local text/HTML scan reviews with inspection completeness,
  all severity counts, the selected failure threshold and a next review step.
  Replace the human "trust verdict" label; JSON decisions and exits are unchanged.
  Clarify that reading project material is distinct from gathering or sending
  requested diagnostics.
- Verify every declared scanner-module identity in the installed-wheel intake
  benchmark, including the contextual analyzer and saved-report reader. Keep its
  admission results separate from the unchanged historical Docker experiment.

Published as [v0.1.14](https://github.com/ralfyishere/agent-zero-trust/releases/tag/v0.1.14)
from `fce49dd727f1be4ba4407394a6b4f544e763ef20` in
[release run 35176398216](https://github.com/ralfyishere/agent-zero-trust/actions/runs/35176398216).
Historical candidate measurements keep their original artifact identities; this
release adds no runtime trial. See [migration](docs/migration.md) and
[analysis limits](docs/sensitive-requests.md).

## 0.1.13 — sensitive-request precision and GitHub review

- Add a bounded GitHub job summary with an opt-out and optional explicitly
  supplied base/head comparison using one trusted scanner installation. Preserve
  candidate threshold exits, display below-threshold findings, and fail visibly
  on incomplete baselines or presentation errors. No raw report upload, target
  execution, remote cloning, comment bot, or additional permissions.
- Harden Action startup against target Python/PATH/startup hooks and separate
  package preparation from offline target inspection. Keep exact version
  overrides; default to the trusted pinned Action checkout. See
  [GitHub usage and limits](docs/github-action.md).

- Revise the analyzer method to `sensitive-request-v1.1` for selected local
  action/object relationships. Preserve affirmative requests after explicit
  contrasts and keep prohibited objects out of unrelated affirmative requests.
- Add the six known synthetic association cases and adversarial/legitimate
  regressions for selected prohibitions, shared objects, local use, warnings,
  wrapped text and one-hop reference labels. C3/C4 target missed token requests;
  C5 targets a false alert on a version-only request with explicit exclusions.
  These development inputs do not establish general English understanding.
- Retain scan/review/changes v2 and readable earlier `sensitive-request-v1`
  records. Engine/method differences reduce comparison confidence; the optional
  snapshot gate requires explicit operator re-admission after upgrade.
- Keep MEDIUM severity, default HIGH threshold, scan exits, one-hop scope,
  resource bounds and security limits unchanged. Preserve historical records,
  known-miss history and FS-001 evidence; add no runtime containment claim.

Published as [v0.1.13](https://github.com/ralfyishere/agent-zero-trust/releases/tag/v0.1.13).
Historical candidate artifacts and results retain their original identities. See
[migration](docs/migration.md) and [limits](docs/sensitive-requests.md).

## 0.1.12 — sensitive-request review

- Identify selected English diagnostic/authentication disclosure requests and
  explain potential consequences without collecting secrets or uploading.
- Correlate explicit one-hop local references using only already inspected text;
  retain ambiguous/unresolved evidence and dependency identities.
- Add scan/review/changes v2, retaining supported v1 inputs with explicit gaps.
  Supporting-file changes stay visible; primary-only exceptions cannot suppress
  reference-bearing findings. Thresholds and command exits are unchanged.
- Package offline guidance and a synthetic scan → compare → explain → export lab.
  Preserve original miss bytes, historical results, presentation and FS-001 scope.
- No runtime dependency, account, telemetry, target execution or model call added.

See [migration](docs/migration.md) and [limits](docs/sensitive-requests.md).

## 0.1.11: offline change-aware repository review

- Compare saved scans with `azt changes`: content and recognized surface changes,
  finding multiplicity, visible exceptions, target requests and provenance/scope
  differences. Unreadable or contradictory observations remain unresolved.
- Add bounded scan-v1 adapter and versioned review/change/guidance schemas.
  New scans record engine/rule identity and explicit approved exception hashes;
  supported older scan-v1 reports remain readable with missing-provenance cautions.
- Add offline `azt explain` guidance for every emitted rule and create-only local
  JSON/text/HTML exports. Raw excerpts and source descriptions are omitted.
- Correct the special-file inventory label: zero recognized special surfaces
  does not mean zero inspected files or zero possible influence.
- Add a frozen four-case lab and saved-report evaluation, installed wheel/sdist
  checks, safe-output tests and version-neutral publication instructions.
- No rule detections, FS-001 adapter/probe/expectations, license, dependencies or
  telemetry added/changed. Engine identity changes require explicit re-admission
  if using the optional strict snapshot gate. No new runtime trial is claimed.

See [change-review semantics](docs/change-review.md), [migration](docs/migration.md)
and [the reproducible lab](examples/change-review/README.md). Publication is separate.

## 0.1.10: presentation and metadata maintenance

- Refresh installation, migration, coverage and release-status documentation.
- Add a source-linked founder article and rendered assets based on captured
  public 0.1.9 scanner output and the existing FS-001 record.
- Correct stale unreleased text and relative README links in the next PyPI
  description. Updating GitHub alone cannot change the uploaded 0.1.9 metadata.
- No runtime behavior, probe, evaluator, policy, dependency or license changes.
  The version-only module edit changes engine identity; strict receipts require
  re-admission. Historical runtime evidence remains tied to its original artifact.

## 0.1.9: released September 15, 2026

- Add `azt safety compare` for an explicit single-service Compose JSON bind
  subset, with change provenance, declared-access limits and review-only repair.
- Bind repairs to original/baseline digests; preserve unrelated candidate bytes;
  reject stale input, unsupported layers and unsafe output paths.
- Implement bundled AZT-FS-001 v1 Docker synthetic check/repair/retest, bounded
  canary protocol and legitimate executed coding-task control. Container
  integration has a real canonical three-phase result: selected access
  unavailable/exposed/unavailable, with legitimate task and cleanup verified.
- Safety evidence v2 separates overlapping controller stages from terminal
  passed/failed/blocked/not-run/unknown outcomes. Removes the stale preflight
  runtime-trial count. Historical v1 evidence is preserved unchanged.
- Add a frozen nested-source configuration input for the same FS-001 pack,
  tested through the installed interface; see the evidence index for actual runs.
- Keep the previous 0.1.8 scanner evidence historical and separate. New source
  version invalidates old snapshot receipts; operator re-admission is explicit.
- Add optional project-local Piénsalo capsule documentation, not a dependency,
  host hook, authority store or global memory system.

See the evidence index and release review for the exact verified candidate and
remaining limitations. Static comparison needs no gate or execution backend.
The GitHub Release and PyPI package were published September 15, 2026.

Final experimental verification: code `94a802bbe8b54e86b730203051b9abc162cf0da8`,
[run 34915008373](https://github.com/ralfyishere/agent-zero-trust/actions/runs/34915008373).
Canonical and frozen variant each passed all three phases, including legitimate
task, original integrity and cleanup. The later evidence/documentation commit
does not identify a newly tested artifact. See [exact records](evidence/fs001-0.1.9/README.md).

## 0.1.8: historical unreleased scanner-hardening candidate

The work below was incorporated into 0.1.9, not published independently as 0.1.8.

- Target `.azt-ignore` no longer suppresses findings. External operator
  exceptions require an exact rule, path, file SHA-256 and reason, and remain
  visible with policy provenance. Reject ambiguous, linked and malformed policy.
- Replace unauthenticated workspace pass JSON with external HMAC-SHA256 snapshot
  receipts bound to workspace, manifest, scope, engine, policy, threshold and
  expiry. Reject legacy, forged, stale, changed and replayed admission.
- Make incomplete reads and supported configuration failures visible and
  non-passing. Bound scan work; reject symlinks, hardlinks and special files;
  omit raw excerpts and escape human-facing labels.
- Preserve an operator setup/edit/re-admission workflow, reject locally disabled
  hooks, map hook-command failure to exit 2, and abort timed-out checking.
  The hook remains an honest workflow aid, not hostile-process containment.
- Validate selected MCP, hook, package and task fields; include Gemini MCP and
  nested inventory paths. Preserve benign fixtures and known-miss ledgers.
- Make JSON results consistent, including gate issuance and errors. Gate
  rejection and operational errors are distinguishable and both non-success.
- Test the built wheel and extracted source distribution. Pass action inputs as
  data, default to the action checkout, pin reviewed upstream action commits,
  and export unfiltered CI review/benchmark evidence.
- Publish schemas, synthetic reproduction, contributor guidance and accurate
  citation metadata. The runtime doctor is read-only and always non-success;
  no launch profile, model integration or runtime containment claim ships.

Breaking changes: external private `--state-dir` is required for gate operations;
target ignore rules are informational; incomplete inspection exits 2; in-scope
edits need re-admission; native Windows safe traversal is unsupported; action
version selection changes. See [migration](docs/migration.md) before upgrading.

Earlier documentation's signed-marker claim was incorrect. The security
correction is recorded in [SECURITY.md](SECURITY.md). The MIT license and local
account-free operation are unchanged. This version has not been published.
