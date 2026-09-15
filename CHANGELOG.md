# Release notes

## 0.1.9 — unreleased safety-regression candidate

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
No release has been published.

## 0.1.8 — unreleased scanner-hardening candidate

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
