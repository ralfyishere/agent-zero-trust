# Experimental candidate review and owner release decision

Version 0.1.9 remains unreleased on `fix/trusted-intake-evidence`.
Recommendation: **ready for a public experimental release**, subject to owner
review and publication checks, with no claim of general agent containment.
Final tested code: `94a802bbe8b54e86b730203051b9abc162cf0da8`; canonical and
variant each passed 3/3 completed phases in run34915008373. See
[the exact artifact record](../evidence/fs001-0.1.9/README.md). This later
documentation/evidence update is not a newly tested package or source revision.
The [evidence index](../evidence/README.md) is the source of truth for verified
code/artifact identities. Historical failures and scanner evidence remain
separate. A release recommendation requires the final code candidate's
canonical and frozen variant runs, not only the earlier canonical success;
that requirement is now satisfied. One of three authorized finalization jobs
was used, with zero failed attempts in that budget; the two earlier historical
failures remain visible. No additional job is needed for unchanged runtime code.

## Prepared PR (not created)

Title: **Harden intake and add evidence-backed filesystem check–repair–retest**

Body:

- Preserve deterministic offline scanning; stop trusting target suppressions,
  bind snapshot admission to explicit operator policy and current inputs, and
  fail incomplete inspection visibly.
- Add experimental Compose JSON mount comparison and digest-bound review-only
  repair, plus AZT-FS-001 synthetic Docker/Linux check–repair–retest.
- Separate controller progress from final phase outcomes in safety evidence v2;
  retain partial observations when later validation or cleanup fails.
- Include a frozen nested-source variant, positive/legitimate-task controls,
  failure tests, clean wheel/sdist checks and reproducible evidence.
- Docker provides isolation. This is one trusted-probe filesystem regression,
  not arbitrary-agent containment, model integration or an independent audit.
  See the evidence index for exact results and historical failed attempts.

## Review findings and limitations

A bounded fresh-context model-assisted review covered accumulated changes and
the evaluator/repair path; it is not a third-party security audit. Resolved
findings include partial CI evidence lost on truncated JSON and variant
reproduction commands missing their case selector. Prior fixes cover unsafe
archive metadata and stale/tampered repairs. Reporting no longer equates
completed collection with execution or carries preflight zero trials into runs.

The selected protected directory/canary is not a recursive audit of every child
secret. A valid HMAC demonstrates this read; unavailable access plus positive
and legitimate controls does not prove universal denial. Host same-user
compromise, network/exhaustion/descendant-stop/controller-death/cross-session
behavior, real agents and cloud egress remain untested or unsupported.

The strongest demonstration is the same coding task succeeding before, during
and after a synthetic mount exposure, with exposure independently checked and
a narrow repair retested. The strongest skeptical objection is the intentionally
small configuration subset and trusted probe. External reproduction and useful
failing configurations within that subset are better evidence than broader
claims. The next small milestone is making this same check useful after recurring
configuration edits, informed by developer reports.

## Owner actions (not performed)

1. Review the full feature diff, exact final evidence, schema migration and
   preserved MIT/creator/contributor/upstream attribution. Keep private outputs
   and unrelated local changes excluded.
2. Decide whether to open a PR. A PR targets normal offline CI and may invoke
   repository-managed CodeQL; review those owner-side workflows first. The
   marked FS-001 feature-push job is separate, not an automatic PR requirement.
3. Merge only after owner review and required checks. A main push invokes the
   existing offline CI and may invoke default-branch security analysis.
   Offline CI has Python3.9/3.12 jobs, a composite-action candidate job and
   artifact uploads; those future owner-triggered runs are outside this
   finalization job's no-upload scope.
4. For publication, use the separately reviewed existing release workflow;
   verify PyPI trusted publishing/environment protections and artifact identity
   before creating a tag or publishing a release. No tag, package or release is
   authorized by this document.
   The committed publisher still has moving action tags and no recorded final
   artifact-test gate. Review/pin it and its protection settings separately
   before publishing; unrelated local publisher edits were deliberately excluded.

The current feature-branch verification job uses a standard Ubuntu runner,
explicit approved setup downloads, no artifacts/caches and no model calls.
Evidence/documentation follow-ups identify their separately tested code commit;
they do not rename a rebuilt wheel as the original tested artifact.

Public contribution statement: **AZT helps developers review selected agent
filesystem-access changes, propose a narrow configuration repair, and test it
with synthetic resources while checking that a small coding task still works.**
