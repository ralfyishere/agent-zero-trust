# Migrating to 0.1.9 and later

## 0.1.13 (unreleased candidate)

The analyzer method changes from `sensitive-request-v1` to
`sensitive-request-v1.1`; scan/review/changes remain v2. Supported saved reports
with the earlier method remain readable. Comparisons across changed method or
engine identities have reduced comparability; preserve historical report bytes
and provenance rather than rewriting them to the current method.

Selected affirmative requests after a prohibition can now be observed, while
explicitly excluded objects no longer supply the sensitive subject of a
version-only request. The [known association cases](../examples/sensitive-request/associations-v1.json)
and [bounded grammar](sensitive-requests.md#bounded-relationships) describe the
scope; this is not a general English interpreter. MEDIUM severity, default HIGH
threshold, scan 0/1/2 exits, one-hop resolution and authority limits are unchanged.

Review and explicitly re-admit after this engine change if using the optional
snapshot gate. Receipts are not renewed automatically. Ordinary scans and saved
report comparisons still need no hook. No new runtime evidence is claimed.

## 0.1.12

New scans emit scan-v2; reviews/comparisons containing them use `azt.review.v2`
and `azt.changes.v2`. Observations add source ranges and reference dependencies.
Updated readers accept supported scan-v1/review-v1 with explicit contextual gaps.
Old binaries do not accept v2. Keep historical reports intact; do not hand-edit
their schema or provenance. Unknown versions still fail clearly.

The preserved diagnostic-request miss now emits MEDIUM. Default HIGH threshold
and scan 0/1/2 exits are unchanged. Comparison/export 0 means completed
information generation, not approval. Primary-only exceptions are refused for
reference-bearing findings; single-file exceptions remain content-bound.

Analyzer source/settings now participate in engine/rule identities and gate
bindings. Review and explicitly re-admit after upgrade if using the optional
snapshot gate. Ordinary scan/comparison needs no hook. FS-001 adapter, probe,
evaluator and expectations are unchanged; new offline results are not runtime evidence.

## 0.1.11

Existing scan exit codes and findings are preserved. The human inventory header
now names **recognized special surfaces**, not all possible agent influences.
Historical demo output retains its original version and wording.

Scan-v1 gains optional `engine` provenance and `suppressed_findings[].exception.file_sha256`.
Consumers should accept these additive fields. New `azt.review.v1` and
`azt.changes.v1` contracts are separate from scan-v1 and admission receipts.
Supported older scan-v1 reports load, but missing provenance reduces comparison
confidence; pre-schema reports and unknown versions require a fresh scan.

`changes`, `report` and `explain` return 0 for a completed informational operation
and 2 for invalid input/output. A zero comparison exit is not a clean scan or
approval. Exports create new files only; archive an old output yourself or choose
a new filename. Use canonical paths without symlink components.

No gate is needed for ordinary edits and repeated comparisons. If you opted into
strict admission, this engine change invalidates old receipts: explicitly review
and re-admit through the existing operator workflow, never silently refresh.

## Earlier versions

Version 0.1.9 was published September 15, 2026. Version 0.1.10 is a
presentation/metadata maintenance update with no runtime behavior change.
Its version identity still changes the engine-bound receipt: re-admit explicitly
if you use the optional strict snapshot gate. Ordinary scanning needs no hook.

The 0.1.8 scanner-hardening changes below remain applicable. Safety comparison
and check reports now use [schema version 2](safety-reporting-v2.md): overlapping
controller-stage counts replace ambiguous `executed` counts; terminal outcomes
partition every planned phase. Preflight no longer reports a runtime trial
count. Readers must dispatch on schema version, not reinterpret historical v1
exports as v2. Scanner, policy and admission formats are unchanged.

Strict snapshot matching remains an optional workflow gate. Source edits can
invalidate it and require explicit operator re-admission; it is never silently
refreshed. Scanning and repeated safety comparisons/checks need no hook.

This is a security-sensitive scanner update, not a 2.0 runtime release. Python
3.9+ remains supported. Safe traversal requires POSIX descriptor-relative opens
and `O_NOFOLLOW`; Linux/macOS are supported. Windows now returns an explicit
non-success error instead of using a race-prone fallback. Native Windows support
needs a separately tested file-handle implementation.

## Intake and exceptions

Target `.azt-ignore` files no longer suppress anything. Reports include their
path, content digest and number of requested lines under `target_requests`.
The files remain in the corpus as adversarial/legacy inputs, with no authority.
The repository's old blanket requests are removed. CI exports the full self-scan
for review and does not call a finding-filled detector repository admitted.
Regression tests still require the expected malicious rule and exact exit code.

An operator can supply `--policy /absolute/operator/policy.json`. Its schema is
in [schemas/policy-v1.schema.json](../schemas/policy-v1.schema.json):

```json
{
  "schema_version": 1,
  "exceptions": [],
  "exclusions": []
}
```

An exception needs exactly `rule`, `path`, `sha256` and a nonempty `reason`.
For example, an operator may approve `net.pipe_shell` at `docs/example.md`,
bound to that exact file's SHA-256 digest, after reading it. There are no rule
prefixes or glob exceptions. A content change invalidates the exception.
Findings remain in `suppressed_findings` with the reason, source and policy
digest. The main finding list contains only active findings.

An exclusion needs exactly `path` and `reason`. It excludes that exact path
(and its descendants if it is a directory), visibly in `scope.skipped`.
Exclusions deliberately reduce inspection scope; they are not a declaration
that excluded content is harmless. Symlinks are rejected before exclusions.
Paths must be canonical relative POSIX paths; traversal, backslashes, wildcard
characters, control/non-ASCII characters and drive prefixes are rejected.
Policies must be outside the target, operator-owned, not group/world writable,
singly linked, UTF-8, and at most 256 KB. Ancestor symlinks are refused.

Neither a flag nor file ownership proves human approval. The caller must be a
trusted operator, with a reviewed policy from a trusted source. A running agent
with the same user's full privileges can call AZT or alter that policy. CI
admission needs a protected evaluator and policy outside candidate execution;
do not use a pull request's policy or expected-results file as authority.

## Receipt and hook lifecycle

Legacy `.claude/.azt-intake-pass` JSON is never accepted. Existing files are left
untouched for review. No receipt is written inside the target, and scanning no
longer edits `.gitignore`. Remove the old hook command during migration before
installing the new one; AZT preserves existing custom hooks.

In an operator terminal, before starting an agent:

```sh
# Use real canonical paths. Parent of the new private directory must exist.
azt install-hook /path/to/workspace --state-dir /operator/private/azt-state
azt scan /path/to/workspace --gate --state-dir /operator/private/azt-state
azt gate-check /path/to/workspace --state-dir /operator/private/azt-state
```

`install-hook` creates the final state directory with mode 0700 if needed;
existing directories must already have that mode. It refuses symlinked paths,
insecure keys/state files, and known project/local `disableAllHooks: true`.
Use the same `--policy` and `--fail-on` on installation, admission and checking
when overriding defaults. No state or policy is inferred from a target file.

Admission issues a receipt for the initial snapshot. A legitimate in-scope edit
is allowed by the workflow, but the next check rejects the changed snapshot.
Review changes and rerun `scan --gate` from the operator terminal to re-admit.
This conservative workflow hashes all regular files in declared scope, including
unsupported-extension files that are only hashed, so it can be inconvenient for
active development. It does not deadlock setup: the operator's terminal does
not depend on the agent hook. Use the scanner without installing the hook when
you only need initial intake. Continuous hashing is not runtime enforcement.

TTL defaults to 60 minutes, with `--ttl-minutes 1..1440` at issuance. The old
`AZT_INTAKE_TTL_MIN` environment override is removed. Expired, future-dated,
changed-scope, changed-policy, changed-engine, changed-threshold and cross-workspace
receipts fail verification. Deleting the one workspace receipt revokes that
workflow admission; restoring an old still-valid receipt can replay admission
for its exact original snapshot. There is no trusted monotonic revocation log.

The generated shell command maps process failures to exit 2, with a ten-second
internal check deadline and thirty-second hook timeout. These improve ordinary
failure behavior, but the application can disable or fail to invoke hooks;
external configuration, startup failures and application timeouts are outside
this tested boundary. Current [Claude hook documentation](https://code.claude.com/docs/en/hooks)
describes non-blocking timeout behavior. Tests invoke the generated command;
they do not establish a live Claude integration.

## Exit codes and output

| Command result | Exit |
| --- | --- |
| Complete scan with no active finding at threshold / valid receipt | 0 |
| Complete scan with active finding at threshold | 1 |
| Incomplete scan, malformed policy/configuration, unsafe path, I/O error, invalid receipt | 2 |
| Runtime doctor (no verified execution profile) | 2 |

`scan --json --gate` emits a single JSON object, including the receipt when
issued. Errors with `--json` are objects on stdout, with diagnostics on stderr.
Gate checks distinguish admission `deny` (missing, invalid, expired or changed
evidence) from operational `error` (for example an inspection deadline or I/O
failure); both exit 2 and grant no authorization.
Ordinary repeated scan JSON is deterministic; newly issued receipts deliberately
contain random IDs and issuance/expiry times. Excerpts are omitted rather than
attempting unreliable generic credential redaction. Relative filenames and
operator reasons may themselves be sensitive; review real exports before sharing.

`scan_repo(root)` retains the inventory/findings tuple for source compatibility,
but it no longer silently suppresses findings. New integrations must use
`scan_report(root, policy=None, fail_on="high")` and check `decision` and
`scope.complete`. A finding-free tuple alone cannot establish completeness.

The composite action now defaults to the scanner source in the selected action
checkout. `version` is an optional validated PyPI override, not the local
candidate under test. Inputs are passed as data. Pin a reviewed action commit;
the action runs scanner/package code, so selecting its source is a trust decision.
