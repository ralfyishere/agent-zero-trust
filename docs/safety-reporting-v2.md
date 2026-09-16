# Safety evidence v2

At the 0.1.9 safety-evidence transition, scanner/admission schemas stayed at v1;
only `azt safety` evidence, its integration artifact record and CI envelope
advanced to v2. Scanner reports subsequently advanced to v2 in 0.1.12; admission
receipts, repair proposals and the FS-001 probe remain v1. Historical exports
are never migrated in place.

Each planned phase has a terminal `status`: `passed`, `failed`, `blocked`,
`not_run`, or `unknown`. Their counts partition the three phases exactly once.
Missing controller records become unknown, not not-run or pass. Operational
errors without an execution record use the error envelope's explicit unknown
execution outcome. Missing/corrupt CI evidence fails export and retains valid
records and cleanup diagnostics; it cannot turn an incomplete job into a pass.

`counts.stages` contains overlapping acknowledgments (never sum these as tests):

| Stage | Controller observation |
| --- | --- |
| container_started | Docker start returned success; not proof the container remains alive |
| probe_returned | Bounded Docker exec returned success and output arrived |
| probe_protocol_completed | That output parsed and matched the fixed probe's challenge/UID envelope; not HMAC/read verification |
| result_exported | Separate unprivileged exec/tar returned a bounded archive |
| archive_validated | Strict archive parser accepted its single bounded regular task.py; no host extraction |
| verification_completed | Probe protocol and validated file available; evaluator performed required checks, which may still fail |

False means not acknowledged, not proof an operation never began (for example,
a command can time out). These are controller records, not syscall monitoring.
`independent_checks` preserves a verified HMAC even if a later export/cleanup
fails. `edited_file_matches` is independent of task stdout. The task passes only
with exact edited bytes and expected executed output. Cleanup and a full
positive-control phase are required for a complete baseline/repaired denial pass.

Preflight has `observation_scope: prerequisites only; no workload launched`,
not `runtime_trials`. It reports its own scope even when nested in a later run.
The old v1 `executed` counted completed result collection; e.g. run34911273066
had three completed probes but zero completed collections. Its missing failed
count and stale preflight zero are documented interpretations, not rewritten data.

[Schema](../schemas/safety-evidence-v2.schema.json). JSON Schema validates field
shapes; producer/reader tests enforce counter conservation and semantic checks.
The CI envelope exports only selected records, bounded to64KiB. No authenticity,
immutability, complete-event-history or independent-third-party-audit claim.
