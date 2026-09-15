# Evidence and the local reproduction

This page describes the historical **intake-only** benchmark, not FS-001 runtime
results. Current synthetic Docker results are indexed [separately](../evidence/README.md)
with [safety v2 semantics](safety-reporting-v2.md). Neither study inherits credit
from the other. The historical development-host block below is not a claim
that the later supported Linux execution did not occur.

The milestone measures static intake and snapshot admission. Its evaluator is
project-owned code outside the synthetic workspace, not an independent audit.
It never executes attack text and never uses a model. Runtime boundary scenarios
and the fair A/B/C disposable-baseline/backend/AZT comparison are explicitly
not run: no supported execution profile is available on the development host.

From a trusted checkout, on Python 3.9+ Linux/macOS:

```sh
python3 scripts/containmentbench.py --output /tmp/azt-evidence-new
```

The output directory must not exist. This creates `results.json`, `inputs.json`
and `review.patch`. Stdout is the actual JSON report. No new product CLI command
is required. A built wheel can be tested with:

```sh
python3 scripts/containmentbench.py --wheel dist/agent_zero_trust-0.1.8-py3-none-any.whl --output /tmp/azt-wheel-evidence-new
```

The latter installs the wheel into a test-owned clean virtual environment using
`--no-index --no-deps`, checks that its engine modules match the current source,
then invokes the installed console command. It needs local venv/pip support but
no network, account, API key or payment. Versions, artifact SHA-256, source file
hashes, effective policy, OS/Python version and elapsed time are recorded. Hashes
identify this exact uncommitted candidate independently of a Git commit label.
Rebuild after engine edits: stale wheel/source pairs are rejected.

The benchmark's prohibited operation is **admission of an unapproved snapshot**.
AZT returns non-success for malicious input despite a wildcard target request,
for forged legacy state, and for modified admitted input. This is not proof of
blocking shell execution. The legitimate task is a fixed arithmetic correction
made by the harness in a temporary workspace, re-admitted and run as benign
Python. The harness compares outputs with expected values kept outside that
workspace, verifies the original fixture remains unchanged, and exports a diff.
It is neither agent-generated code nor a contained hostile workload.

Reports distinguish `workload_claim`, `azt_observed` and `evaluator_verified`.
The arithmetic program's text output is compared to expected output; no program
can pass by printing a generic success message. The evaluator checks the rule
identity as well as the malicious scan's exact exit code, so a crash is a failure.
Required/expected results and operator state are not files the evaluated scan
target controls. The harness itself is trusted and must be reviewed before use.

## Local format and trust assumptions

[Scan](../schemas/scan-v1.schema.json), [policy](../schemas/policy-v1.schema.json),
[receipt](../schemas/receipt-v1.schema.json), and
[error](../schemas/error-v1.schema.json) schemas describe the version 1 interfaces.
The [benchmark export schema](../schemas/benchmark-v1.schema.json) labels the
current intake-only reproduction with zero runtime trials.
Unknown future schemas must not authorize admission. Runtime event logging is
not implemented. The receipt observes `snapshot_admitted`, not attempted or
executed syscalls, network requests, subprocesses, or subsequent file mutations.

| Property | Implemented mechanism | Limit |
| --- | --- | --- |
| Content binding | SHA-256 of sorted path/type/file-digest/executable manifest, scope, engine source, policy | Local reads are not an atomic snapshot; scan a quiescent tree |
| Authenticated issuance | HMAC-SHA256 over canonical sorted JSON with a random 32-byte key | Symmetric authentication, not a public signature; any key holder can issue |
| Freshness | Authenticated issue/expiry times, bounded TTL, current snapshot comparison | Trusts host clock; no monotonic revocation service |
| Authority isolation | External directory 0700, files 0600, owner/link checks, no symlink traversal | Same-user arbitrary code can access it; no hostile-process isolation |

Canonical JSON uses Python stdlib `json.dumps` with sorted keys, separators
`,` and `:`, ASCII escaping, UTF-8 bytes. Files are hashed as raw bytes. Manifest
names remain relative; symlink target text is hashed and never printed. Directory
and excluded entries name scope boundaries. Built-in excluded directory contents
are not bound. Read/analysis gaps invalidate admission. File size, entry count,
total bytes, depth, line length and finding count are bounded in the report.

Receipts live as `<workspace-id>.json` in the operator state directory beside
`issuer.key`. The workspace ID binds canonical absolute path, device and inode
without publishing the path. Successful re-admission atomically replaces that
workspace's previous receipt. Local verification compares HMAC using stdlib
`hmac.compare_digest`. Never publish the key. Exported HMAC receipts are not
independently authenticated to strangers; they can reproduce the scan against
the named inputs and engine instead.

There is no append-only event store or hash chain. The implementation neither
detects deletion nor proves completeness of an event history. State is retained
until operator deletion, with one current receipt per admitted workspace; a
receipt file is bounded to 32 KB at verification. Output volume is bounded by
scan limits. On evidence-write failure, issuance reports an error and attempts
to remove a newly published receipt. A broken filesystem cannot guarantee
rollback or durability; repair it before trusting subsequent checks.

Only synthetic evidence belongs in public artifacts. Command excerpts and
dynamic configuration names are omitted from scan findings, but arbitrary file
names, operator policy paths/reasons and digests can still reveal information.
CI's review artifacts have fourteen-day retention. There is no telemetry,
network listener, hosted evidence dependency, or claim of immutable logs.
