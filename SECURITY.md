# Security

## Experimental safety pack

AZT-FS-001's static adapter and repair logic are offline-tested. Its Docker
orchestration has a real synthetic three-phase result in the [evidence index](evidence/README.md).
Do not use it as proof of protection for real credentials or agents. Only
synthetic resources and bundled reviewed code execute. See the
[pack boundaries and TCB](packs/AZT-FS-001/v1/README.md). Configuration readback
is not a test of every kernel boundary; no model, network or descendant-stop
outcome is claimed. Review proposals before sharing: operator-selected inputs
can contain private paths or labels.

## Scanner boundary

AZT inspects repository content without executing it or calling a model.
Its security-sensitive components are the filesystem reader, configuration
validation, exception policy and optional admission receipt lifecycle.
A passing scan means no active known-shape finding met the selected threshold
within the declared scope. It does not mean the repository is safe.

## Trust boundary

The target's `.azt-ignore` has no suppression authority. Explicit operator
policy must be outside the workspace. Exceptions require an exact rule, path,
file digest and reason; suppressed findings remain in the report.

The optional gate verifies HMAC-authenticated snapshot receipts in a private
external state directory. It rejects legacy workspace markers and changed,
expired, future-dated or mismatched evidence. HMAC authenticity depends on
protecting its key. Same-user hostile code can read that key, alter policy or
disable the hook. No filesystem location alone fixes that authority problem.

Generated hook failures map to exit 2; gate checking has a 10-second inspection
deadline inside the generated 30-second hook timeout. The local lifecycle is
tested, but complete behavior inside a coding-agent application has
not been tested. User-level configuration, disabled hooks, uncovered tools and
already-running processes remain outside this workflow gate.

The scanner and hook do not supply a runtime isolation boundary. The optional
FS-001 synthetic profile uses Docker isolation within its documented scope.
See [threat model](docs/threat-model.md), [runtime status](docs/runtime.md)
and [coverage](COVERAGE.md).

## Reporting

Use a public issue for a synthetic bypass, false positive or documentation error
that does not expose sensitive information. Include a minimal fixture,
`azt --version`, the exact command, expected outcome and actual output.
Do not include working credentials, private repository content or customer data.

For sensitive reports, use GitHub's private vulnerability reporting if enabled
on this repository. If it is unavailable, open a public issue requesting a
private reporting channel without disclosing the exploit or affected parties.
Do not assume a private channel is enabled merely because this document mentions it.

Confirmed limitations should become either a failing regression with a fix or
a clearly labeled entry in the known-miss ledger. Reporters and contributors
are credited with their consent; do not disclose private identities by default.

## Scanner correction developed as 0.1.8, shipped in 0.1.9

Earlier documentation described the legacy pass marker as signed or content-bound.
That description was incorrect: the implementation accepted plain JSON with
`"verdict": "pass"` and used file age. Broadening a hook's tool matcher did
not authenticate the marker. Do not rely on the old disclosure entries as proof
that hostile-process forgery was fixed.

Version 0.1.9 replaces that mechanism with authenticated snapshot receipts,
removes target-controlled suppression, and makes relevant incomplete inspection
a non-success result. It does not claim to contain an already-running hostile
program. [Migration instructions](docs/migration.md) describe the breaking changes.

The default report omits raw file excerpts and arbitrary configuration commands.
Paths and operator-authored reasons can still be sensitive; review exported
reports before sharing them. State directories contain the issuer key:
never publish, upload or commit them. See [evidence format and retention](docs/evidence.md).
