# Saved-scan review contract

The local workflow is scan, edit, compare, explain, review, export. It neither
executes target code nor grants authority. It does not need a hook or Docker.

## Inputs and identity

Since 0.1.12, scan-v2 and `azt.review.v2` are accepted
alongside v1. Comparisons containing v2 emit `azt.changes.v2`. The versioned
[sensitive-request observation](sensitive-requests.md) adds supporting inputs,
safe class/action labels and explicit reference dispositions. Old binaries reject
v2; current readers preserve legacy records and flag their contextual-analysis gap.
They never reconstruct missing old analysis from today's files.

`azt changes --before before.json --after after.json` accepts the complete
scan-v1 shape produced since scanner hardening, or a redacted `azt.review.v1`
scan export. “Complete shape” includes reports whose inspection was incomplete.
Error-only envelopes, pre-schema reports, unknown versions, unknown fields and
malformed records fail with exit 2. Do not hand-edit a report to make it pass.
The library equivalents are `azt_review.load`, `adapt`, `compare`, `explain`
and `render`; invalid scan structure raises `ReviewError`.

New scans record the engine version, a digest of the `azt.py` and `azt_intake.py`
file-hash map, and a separate digest of text-rule declarations. From 0.1.12 this
map also includes `azt_sensitive.py`; the historical `text_rules_sha256` field
binds the line rules plus contextual settings and source bytes. The implementation
digest includes structural rules and non-rule code; it is intentionally broader
than detection logic. Older scan-v1 reports lacking these fields remain readable,
with missing provenance explicit. The manifest identifies observed input bytes
and file kinds, not Git history or a globally unique workspace. The caller must
choose the two intended snapshots. Reports cannot prove they came from AZT.

`source_report_sha256` hashes canonical parsed input JSON, not its original
whitespace/bytes. Reading a redacted export hashes that derivative on the next
operation. Schema validation and matching hashes are not authentication. Embedded
admission data is discarded, never verified, inherited or issued by review.

## Matching and uncertainty

- Surfaces use exact case-sensitive relative paths and manifest identity.
  Other hashed content changes are reported separately; an empty special-surface
  inventory does not mean zero inspected content or influence.
- Findings group by rule/path/severity and preserve multiplicity. Lines order
  duplicate groups but do not establish occurrence identity. Line shifts remain
  visible; changed file bytes can mean a different occurrence of the same rule.
  Raw evidence is unavailable, so the report explicitly limits continuity.
- Same-hash removed/added paths are only rename candidates. Their findings remain
  removed/new by path. No rename or normalization silently clears a finding.
- An absent file during incomplete inspection is unavailable, not confirmed
  deleted. Disappearing findings remain unresolved if scope/provenance deteriorates
  or observations contradict unchanged deterministic inputs. Otherwise they are
  “no longer observed,” never “fixed.”
- Engine, rules, policy, threshold, exclusions, limits and analysis coverage
  differences reduce comparability. Added/removed inspected paths are visible
  scope changes without automatically making every normal edit incomparable.
- Approved exceptions retain their explicit file digest and policy provenance.
  Changed bytes cannot inherit an exception. Older exceptions lack an explicit
  approved hash; their manifest association is an inference, flagged as such.
  Target `.azt-ignore` requests stay informational and separate.

`meaningful_delta=false` means no relevant difference between supplied records,
not that either is safe, authentic or complete. Check comparability separately.
Commands exit 0 for successful information generation, even with changes or
reduced comparability; 2 for invalid/unsupported input or output failure. Scan's
existing 0/1/2 semantics are unchanged.

## Guidance and exports

`azt explain RULE_ID` reads the bundled 24-rule catalog. Each entry gives meaning,
review rationale, legitimate context, limits and a next step. Unknown IDs fail.
Old reports may retain unknown rules without pretending they are harmless.

All three commands support `--json` or `--format json|text|html`, and `--output`
for create-only files. `azt report --input scan.json --format html --output scan.html`
validates and redacts a scan. Export comparisons directly with `azt changes`;
comparison JSON is an output contract, not another scan input.

Text/HTML/JSON expose control and bidirectional characters as escapes. HTML escapes
all untrusted content, has a restrictive CSP, and has no links, scripts, remote
fonts or fetches. Excerpts and source-supplied descriptions are omitted, with
descriptions replaced by maintained catalog text. Paths, reasons and labels can
still be sensitive: review before sharing. No upload or public page is created.
This derivative is not the original evidence. Keep original files separately.

In the 0.1.14 source candidate, terminal and text/HTML scan reviews separately
state inspection completeness, HIGH/MEDIUM/INFO counts, and the selected failure
threshold. A MEDIUM finding is visible even when HIGH is not exceeded. Incomplete
inspection remains incomplete regardless of that threshold. The JSON `decision`
field and scan exits retain their existing meanings; none is human approval.

Input/output is bounded to 8 MiB, nesting to 32, aggregate nodes to 150,000,
arrays to 10,000 entries, strings to 8,192 and relative paths to 4,096 characters.
Expanded exports exceeding a bound fail rather than silently truncate. No remote
schema references are resolved. Paths use descriptor-based regular-file reads;
symlinks, hardlinked input, traversal and special files are rejected. Output
requires an existing operator-owned parent not writable by group/others and a
new filename. A filesystem write failure may leave a partial new file; it returns
non-success and must not be treated as complete evidence.

[Schemas](../schemas/) describe structural contracts; the stdlib validator also
checks manifest hashes, disposition coverage, decisions and exception consistency.
Packaged schema copies accompany the offline guidance catalog.

## Scope and shared-code impact

The 0.1.11 change-review milestone did not change detection rules. Version 0.1.12
added sensitive-request detection, intake correlation and gate identity
binding; dependency-aware comparison includes every supporting input and keeps
degraded evidence unresolved. No FS-001 runtime module/probe/expectation changed. The
shared scanner dispatcher/version and additive intake provenance did change;
offline scanner, admission, static safety and installed-artifact tests cover them.
Historical Docker evidence does not verify this rebuilt package. No new Docker
trial, live agent, continuous authorization or universal containment is claimed.
