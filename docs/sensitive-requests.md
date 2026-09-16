# Review before sharing diagnostics

An unfamiliar project's helpful-looking instructions can ask for more than a
bug report. AZT identifies selected English requests to share shell history,
environment dumps, credential-bearing configuration, tokens or private keys.
It explains what those materials **may** expose without collecting them to
check whether credentials exist. This is repository intake, not runtime blocking.
Try the [synthetic lab](../examples/sensitive-request/README.md).

## Meaning and next step

`request.sensitive_disclosure` is **MEDIUM**: the wording warrants review, but
does not establish malicious intent, actual sensitive contents, disclosure, or
recipient trust. Default `--fail-on high` still exits 0 for an otherwise complete
scan containing only this finding; `--fail-on medium` exits 1. Relevant inspection
errors exit 2. No default threshold changed.

`azt explain request.sensitive_disclosure` provides maintained offline guidance:
verify the request independently, provide only necessary diagnostics, and inspect
the exact contents before sharing. A promise to redact later is not assurance
that an unrestricted upload is appropriate. A limited request can be legitimate;
a flagged document or command is not automatically malicious. AZT never turns
the suspect upload command into its own advice.

## Bounded relationships

The analyzer uses successfully decoded, safely read snapshots from intake. It
matches English case-insensitively, collapses ASCII spaces/tabs/newlines, and
retains source line ranges. It does not remove Unicode concealment characters;
the existing hidden-Unicode rule remains separate. Homoglyphs, other languages,
arbitrary paraphrases, complex negation and indirect persuasion can miss.

Paragraphs have non-overlapping windows of at most **16 lines / 4,096 characters**.
An action must relate locally to named information classes. Explicit bundle/include
lists and local pronouns such as “them” or “both values” can connect collection
to sharing. Blank paragraphs and window boundaries do not carry pronouns.
Selected prohibitions and quoted warnings are handled; fences, quotations,
“official,” “approved,” “example” and debugging pretexts are not blanket exemptions.
Local configuration use or a version-only request is not equivalent to disclosure.

The analysis indexes each eligible document once, within intake's 32 MB total
read budget. Limits are 32 million retained text characters, 1,000 request
observations, two references per request, and 2,000 reference lookups. Aggregate
limit failures make inspection incomplete; valid partial observations remain.
Window-boundary relations are explicitly unsupported, not a promise of unlimited
whole-document analysis. Existing shell-transfer findings are not duplicated for
the same single-line request, except where a contextual dependency must be retained.

## One hop, no new reads

Supported references are Markdown links with contact/sharing context, or bare
paths immediately after “address in”, “address listed in”, “instructions in”,
“steps in”, “see”, “refer to” or “follow”. A collection-only request also needs
explicit sharing/contact context; a generic local-instructions link is insufficient.
Paths are relative to the **request document's directory**, case-sensitive,
ASCII canonical POSIX paths, at most 256 characters, ending `.md`, `.txt` or `.mdc`.

Only already inspected eligible text supplies support. No second hop is followed.
Dot/traversal, percent-encoded, absolute, drive, UNC, query/fragment and unsupported
path forms are rejected. Symlinks, hardlinks, special files, unreadable and
structurally failed inputs cannot supply support; exclusions stay excluded.
A requested `.env` is a data subject, **not** a document to fetch. Unrelated files
are not paired by fuzzy names or shared topics. No URL fetch, DNS, email, setup
hook, subprocess or target instruction is executed for correlation.

A contact block can establish that an address is mentioned, not that it is
genuine. Multiple possible contact blocks/recipients remain ambiguous. Every
actually used source, including ambiguous context, has an input hash and location.
Missing/excluded/unsupported material stays unresolved. External links are not
automatically whole-scan errors. Raw addresses/URLs are omitted, including
userinfo, paths, query strings and fragments. Local paths may still be sensitive.

## Reports and authority

Scan-v2 adds bounded `sensitive_request` action/class labels, source ranges,
reference dispositions and dependency identities. Review/changes v2 carry these
through existing JSON, text and static HTML commands. Supporting-file changes
remain visible even when the request file is unchanged. Missing/degraded support
cannot resolve an old request. “No longer observed” does not mean “fixed.”
Comparison uses saved validated records, not today's filesystem. Engine/method
changes reduce comparability; unrelated edits do not invalidate every observation.

Existing external single-file exceptions work. A primary-only exception cannot
suppress **any reference-bearing request**, even when unresolved; the report
explains the refusal. Multi-input exceptions are not implemented. Target ignore
requests, approval claims and contact text never grant authority. Hashes identify
inputs, not authenticity, intent, atomic scanning or complete understanding.
The optional snapshot gate remains separate; upgrading requires explicit operator
re-admission, not automatic renewal. Passive scanning needs no hook.

## Evidence and contribution

The original miss bytes and historical results remain unchanged. The
[evaluation/lab](../examples/sensitive-request/README.md) separates development
and reviewer-authored inputs and discloses actual results and performance.
Cases seen during development are not held out. This is not a live-agent trial,
third-party audit, or real-world safety percentage; FS-001 evidence is separate.

Submit a minimal **synthetic** request and legitimate contrast, expected classes
and reference status, version, command and actual output. Use reserved example
destinations. Never include real secrets, shell history, customer submissions or
private repositories. New cases should exercise relationships, not just matcher
spellings. See [contributing](../CONTRIBUTING.md).
