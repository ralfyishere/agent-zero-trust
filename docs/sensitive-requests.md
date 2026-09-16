# Review before sharing diagnostics

An unfamiliar project's helpful-looking instructions can ask for more than a
bug report. AZT identifies selected English requests to share shell history,
environment dumps, credential-bearing configuration, tokens or private keys.
It explains what those materials **may** expose without collecting them to
check whether credentials exist. This is repository intake, not runtime blocking.
Sensitive-request review was introduced in 0.1.12 and its action/object handling
was improved in the [published 0.1.13 release](https://github.com/ralfyishere/agent-zero-trust/releases/tag/v0.1.13).
Try the [synthetic lab](../examples/sensitive-request/README.md). The unreleased
0.1.14 candidate refines selected token meanings and reference observations as
`sensitive-request-v1.2`; use a reviewed candidate build to test those changes.

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

Since 0.1.13, a selected action grammar handles an explicit contrast such as
“instead” can end a prohibition, so a later affirmative request keeps its own
object. A later “do not include” does not attach its excluded objects to an earlier
version-only request. Selected coordinated actions can share an object, as in
“collect and upload”; a prohibition can apply to both in “do not collect or upload”.
Sentence/semicolon boundaries and selected action bullets also separate requests.
Selected contractions accept straight or curly apostrophes. These are bounded
wording cases, not general English negation, syntax or intent understanding.

The 0.1.14 candidate distinguishes selected token measurements from credential
requests. Asking for a token count is not the same as asking for an API token.
The matcher checks at most 64 adjacent characters around a bare `token`/`tokens`
mention for selected count/budget/usage/total/limit phrases or parser/lexical/syntax
context. Credential-qualified terms such as `API token` are not exempted, and a
directly stated authentication role or credential value overrides the selected
measurement/parser meaning. “The number of tokens” names a quantity; “a number
of tokens” can request several token values and remains reviewable. A separate
credential request in the same paragraph still deserves review. This
is a local wording distinction, not a determination of what a token really
contains; unfamiliar vocabulary and ambiguous bare-token requests remain limits.

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

In the 0.1.14 candidate, identical repeated reference targets are counted once
within the two-reference request limit; repeating the same recipient within one
contact block does not establish several recipients. Deduplication uses exact
strings, not a reputation service or an assumption that different URL paths,
query strings or letter case identify the same recipient. Different contact blocks remain separate
contexts even when they repeat an address: this bounded analyzer does not infer
that their instructions are equivalent. A further reference is labeled
`additional-hop-not-followed`, not `cycle` merely because it exists. `cycle`
is reserved for a supported reference back to a document already in this
one-hop relationship. Neither status grants additional reads or resolves the
destination. An unknown second hop remains unknown.

## Reports and authority

Scan-v2 adds bounded `sensitive_request` action/class labels, source ranges,
reference dispositions and dependency identities. Review/changes v2 carry these
through existing JSON, text and static HTML commands. Supporting-file changes
remain visible even when the request file is unchanged. Missing/degraded support
cannot resolve an old request. “No longer observed” does not mean “fixed.”
Comparison uses saved validated records, not today's filesystem. Engine/method
changes reduce comparability; unrelated edits do not invalidate every observation.
Scan/review/changes remain v2. The 0.1.14 reader accepts supported records with
`sensitive-request-v1`, `sensitive-request-v1.1` and `sensitive-request-v1.2` methods.
The new `additional-hop-not-followed` reference status is an explicit contract
extension: older binaries may reject a new report containing it. Use the updated
reader instead of editing historical reports, their methods or their hashes.
See [migration](migration.md).

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

The [six-case association pack](../examples/sensitive-request/associations-v1.json)
records the follow-up's known development inputs. C3 and C4 require only the
affirmatively requested `tokens` class after a shell-history prohibition; C5
requires no sensitive-request finding for a version-only request that excludes
API keys and shell history. These are regression expectations, not a measured
accuracy rate. [Association regressions](../tests/test_sensitive_associations.py)
also exercise legitimate contrasts, coordinated actions, local use, wrapped text,
warnings and reference labels. Historical sample reports and original miss bytes
remain tied to their original versions and runs.
The [September 16 association measurement](../evidence/sensitive-associations/README.md)
records the installed baseline and candidate, including false alerts and misses.

Submit a minimal **synthetic** request and legitimate contrast, expected classes
and reference status, version, command and actual output. Use reserved example
destinations. Never include real secrets, shell history, customer submissions or
private repositories. New cases should exercise relationships, not just matcher
spellings. See [contributing](../CONTRIBUTING.md).
