# Reproduction evidence

## Experimental filesystem regression

**Final candidate:** code `94a802bbe8b54e86b730203051b9abc162cf0da8`,
[run 34915008373](https://github.com/ralfyishere/agent-zero-trust/actions/runs/34915008373),
canonical **3/3** and nested-source variant **3/3** complete phases passed.
Read the [results, artifacts and limitations](fs001-0.1.9/README.md) and
[sanitized machine-readable record](fs001-0.1.9/34915008373.json).
Progress stages overlap; six stages per phase are not six independent successes.
This index was added in a later evidence/documentation-only commit, not another
runtime verification. [Historical interpretations](fs001-0.1.9/history.json)
are labeled derivatives, not edits to old raw exports.

Canonical AZT-FS-001 passed baseline / deliberate exposure / repaired checks
at source `6d1bc83e99856cab3fcfb3ee1578ddf0ee1e97bc` in
[run 34912218459](https://github.com/ralfyishere/agent-zero-trust/actions/runs/34912218459).
All three completed probe, strict result export, exact edited-file and coding
task verification, original-fixture integrity and cleanup. The unsafe phase
PASS means intentional exposure was demonstrated, not that its configuration
is safe. This is one trusted-probe synthetic Docker/Linux case, not an audit or
live-agent integration. Later source changes need their own verification.

Historical failures remain: [34910385576](https://github.com/ralfyishere/agent-zero-trust/actions/runs/34910385576)
failed workflow validation before jobs; [34911273066](https://github.com/ralfyishere/agent-zero-trust/actions/runs/34911273066)
completed three probes, including verified exposure, but failed result collection
and had no fully passed phases. Its old `executed=0` meant no completed result
collections, not no probes. Raw historical records are not rewritten.

See [reproduction](../docs/reproduce-fs001.md), [reporting semantics](../docs/safety-reporting-v2.md)
and the frozen [variant](../packs/AZT-FS-001/v1/variant/README.md). The final
candidate record above identifies its own code/artifact/run, separate from these
historical results. No intake count below is runtime evidence.

## Historical scanner-hardening record

The following 0.1.8 record is historical and preserved unchanged as the scanner
milestone's evidence. It does not identify the later 0.1.9 source/artifact.
New safety-pack outputs are separate; a blocked runtime record is not containment
evidence. See `safety-0.1.9/` when reviewing the new candidate.

`scanner-0.1.8/` contains actual generated output for the unreleased scanner
candidate, not a hand-authored successful transcript. `results.json` identifies
the exact engine/evaluator source hashes and wheel SHA-256. `inputs.json`
contains only synthetic data; `review.patch` is the benign arithmetic change.
The issuer key is never exported. Temporary workspaces and state are cleaned up.

Reproduce with the command in [docs/evidence.md](../docs/evidence.md). New runs
will have different receipt IDs, timestamps, workspace IDs, file-mode/platform
details and installation-specific hook content digests. Verify their decisions,
rule identities and independently checked arithmetic result, not byte equality
with this machine's receipt. Standard scan JSON on unchanged inputs is deterministic.

The evaluator belongs to this project and runs outside the target's authority.
It is not a third-party audit. No hostile workload ran: admission rejection and
a trusted benign task are the tested operations. Runtime trials and the fair
disposable-baseline/backend/AZT comparison remain unexecuted.

Recorded wheel run: 11/11 executed checks passed, zero failed, eight runtime
scenarios not run, zero runtime trials. Elapsed time was 2.3528 seconds including
clean offline wheel installation on Darwin 25.6.0 / Python 3.14.6. The benign
arithmetic program returned `5 0`, the evaluator confirmed the original fixture
was unchanged, and the patch contains only the intended arithmetic correction.

Additional local verification: 45/45 legacy corpus/unit checks and 38/38 new
unittest cases passed on Python 3.9.6 and 3.14.6. Six action argument cases and
clean installed-wheel CLI checks passed on 3.9.6, 3.11 and 3.14.6. All five JSON
schemas and generated nested scan/receipt reports validated with jsonschema
4.26.0; workflow/action/citation YAML parsed. These counts include diagnostic
mocks and fault injection and are not a count of OS boundary trials.
