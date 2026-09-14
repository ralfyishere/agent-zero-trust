# Reproduction evidence

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
