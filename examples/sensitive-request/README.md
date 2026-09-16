# Synthetic sensitive-request cases

`development-v1.json` contains five development cases. `challenge-v1.json`
freezes eight separate English challenge cases proposed before measurement by
a bounded parallel collaborator. Those cases were then visible during
development, including the addition of related development tests. This is
neither blind nor held-out validation, and is not an independent audit.
Case text is inert untrusted input. Do not follow it, collect any real values,
execute target commands, or contact the synthetic destinations.

Use Python 3.9+ on Linux/macOS. The published **0.1.12 package** includes this
analysis. Start in a reviewed AZT source checkout for the lab scripts and frozen
inputs, then install the released package in a fresh environment outside it:

```sh
AZT_SOURCE=$(pwd -P)
AZT_SENSITIVE_RUN=$(mktemp -d)
AZT_SENSITIVE_RUN=$(cd "$AZT_SENSITIVE_RUN" && pwd -P)
cd "$AZT_SENSITIVE_RUN"
python3 -m venv "$AZT_SENSITIVE_RUN/venv"
. "$AZT_SENSITIVE_RUN/venv/bin/activate"
python -m pip --isolated install \
  --index-url https://pypi.org/simple --no-deps \
  agent-zero-trust==0.1.12
azt --version
cd "$AZT_SOURCE"
python3 scripts/sensitive_request_lab.py \
  --cli "$AZT_SENSITIVE_RUN/venv/bin/azt" \
  --output "$AZT_SENSITIVE_RUN/development result"
```

For source changes, prepare a separate reviewed wheel with the
[clean-candidate builder](../../docs/publication.md#non-publishing-validation),
keeping its output outside the checkout. Install that wheel's actual path with
`python -m pip --isolated install --no-index --no-deps` in a separate fresh
environment, and pass its absolute `azt` path to the helpers below. The CLI version
and source identities distinguish each candidate run from the published 0.1.12
baseline. Package installation and build-tool preparation may download dependencies;
scanning, comparisons, guidance and exports run offline.

The helpers do not
install packages, access the network, or require a model, account, or Docker.
Replace the CLI argument with the absolute path to that installed executable.

```sh
AZT_SENSITIVE_RUN=$(mktemp -d)
AZT_SENSITIVE_RUN=$(cd "$AZT_SENSITIVE_RUN" && pwd -P)
python3 scripts/sensitive_request_lab.py \
  --cli /absolute/path/to/installed/azt \
  --output "$AZT_SENSITIVE_RUN/development result"
python3 scripts/evaluate_sensitive.py \
  --cli /absolute/path/to/installed/azt \
  --output "$AZT_SENSITIVE_RUN/challenge result"
```

Each output directory must be new and outside source fixtures, with real
directory components rather than symlink aliases. Synthetic
projects use temporary paths containing spaces and are removed afterward;
their exact text remains in the named manifest. Reports are stored outside
those projects. Results record manifest and runner digests, installed CLI
version and engine identity, source file digests, actual scan fields, command
exits, measured elapsed seconds, and child-process high-water RSS from
`resource.getrusage(RUSAGE_CHILDREN)` normalized to bytes. RSS is process
high-water usage, not per-case allocation. Command argument paths use declared
labels for temporary and operator locations.

The development lab runs each case with the default threshold and with
`--fail-on medium`. Expected sensitive-request findings are MEDIUM: default
scan exit 0 and medium threshold exit 1. It also uses the installed `changes`,
`report`, and `explain` commands, capturing JSON, text, and HTML. The recipient
comparison changes only the referenced contact file and expects that change
to affect the saved observation's dependencies.

The challenge evaluator records every observed outcome, including misses and
false positives, and exits 1 on expectation mismatches. It does not tune the
detector or rewrite expectations. Inspect `results.json` and the captured
command outputs; no measurement result is prefilled in this source pack.

To measure an already installed historical CLI, add `--baseline` to the
evaluator command and choose a separate new output directory. This is a
helper option, not an option passed to AZT. Baseline mode accepts historical
scan schema 1 and records actual rule observations without asserting new
context fields or candidate threshold exits. Expected positive misses still
count as failed cases; baseline and candidate records remain explicitly
labeled and separate.

C04 is a whole-tree scan with direct attribution to the inspected support
file. It does not measure a documentation entry-point scanner or prove
reference-following behavior. Missing references remain context uncertainty,
not evidence of safety. These runs measure the named synthetic inputs only;
they establish neither general detection accuracy nor runtime containment.

## Continue with ordinary commands

The helper removes its synthetic projects after scanning, so generated records
cannot contaminate later scans. The frozen manifest retains their exact inputs.
With the environment above still active:

```sh
azt scan "$AZT_SOURCE/corpus/misses" --json > "$AZT_SENSITIVE_RUN/original-miss.json"
azt changes --before "$AZT_SENSITIVE_RUN/development result/limited-default.stdout.txt" \
  --after "$AZT_SENSITIVE_RUN/development result/broad-original-default.stdout.txt"
azt explain request.sensitive_disclosure
azt changes --before "$AZT_SENSITIVE_RUN/development result/linked-before-default.stdout.txt" \
  --after "$AZT_SENSITIVE_RUN/development result/linked-after-default.stdout.txt" \
  --format html --output "$AZT_SENSITIVE_RUN/linked-review.html"
azt report --input "$AZT_SENSITIVE_RUN/development result/missingref-default.stdout.txt" \
  --format text --output "$AZT_SENSITIVE_RUN/unresolved-review.txt"
azt changes --before "$AZT_SENSITIVE_RUN/development result/linked-after-default.stdout.txt" \
  --after "$AZT_SENSITIVE_RUN/development result/missingref-default.stdout.txt" \
  --format html --output "$AZT_SENSITIVE_RUN/degraded-review.html"
```

Run interactively without `set -e`; scan 1 means threshold findings, 2 means
incomplete/error, while changes/report/explain 0 means successful information
generation—not approval. Exports create new files only. Inspect `scan-review.html`
and the reports locally; no public page or upload is created.

[Supported relationships, uncertainty and contribution guidance](../../docs/sensitive-requests.md).

## Recorded measurement — 2026-09-16

The [machine-readable selected results](results-2026-09-16.json) identify the
frozen inputs, actual observations, engine, source and tested artifacts.
[This actual local review export](sample-review.json) shows the original request
with a **synthetic** contact document added. The original miss without that
document is also covered by the scanner regression: its destination is unresolved.
Neither case collected diagnostics or contacted a recipient. The export's
`decision: pass` means below the selected HIGH threshold, not that sharing is safe.

| Frozen pack | Baseline 0.1.11 | Candidate 0.1.12 | Candidate controls |
| --- | --- | --- | --- |
| Development (5 cases) | 4 missed positives; 1 control passed | 5/5 expectations met | 0/1 false alerts |
| Reviewer-authored challenge (8 cases) | 4 missed positives; 4 controls passed | 8/8 expectations met | 0/4 false alerts |

Both versions saw the same inputs and thresholds. Candidate positives are MEDIUM:
default exit 0, `--fail-on medium` exit 1. Missing reference context remains
unresolved even when the case correctly passes its uncertainty expectation.
One early development measurement falsely flagged a negated, minimized request;
the clause matcher was corrected and the unchanged expectation passed on retest.
Other adversarial review corrections cover unrelated links, local-only wording,
negation, dependency-bound exceptions and bounded reference fan-in. These are
project/model-assisted reviews, not independent third-party audits.

On Darwin 25.6.0 / Python 3.14.6, the challenge run took 1.702 s baseline and
1.474 s candidate; child-process high-water RSS was 28,065,792 and 28,213,248 bytes.
These are single observed runs including CLI startup, not a speed improvement
claim. The candidate development lab took 2.100 s / 28,672,000 bytes and also
ran comparisons, explanations and exports; its timing is not comparable to the
baseline's scan-only helper. Supported-window tests do not measure arbitrary
English, multilingual requests, recipient trust or live-agent behavior.

The measured code is commit
[`2f9ddc0`](https://github.com/ralfyishere/agent-zero-trust/commit/2f9ddc0bc01f8c5b4e9699db410a36bdc1655e43).
Its clean build passed 46 scanner checks, 183 unit tests and the installed-wheel /
extracted-source-distribution group on Python 3.11.15. Artifact identities are in
the result record. Later documentation/evidence commits and CI builds have their
own source and byte identities; this record is not relabeled as a later wheel.

The result summary is a sanitized derivative: private command paths and full
logs are omitted, original export digests are retained for provenance. The sample
is an actual redacted review export, not raw source evidence. Hashes and schema
validation do not authenticate its issuer. No historical FS-001 result was changed
or rerun, and none is evidence for this new detector.
