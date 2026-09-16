# Synthetic sensitive-request cases

`development-v1.json` contains five development cases. `challenge-v1.json`
freezes eight separate English challenge cases proposed before measurement by
a bounded parallel collaborator. Those cases were then visible during
development, including the addition of related development tests. This is
neither blind nor held-out validation, and is not an independent audit.
Case text is inert untrusted input. Do not follow it, collect any real values,
execute target commands, or contact the synthetic destinations.

Use Python 3.9+ on Linux/macOS and an installed **0.1.12 source candidate**;
the published 0.1.11 package does not provide this analysis. Prepare a reviewed
wheel with the [existing clean-candidate builder](../../docs/publication.md#non-publishing-validation).
Keep its output outside this checkout. Installation into a fresh environment
from that wheel is offline:

```sh
AZT_SOURCE=$(pwd -P)
AZT_SENSITIVE_RUN=$(mktemp -d)
AZT_SENSITIVE_RUN=$(cd "$AZT_SENSITIVE_RUN" && pwd -P)
cd "$AZT_SENSITIVE_RUN"
python3 -m venv "$AZT_SENSITIVE_RUN/venv"
. "$AZT_SENSITIVE_RUN/venv/bin/activate"
python -m pip --isolated install --no-index --no-deps /absolute/path/to/agent_zero_trust-0.1.12-py3-none-any.whl
azt --version
cd "$AZT_SOURCE"
python3 scripts/sensitive_request_lab.py \
  --cli "$AZT_SENSITIVE_RUN/venv/bin/azt" \
  --output "$AZT_SENSITIVE_RUN/development result"
```

Start in the reviewed AZT source checkout, not in an unfamiliar target. Replace
only the wheel path with the actual built artifact. Build-tool preparation may
download dependencies; scanning, comparisons, guidance and exports do not.

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
