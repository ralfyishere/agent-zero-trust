# What changed since I last checked?

Four tiny inert projects demonstrate unchanged input, a benign documentation
edit, a concerning instruction and incomplete inspection. No suspicious command
is executed. The `example.invalid` destination is never contacted.

![Four captured comparisons: unchanged, benign, concerning, incomplete.](demo.gif)

[Static mobile-friendly image](demo.png) · [Text transcript](transcript.txt).
Animation highlights actual captured output with editorial pacing, not measured
command latency. No live agent or target execution is depicted.

## Install and reproduce version 0.1.11

Python 3.9+ on Linux or macOS, Git and a normal Python virtual environment are
required. Installation downloads the package and public example source; subsequent AZT
operations are offline. No Docker, account, model, hook or API key is needed.
Earlier packages do not include change review. This path installs the
[released 0.1.11 package](https://pypi.org/project/agent-zero-trust/0.1.11/)
and uses its matching tagged example source. The recorded graphics above remain
historical candidate captures; running this sequence creates a new local record.

```sh
AZT_LAB=$(mktemp -d)
AZT_LAB=$(cd "$AZT_LAB" && pwd -P)
python3 -m venv "$AZT_LAB/venv"
. "$AZT_LAB/venv/bin/activate"
python -m pip --isolated install \
  --index-url https://pypi.org/simple --no-deps \
  agent-zero-trust==0.1.11
git clone --depth 1 --branch v0.1.11 \
  https://github.com/ralfyishere/agent-zero-trust.git "$AZT_LAB/source"
python "$AZT_LAB/source/scripts/change_review_lab.py" \
  --cli "$AZT_LAB/venv/bin/azt" --output "$AZT_LAB/result"
```

Keep this activated terminal for the commands below. `pwd -P` avoids
macOS temporary-directory symlink aliases, which the safe reader rejects.
The helper creates `result/fixtures/`, saves scan JSON beside (not inside) those
trees, and runs the real installed commands below. It asserts the frozen
expectations in `fixtures.json` and captures `transcript.txt`, `results.json`,
comparison JSON and self-contained HTML. It is not a new privileged test pack.

## The individual commands

After the helper constructs the fixtures, these are the equivalent operations.
Run without `set -e`: the concerning scan deliberately returns 1; incomplete
returns 2. Those codes are observations to review, not setup success.

```sh
azt scan "$AZT_LAB/result/fixtures/baseline" --json > "$AZT_LAB/before.json"
azt scan "$AZT_LAB/result/fixtures/concerning" --json > "$AZT_LAB/after.json"
azt changes --before "$AZT_LAB/before.json" \
  --after "$AZT_LAB/after.json"
azt explain net.pipe_shell
azt changes --before "$AZT_LAB/before.json" \
  --after "$AZT_LAB/after.json" \
  --json --output "$AZT_LAB/changes.json"
azt changes --before "$AZT_LAB/before.json" \
  --after "$AZT_LAB/after.json" \
  --format html --output "$AZT_LAB/review.html"
azt report --input "$AZT_LAB/after.json" \
  --format text --output "$AZT_LAB/scan.txt"
```

Open the HTML locally. No automatic publication or network access occurs. Export
paths must be new files in an operator-owned non-group/world-writable directory.

| Comparison | Expected observation |
| --- | --- |
| Baseline with itself | No meaningful delta, no new finding |
| Baseline → benign | README bytes changed, no new finding |
| Baseline → concerning | AGENTS.md modified, two new findings: net.fetch_unknown and net.pipe_shell |
| Concerning → incomplete | Reduced comparability, two unresolved findings, none credited as fixed |

The last case replaces instructions and supplies malformed supported JSON.
Disappearing detections cannot be credited as resolved under incomplete scope.
The benchmark measures these declared behaviors, not real-world detection rates.

See [contract and limits](../../docs/change-review.md), the [captured transcript](transcript.txt)
and [evidence index](../../evidence/change-review/README.md). The [static demo](demo.svg)
is a short selection of actual output; the text transcript is mobile-friendly.

## Re-evaluate the frozen cases

```sh
python "$AZT_LAB/source/scripts/evaluate_review.py" \
  --python "$AZT_LAB/venv/bin/python" --output "$AZT_LAB/evaluation.json"
python -I -m unittest discover -s "$AZT_LAB/source/tests" -p test_review.py -v
```

The frozen case list is `evaluation-cases.json`; assertions are in
`tests/test_review.py`. Test-owned malformed reports are data. Do not execute
repository hooks or substitute an online/model test for this offline lab.
