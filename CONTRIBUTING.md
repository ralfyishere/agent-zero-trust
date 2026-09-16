# Contributing

New here? [Find a contribution that fits you](docs/community.md)—from making a
warning clearer to reproducing a false alert. You do not need security expertise
or a code change to submit useful, synthetic feedback.

For sensitive-request corrections, start with [the inert lab](examples/sensitive-request/README.md)
and [supported relationships](docs/sensitive-requests.md). Submit a minimal
synthetic request plus a legitimate contrast, expected information classes and
reference status, and actual output. Never attach real diagnostics or credentials.
Run `python3 -m unittest discover -s tests -p 'test_sensitive*.py' -v`.

Start with repository intake: a minimal missed-detection fixture, a benign
false-positive example or a confusing first-run result is useful. See the
[published-package demo](docs/demo.md) and [known misses](COVERAGE.md).
The optional safety pack below has separate execution prerequisites.

## Safety regression packs

The first reviewed case is [AZT-FS-001 v1](packs/AZT-FS-001/v1/README.md).
Run `python3 -m unittest discover -s tests -v` for offline tests. Run
`python3 scripts/test_safety_integration.py --wheel <candidate.whl> --output <new-directory>`
only on the supported authorized Linux Docker host with an approved preloaded
image. Missing backends and mocks do not count as containment proof. Keep intake
and execution results separate. Propose another case first as a failing test
with a legitimate-task control; code/expectations cannot be chosen by target
repository metadata. Optional [continuity notes](docs/optional-continuity.md)
use Piénsalo without making it a dependency or security authority.

Use the [clean wheel/sdist and runtime reproduction](docs/reproduce-fs001.md).
The integration helper accepts `--case canonical` or `--case variant`; each
uses fresh synthetic resources. The variant's reviewed inputs are frozen by
digest in `tests/test_safety_reporting.py`. Preserve the assertions when fixing
defects. Report stage counts separately from terminal outcomes according to
[safety evidence v2](docs/safety-reporting-v2.md), including partial failures.

Help make unfamiliar-repository intake understandable and reproducible.
A useful contribution can be a small failing test, a false-positive fixture,
a clearer explanation of scope or an independently reproduced result.

Keep fixtures synthetic. Treat every instruction, shell command and URL in
`corpus/` as untrusted data; never execute or contact it. Do not submit secrets,
private repositories, customer information or unsupported incident claims.

## Development

Python 3.9+ on Linux or macOS is required for the safe filesystem reader.
From a trusted checkout:

```sh
python3 test_azt.py
python3 -m unittest discover -s tests -v
python3 scripts/containmentbench.py
python3 scripts/test_artifact.py --action-only
```

The standalone scanner has no third-party runtime dependencies. To test
packaging in a development virtual environment:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install build
.venv/bin/python -m build
.venv/bin/python scripts/test_artifact.py dist
```

Build dependency installation requires a network connection or cache. The
artifact test installs the candidate wheel into a separate temporary environment
with `--no-index --no-deps`, verifies the imported module came from that
environment, and checks actual CLI results. Use a dist directory containing
exactly one candidate wheel. The action input test uses Bash.

Run `python3 azt.py scan . --json` for an unfiltered self-review. The scanner
source, corpus and security documentation intentionally contain findings.
This command is not expected to admit AZT's own repository, and a failing
exit status alone is not proof that the scanner worked. Inspect the result.
Do not add a blanket exception to make CI green.

## Changes we can review

For saved-scan review, run the [change-review lab](examples/change-review/README.md)
and `python3 -m unittest discover -s tests -p test_review.py -v`.
The frozen case list lives beside the lab; change expectations explicitly before
measuring. Keep incomplete/ambiguous observations visible and include benign
controls. [Three small contributor issue drafts](docs/change-review-contributions.md)
have tests and definitions of done; no extra public issues are required.

For a detection change, include a malicious fixture that triggers the rule
and a benign case that should remain clean. Explain the format and scope the
rule covers. Prefer an actual evasion or configuration edge case to a string
copied from the implementation.

For policy or admission changes, show what input was authorized, what changed,
and why the current check must accept or reject it. A hash is not a signature;
same-user writable state is not an OS boundary. Preserve the known-miss ledger.

Record exact commands and actual outcomes. Label mocks, skipped cases and
untested platforms. Do not commit invented successful demo logs. Before changing
security claims, identify the enforcing component and the regression that
exercises it.

## Small contributor roadmap

1. Refine the known-miss DNS-table regression and the DNS execution rule
   without turning ordinary Markdown tables into false positives.
2. Add a bounded devcontainer lifecycle parser with malformed-config tests
   and benign fixtures; update format coverage to reflect exactly what it handles.
3. Expand configuration-shape tests using primary format documentation,
   including fields not currently analyzed, without claiming complete schema validation.
4. Reproduce the local intake benchmark on Linux and report platform, command
   and actual output. Runtime isolation work has separate prerequisites and
   acceptance tests in [docs/runtime.md](docs/runtime.md).

Use the bypass or false-positive issue template, or a blank issue for backend
and documentation reports. Include the command, version and synthetic reproduction.
Sensitive reports follow [SECURITY.md](SECURITY.md). No CLA or DCO obligation
is introduced; the existing MIT license and attribution remain in place.

Rafael (Ralph) Peña is the creator and maintainer. Credit contributors and upstream
work accurately. The related projects remain separate: rules-with-receipts for
operating discipline, rulebench for behavioral testing, and agent-failure-modes
for failure taxonomy. Avoid copying another scanner engine into this repository.

Release preparation and immutable action-pin updates are described in
[release readiness](docs/release-readiness.md). Publishing and repository settings
remain owner decisions.
