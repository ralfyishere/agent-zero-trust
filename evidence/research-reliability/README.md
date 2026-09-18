# Research reliability — development evidence, September 18, 2026

Baseline: published 0.1.15, source
`fac2bde012f6aff84e86c67f2db2c0bc347c536b`; released wheel SHA-256
`210ff5af5c63aad60394afc31bf984b215385bb9a7c4461b46621d8645cabefb`.

First candidate: `4343c40c605df506e4fdb14d7dee700672fa7697`, 0.1.16 unreleased.
Clean local wheel `agent_zero_trust-0.1.16-py3-none-any.whl`, SHA-256
`2b433de8af8fe9c501289c8cac8a43560e53749e83b088d614de0a7df204ac09`;
sdist `agent_zero_trust-0.1.16.tar.gz`, SHA-256
`89925bd6ca64cd89bfdbdf77af78863fb3aac2ccc54e1756d7b1a747e32fa5c2`.
These identify the local build, not the hosted build or a future release.

## Static/installed observations

macOS, Python 3.11.15; fresh isolated environments, installed import confirmed,
inert README fixtures and outputs outside targets. Direct analyzer and installed
ordinary `scan --json` agreed on all 14 disclosed probes:

| Cases | Released baseline | Candidate |
|---|---|---|
| C1/C3/C4/C6: affirmative key disclosure, including contrasts | Tokens finding | Unchanged |
| C2/C5: limited version diagnostics with prohibited sensitive objects | No sensitive finding | Unchanged |
| P1/P3: token counts / parser tokens | No sensitive finding | Unchanged |
| P2/P4: measurements plus credentials / authentication token | Tokens finding | Unchanged |
| E1: version **without** keys/history; E2: send **no** keys/history | Two false alerts (one per case) | Neither alerts |
| E3: keys **must be sent**; E4: copy keys into a bug report then **submit the report** | Two misses | Tokens finding in both |

All these scans exit 0 at the unchanged default HIGH threshold. The sensitive
rule remains MEDIUM. No secret content, transmission, malicious intent or live
agent response was established. See the [34 frozen semantic contrasts and extra
boundary controls](../../tests/test_sensitive_reliability.py); expected ambiguous
and cross-window cases are limitations, not proof of benign intent. All cases
were visible during development, not held out.

Clean-source checks: scanner suite passed; **305 unit tests passed**; installed
wheel and extracted sdist tests, four-case change lab, sensitive-request lab,
captured-source lab, Action injection/exit tests and package exclusion checks
passed. No private files found in 29 wheel members / 272 sdist members.

Reproduce static verification from a reviewed checkout with declared build tools:

```sh
python3 test_azt.py
python3 -m unittest discover -s tests -q
python3 -m build
python3 scripts/test_artifact.py dist
```

The optional build frontend may require installation; scanning and tests do not
call a model or fetch fixture destinations. New artifact hashes must be measured,
not borrowed from this record.

## First actual Linux attempt — failed, preserved

[Run 35308332998](https://github.com/ralfyishere/agent-zero-trust/actions/runs/35308332998)
used the exact first candidate above on a standard ephemeral Ubuntu runner,
Docker client/server 28.0.4, cgroup v2, Python 3.12.3. Image:
`python@sha256:2fe5997d249a808b8eeea52c58a1dbffbba28754dc11699ef5c029f2d818ce79`,
executed by immutable local ID
`sha256:ec7d6c95cd3692a2e2d228a8b1ca74e4025b54121fcc4c5da6f09cfa473315ad`.

Actual hosted wheel SHA-256:
`53d3385366a88d82daa4e41935da60c808e211f9958afd7c3ae02f067314841e`;
hosted sdist SHA-256:
`a8202219616f5092aeba6217f9ffa8890133b32b1c19dcbf48ca430e4fe4a034`.
These differ from the local build; no byte-equivalence claim is made.

**12 passed, 1 failed, 0 not run; final cleanup passed; 0 live-model trials.**
Legitimate review, large source paging, 22-second preparation delay followed by
completion, expired preparation without launch, four forbidden proposals, matched
synthetic file/network controls, private state/tamper, operator stop, paused-controller
lease expiry, bounded resources/output and audit failure checks passed.
The expired-preparation check is a controller precondition, not an OS denial.

The controller-SIGKILL case failed with `FileNotFoundError` during evaluation;
the raw export retained no partial per-case observation. It is **not credited**
as a passing stop test. Code inspection identifies the unguarded supervisor-result
read as the relevant uncaught missing-file operation: Docker removal can become
visible before that result is written. Local failure-injection tests reproduce
the missing/partial-record ordering. The proposed evaluator correction waits only
inside the existing stop deadline and preserves partial stages; it does not
change the worker, supervisor, required assertions, resources or stop bound.

This summary is a selected derivative of bounded synthetic workflow output, not
a byte-identical raw export or independent audit. Private logs and checkpoints
are not published. Historical v1 research and FS-001 records remain unchanged.
The subsequent verification below tests the corrected evaluator; it does not
rewrite this failed attempt.

## Corrected evaluator — actual Linux verification

[Run 35308844187](https://github.com/ralfyishere/agent-zero-trust/actions/runs/35308844187)
tested source `988faef305189b0b2c20db74d46a35bf1f26a22e` and
tree `f1773437dcf5c6139aa9045c72b5369e855b8480`.
**13 passed, 0 failed, 0 not run; cleanup passed; 0 live-model trials.**
The [selected machine-readable record](run-35308844187.json) includes every case,
timings, source/module/evaluator hashes, backend and immutable image identity.
It omits run-local container/mission IDs, detailed worker records and private logs.
Its raw-export-line digest identifies the original input to this derivative;
it neither authenticates that input nor proves log completeness.

The complete legitimate review passed without unnecessary denials. The larger
source review and a 22-second setup delay also completed. Matched generated-file
and test-owned network controls passed. Four externally observed processes were
gone after both operator stop (0.086 s) and controller SIGKILL (0.084 s); pausing
the controller exercised the independent finite lease (19.851 s). These are
observations on this runner, not universal shutdown timing guarantees. Expired
preparation is a controller precondition check, not an exercised OS denial.

The hosted build tested these **new** distributions, without borrowing local hashes:

| Artifact | SHA-256 |
|---|---|
| `agent_zero_trust-0.1.16-py3-none-any.whl` | `6095c412bc8bbdf552356b03107569eec1fcb394c0fd6aac23eba130a38c9f6c` |
| `agent_zero_trust-0.1.16.tar.gz` | `d9868ee2d886ed32dda9f6da1ac579b945ec06e891146c692dc42d58df9b7c67` |

Clean-source local and hosted checks passed: scanner suite, **307 unit tests**,
installed wheel/extracted-sdist verification and bundled offline labs. Ordinary
PR CI also passed on Python 3.9 and 3.12. The local fresh-user README sequence
installed published 0.1.15 into a separate environment using paths with spaces;
benign and MEDIUM scans returned 0, then comparison, explanation and local HTML
export succeeded. No Docker or model was used on that macOS host.

Only finite reviewed workers ran inside disposable Linux isolation. Docker,
kernel, host, image, supervisor, controller and evaluator remain trusted. The
runtime outcome does not validate an Ollama integration or live-model behavior.
This evidence/documentation follow-up is separate from the tested code commit.
