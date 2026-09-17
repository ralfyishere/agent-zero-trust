# A helpful-looking diagnostic request deserves a second look

The illustration starts with a familiar situation: **your app will not start,
and the project asks for diagnostics.** That situation is editorial framing,
not a recorded application failure or a quotation from the fixtures.

The recorded example compares two existing, frozen synthetic documents:

1. A limited request: share the Python version and `AZT_LOG_LEVEL`; keep
   credentials and private configuration local.
2. A broad request: collect shell history, environment variables and local
   configuration, then share them using a contact in another local document.

The inputs are the unchanged `limited` and `broad-original` cases from
[development-v1.json](../../../examples/sensitive-request/development-v1.json).
They are treated as before/after snapshots for the demonstration, not presented
as an actual pull request, intercepted upload or live-agent session. The broad
README preserves the original diagnostic-request fixture verbatim; its contact
file contains only a reserved synthetic address.

## What the released tool actually reported

| Observation | Limited request | Broad request |
| --- | --- | --- |
| Inspection | Complete: 1 file | Complete: 2 files |
| Total findings | 0 | 1 MEDIUM |
| Sensitive request | Not observed | `request.sensitive_disclosure` |
| Selected HIGH threshold | Not exceeded; exit 0 | Not exceeded; exit 0 |
| MEDIUM threshold control | Exit 0 | Exceeded; exit 1 |

The [actual comparison](evidence/changes.txt) is comparable and reports one new
finding. It does not report that the project is safe or grant permission.

The [actual local report](evidence/report.txt) says:

> This request asks you to share configuration, environment variables, shell history.
> These materials may contain credentials or private activity.

The observation binds `README.md:3–7` and
`docs/maintainer-contact.txt:1`. It records one explicit email destination from
that supported local reference, but does **not** verify the recipient. Recipient
values and request excerpts are omitted by the reporting defaults.

The maintained next step is:

> Verify the request independently, provide only necessary diagnostics, and inspect
> the exact contents before sharing.

The animation abbreviates this guidance; it is an illustration of recorded CLI
results, not a graphical AZT application. No diagnostic collection, upload,
target command, agent, blocking or automatic repair was performed.

## Reproduce without downloads

Requires Python 3.9+ with `venv`/`ensurepip` on Linux or macOS, this reviewed
repository checkout, and the already-downloaded
`agent_zero_trust-0.1.14-py3-none-any.whl` release wheel. Obtaining Python, the
repository or wheel is a separate installation step that may need internet
access. This capture helper does not download anything.

From the repository root, set `AZT_WHEEL` to that explicit local wheel:

```sh
AZT_SOURCE=$(pwd -P)
AZT_RECORDING=$(mktemp -d)
AZT_WHEEL="/absolute/path/to/agent_zero_trust-0.1.14-py3-none-any.whl"
python3 -I "$AZT_SOURCE/assets/landing/diagnostic-story/capture.py" \
  --wheel "$AZT_WHEEL" \
  --output "$AZT_RECORDING/diagnostic review"
```

Expected final message:

```text
Captured two frozen scans, threshold checks, comparison, guidance and local exports; all assertions passed.
```

The helper validates the exact wheel and fixture-pack digests before use. It
creates a fresh temporary virtual environment outside the inspected targets,
installs only that wheel with `--no-index --no-deps`, and checks the installed
module hashes against the wheel. Python runs with `-I`, a cleared environment
and an external working directory. Paths containing spaces are exercised.
Temporary environments and fixture copies are removed on completion; only the
explicit new output directory is retained. Existing captures are not overwritten.

The operations performed are the normal released workflow below. These are
portable labels for the helper's temporary paths; the exact exits and output
identities are retained in [capture.json](evidence/capture.json).

```sh
azt scan fixtures/limited --json > before.json
azt scan fixtures/broad-original --json > after.json
azt changes --before before.json --after after.json --json > changes.json
azt explain request.sensitive_disclosure
azt report --input after.json --format html --output 'local review.html'
```

The helper separately checks the MEDIUM-threshold exit of 1 as an expected
finding result; it does not hide execution failures. Both default-threshold
scans above return 0 despite the broad case's MEDIUM warning. Reports and
environments remain outside the inspected fixture trees. For a larger
interactive lab, use the existing
[sensitive-request lab](../../../examples/sensitive-request/README.md).

## Provenance and inspectable output

- Released implementation:
  [`fce49dd727f1be4ba4407394a6b4f544e763ef20`](https://github.com/ralfyishere/agent-zero-trust/tree/fce49dd727f1be4ba4407394a6b4f544e763ef20).
- Release build:
  [35176398216](https://github.com/ralfyishere/agent-zero-trust/actions/runs/35176398216).
- Wheel SHA-256:
  `be250d871a1b3783423ac92e96238e5154beec4b358015c07371ddecdf98db68`.
- Frozen fixture pack SHA-256:
  `10929881e531a9de75e9f71b40a2db1a55f6c1e95178ea078860b7b04c8d9941`.
- [Capture, environment, command exits and output hashes](evidence/capture.json).
- [Selected synthetic input bytes and hashes](evidence/fixtures.json).
- [Before scan](evidence/before.json), [after scan](evidence/after.json),
  [before terminal output](evidence/before.txt), [after terminal output](evidence/after.txt),
  [structured comparison](evidence/changes.json),
  [recorded command/output transcript](evidence/transcript.txt),
  [maintained guidance](evidence/explanation.txt), and
  [local HTML report](evidence/report.html).

The saved CLI outputs are unchanged stdout bytes. The HTML file also exactly
matches the separately tested `--output` export. These outputs already use AZT's
default omissions; the exported review is a **redacted derivative**, not the
original input evidence. `fixtures.json` separately records the explicitly
synthetic source text. Command labels are normalized to portable paths; personal
capture paths are not published. No recipient value appears in the scan,
comparison or report exports.

This is a reproducible illustration using two known development cases, not
held-out evaluation, evidence of actual disclosure, a user study or runtime
containment. It exercises selected English wording and an explicit one-hop local
reference. Hashes identify these records; they do not authenticate a report or
prove general detection coverage.

## Illustration and motion-free alternatives

[render.py](render.py) is optional asset tooling using already-available Pillow,
Playwright and Chromium. It does not install or download those tools; they are
not AZT runtime dependencies. From an environment where they are already
installed, run `python assets/landing/diagnostic-story/render.py` from the
repository root after capturing the evidence.

The desktop and mobile GIFs repeat a 26-second sequence, with editorial pacing
rather than measured command latency. [timeline.json](timeline.json) records
the rendered timings and identities. The static [desktop](desktop.png) and
[mobile](mobile.png) views preserve the finding and next step without motion.
Separate [before](desktop-before.png), [changed request](desktop-changed.png)
and [finding](desktop-finding.png) stills make the sequence inspectable; mobile
equivalents are included beside them. The README's picture sources provide
reduced-motion alternatives without changing a visitor's playback preferences.

The report images are cropped views of the finding paragraph in the unmodified
[actual HTML export](evidence/report.html), not a replacement interface. The
illustration's short “Ask for less” closing line summarizes the maintained
guidance to verify the request and share only necessary information; AZT does
not make that decision or perform a repair on the user's behalf.
