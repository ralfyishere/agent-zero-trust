# A sensitive request, explained

This is an **illustrated demonstration of recorded CLI output**, not an AZT
graphical interface, live agent, automatic watcher, upload blocker or repair.
The two input strings are inert synthetic data. No keys were collected and no
destination was contacted. Editorial timing is not scanner performance.

The scene keeps the same instruction visible while highlighting the request,
explaining its possible consequence, showing maintained guidance and pointing to
the actual local export. The example destination is omitted in the illustration;
its reserved `example.invalid` value remains in the reproducible fixture record.

- [Desktop animation](desktop.gif) and [mobile animation](mobile.gif): 22.5-second
  repeating sequence with short transitions, readable holds and a readable reset.
- [Desktop still](desktop.png) and [mobile still](mobile.png): motion-free options.
- [Actual exported report, desktop viewport](report-desktop.png) and
  [mobile viewport](report-mobile.png): unmodified AZT HTML, not an illustrated UI.
- [Complete local HTML export](report.html), [text export](report.txt),
  [offline explanation](explanation.txt) and [command/output transcript](transcript.txt).
- [Capture identities](capture.json), [broad scan](broad-scan.json),
  [limited scan](limited-scan.json) and [editorial timeline/checks](timeline.json).

The broad API-key sharing request produces **one MEDIUM finding**,
`request.sensitive_disclosure`, with information class `tokens`. The version-only
control excluding keys/history produces none. Both inspections complete and exit
0 at the unchanged default HIGH threshold. **Exit 0 is not “no findings,” trust or
approval.** Neither wording establishes actual credentials, malicious intent or
recipient trust. These two known cases are not an accuracy measurement or an
independent audit.

## Provenance

Captured from the actual released 0.1.13 wheel, independently installed into a
fresh external virtual environment without index access or dependencies:

- Source: [`4adfa0bebefabe0c9a85b88802f709249957c464`](https://github.com/ralfyishere/agent-zero-trust/commit/4adfa0bebefabe0c9a85b88802f709249957c464).
- Release build: [35124897388](https://github.com/ralfyishere/agent-zero-trust/actions/runs/35124897388).
- Wheel: `agent_zero_trust-0.1.13-py3-none-any.whl`.
- Wheel SHA-256: `5a39a4005d75579bb5df47da2578846047900da71dd05f7fb31e2e54cc955c8b`.
- Local capture: September 16, 2026, macOS/Darwin 25.6.0, Python 3.11.15.

The scan JSON, explanation and HTML/text files contain actual CLI stdout.
`transcript.txt` labels use portable paths and annotate exit status; that
transcript is a documented derivative, not a byte-identical terminal recording.
The captured JSON records each fixture/input/engine identity and output digest.
The imported scanner/analyzer/intake/review modules were confirmed inside the
external environment and matched their bytes in the recorded release wheel.
Hashes identify these bytes; they do not authenticate a report or prove coverage.
Screenshots show only the original report's top viewport (1120×455 desktop,
390×915 mobile), ending before its structured detail; its full content is linked.

## Reproduce without executing the instructions

For the normal user workflow, use the [sensitive-request lab](../../../examples/sensitive-request/README.md).
For this exact asset capture, first obtain the release wheel through your reviewed
installation process. All following execution is offline. Keep the environment
outside the checkout and inspected fixtures:

```sh
python3 -m venv "/absolute/path/outside-project/azt-visual-env"
"/absolute/path/outside-project/azt-visual-env/bin/python" -I -m pip --isolated \
  install --no-index --no-deps "/absolute/path/to/agent_zero_trust-0.1.13-py3-none-any.whl"
python3 assets/landing/sensitive/capture.py \
  --python "/absolute/path/outside-project/azt-visual-env/bin/python" \
  --wheel "/absolute/path/to/agent_zero_trust-0.1.13-py3-none-any.whl"
```

The capture helper creates fresh temporary synthetic fixture directories, runs
the installed CLI from outside them, checks observed results, and regenerates
only the files in this asset directory. It never executes the target text.
The source strings and reserved destination are reviewable in `capture.py`.

Optional illustration regeneration uses the existing landing renderer's palette
and drawing helpers, plus **already installed** Pillow and Playwright/Chromium:

```sh
python3 assets/landing/sensitive/render.py
```

No rendering dependency is added to AZT. Chromium sandboxing remains enabled;
missing tools or platform approval is an explicit prerequisite, not permission
to download tools or disable sandboxing. The renderer checks source hashes,
text bounds, both layouts, GIF timing, actual playback after 35 seconds, static
selection for reduced motion, and that the actual report made no remote request.
The report's content security policy remains unchanged. Host playback controls
and reduced-motion preferences remain under the host/user's control.

AZT is by Rafael Peña and contributors. Drawing styles reuse the existing project
assets. See [scope and limits](../../../docs/sensitive-requests.md) before
generalizing beyond these selected English requests.
