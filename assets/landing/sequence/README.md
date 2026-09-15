# Connected change-review illustration

One persistent `AGENTS.md` card changes in place, then its review appears beside
it (below it on mobile). The result remains connected to the changed instruction
while guidance and a local HTML review are introduced. The final static view is
available without motion. Existing presentation and historical evidence assets
are unchanged.

- [Desktop GIF](desktop.gif) · [PNG](desktop.png) · [editable SVG](desktop.svg)
- [Mobile GIF](mobile.gif) · [PNG](mobile.png) · [editable SVG](mobile.svg)
- [Exact editorial timeline and rendering checks](timeline.json)

The GIFs loop every 22 seconds. Text transitions are brief fades inside stationary
panels, with longer reading holds and a return to the original instruction before
replay. This is editorial timing, not a benchmark. Use the static PNGs for a
motion-free view.

## What this depicts

**Illustrated recorded CLI workflow**, not a shipped graphical interface, an
unedited terminal recording, live monitoring or fresh execution evidence. The
instruction strings are copied from the frozen
[synthetic inputs](../../../examples/change-review/fixtures.json) and only
visually wrapped. The suspicious instruction is never executed; its destination
is never contacted.

The concerning change produces two new findings in the
[recorded transcript](../../../examples/change-review/transcript.txt) and
[comparison](../../../evidence/change-review/concerning-changes.json):
`net.pipe_shell` (HIGH) and `net.fetch_unknown` (MEDIUM). The latter means the host
is outside the scanner's small allowlist, not that the destination is proven
malicious. The plain-language explanation summarizes what this instruction asks
an agent to do. “Review the source before using it” summarizes the recorded
offline guidance; a documented installer may have a legitimate use.

The illustrated `review.html` is a local export outcome, not a hosted result or a
copied screenshot of AZT's report layout. The recorded
[lab helper](../../../scripts/change_review_lab.py) exercised HTML export for each
case, using case-specific names such as `concerning.html`; `review.html` is the
equivalent example name used by the quickstart. No output is automatically
uploaded, no instruction is approved, and no repair is performed.

These records identify implementation
[`0296facec2565668386c3c0d5dbacb734e6241e3`](https://github.com/ralfyishere/agent-zero-trust/commit/0296facec2565668386c3c0d5dbacb734e6241e3),
a **0.1.11 candidate**, as preserved in the
[historical evidence index](../../../evidence/change-review/README.md).
The animation does not relabel those captures as results from a later commit or
published artifact. Companion cases remain important: the benign edit has zero
new findings; incomplete comparison retains two unresolved observations. “No
longer observed” is not “proven fixed.” [Reproduce the lab](../../../examples/change-review/README.md).

## Re-render

Use the already-installed local Python environment with Playwright, its Chromium
browser and Pillow. These optional editorial tools are not product dependencies.
No downloads, target commands, model calls or remote services are used.

```sh
python3 assets/landing/sequence/render.py
```

The renderer imports the existing reviewed parent drawing helpers and evidence
assertions, without invoking the old renderer or rewriting its assets. It verifies
the recorded fixture hash, findings, instruction wrapping, visible SVG text
bounds, GIF duration/loop and size. Temporary frames remain outside the checkout.
Chromium's browser sandbox stays enabled. Font/browser changes may alter rendered
bytes; inspect both widths after regeneration. Standard system fonts are
referenced, not redistributed.
