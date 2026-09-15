# Front-page presentation assets

These are designed summaries, not unedited terminal captures or new release
measurements. AZT means Agent Zero Trust; the project was created by Rafael
(Ralph) Peña, with contributors. The palette continues the existing
[`assets/launch`](../launch/) artwork. Historical assets remain unchanged.

| Asset | Use |
| --- | --- |
| `hero.svg` / `hero.png` | Compact 1600×500 README banner |
| `hero-mobile.svg` / `hero-mobile.png` | 720×600 narrow-screen banner |
| `social-preview.svg` / `social-preview.png` | Separate 1280×640 social card, PNG under 1 MB |
| `change-review.svg` / `change-review.png` | 1280×720 static demonstration |
| `change-review-mobile.svg` / `change-review-mobile.png` | 720×960 readable stacked demonstration |
| `change-review.gif` | Four frames, 16 seconds, one playback; editorial timing, not scan latency |

## Evidence and meaning

Source: the existing [captured transcript](../../examples/change-review/transcript.txt),
[synthetic inputs](../../examples/change-review/fixtures.json),
[lab result](../../evidence/change-review/lab-py311.json) and
[redacted comparison](../../evidence/change-review/concerning-changes.json).
Their recorded implementation is
[`0296facec2565668386c3c0d5dbacb734e6241e3`](https://github.com/ralfyishere/agent-zero-trust/commit/0296facec2565668386c3c0d5dbacb734e6241e3),
a 0.1.11 candidate, as identified in the [historical evidence index](../../evidence/change-review/README.md).
The new graphics do not relabel those records as results of a later source or
published artifact. The original candidate-labeled graphics and transcript are
preserved.

The before/after wording is the exact fixture instruction, visually wrapped.
The concerning `AGENTS.md` change has two new findings: `net.fetch_unknown`
and `net.pipe_shell`. The next-step text is selected from the recorded offline
rule guidance. The benign README edit has zero new findings. Incomplete
inspection retains two unresolved observations; disappearing observations are
not credited as proven fixes. An unchanged input has no meaningful delta.

These are static inspection and comparison results. The suspicious instruction
was not executed and its destination was not contacted. Findings are prompts
for contextual review, not evidence of malicious intent, runtime blocking,
automatic monitoring, authorization or general containment. This is not a live
agent demonstration. [Run the reproducible lab](../../examples/change-review/README.md).

## Render locally

The optional `render.py` uses already-installed Playwright with its local Chromium
browser and Pillow. These are editorial tools, not AZT dependencies. It does not
install anything or use a network service; Chromium's sandbox remains enabled.
From this checkout with those tools available:

```sh
python3 assets/landing/render.py
```

It validates the recorded fixture hash and selected expected observations before
rendering, checks SVG text stays on the canvas, optimizes PNGs, and validates the
GIF's finite playback and duration. Intermediate animation frames use a temporary
directory and are not committed. SVG sources are editable; standard system fonts
are referenced, not redistributed. Different local fonts/browser versions can
change rendered bytes. Review both desktop and mobile output after regeneration.

The README retains real text, commands, navigation and static alternatives; no
important prerequisite is only available inside an image. The social card is an
upload-ready file, not an indication that repository settings were changed.
