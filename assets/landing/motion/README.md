# Motion-first change-review demo

Four distinct views replace the dense overview: baseline instruction, changed
instruction, two findings with plain-language labels and rule IDs, then guidance
and local export. Labels are editorial explanations, not extra scanner output.
The "list" is the text rule's built-in download-host allowlist, not a runtime
permission or a claim that listed hosts are safe.
Each frame lasts 2.5 seconds; the 10-second sequence plays three times, then stops. Timing is
editorial, not scan latency. Static images support reduced-motion preferences.

This is a new design derivative of the same historical 0.1.11 candidate capture
at `0296facec2565668386c3c0d5dbacb734e6241e3`; it is not a fresh terminal recording.
[Source records and limitations](../README.md#evidence-and-meaning) are unchanged.
No target instruction was executed. No runtime protection or approval is shown.

Render with the already-installed local Playwright browser and Pillow:
`python3 assets/landing/motion/render.py`. It reuses the reviewed parent renderer's
source checks and drawing helpers, with Chromium's sandbox enabled. No download
or AZT dependency is added. Existing published artwork remains untouched.
