# Security

## The tool's own security posture

The core scan is deterministic, offline, and never calls a model — by design
it cannot be prompt-injected, because nothing in it interprets prompts (see
docs/threat-model.md for the bootstrap-paradox argument). It reads files and
never executes repo content.

## Bypasses are the contribution we want most

If you craft repo content that SHOULD be flagged and isn't: report it. Each
confirmed bypass becomes either a new rule with a caught-fixture, or a
documented entry in COVERAGE.md's known-misses ledger — publicly, credited.
Non-sensitive reports: open an issue. Sensitive ones (a shape you believe is
being exploited in the wild): GitHub private vulnerability reporting on this
repo.

## Disclosure log

- **v0.1.1** — gate bypass fixed: the intake hook originally matched only
  Bash, so an agent's file-write tools could forge the pass marker. Found in
  our own first live-session test; fixed same day (broadened matcher +
  signed marker). Logged here because a gate that quietly patches its
  bypasses is not a gate you should trust.

## What a clean scan means

"No known-shape red flags found." Never "safe." Pattern matching cannot catch
cleverly worded natural-language manipulation — we publish working examples
of exactly that in corpus/misses/. Read the instruction environment the scan
inventories for you; that inventory is arguably the most important output.
