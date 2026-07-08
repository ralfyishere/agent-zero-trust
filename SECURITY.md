# Security

## The tool's own posture

- Deterministic, offline, no model calls. Nothing in the core interprets
  prompts, so nothing in it can be prompt-injected (the bootstrap-paradox
  argument is in [docs/threat-model.md](threat-model.md)).
- It reads files. It never executes repo content.
- Gate mode is a speed bump, not a sandbox: it enforces "a scan happened,"
  not "the agent is contained."

## Reporting

- **Non-sensitive** (a bypass, a false positive): open an issue. Templates
  guide you through what we need.
- **Sensitive** (a shape you believe is being exploited in the wild): use
  GitHub's private vulnerability reporting on this repo.

## Bypasses are the contribution we want most

Craft repo content that *should* be flagged and isn't, and report it. Each
confirmed bypass becomes one of two things, publicly and credited:

- a new rule, with a fixture that trips it, or
- a documented entry in [COVERAGE.md](../COVERAGE.md)'s known-misses ledger.

Both improve the ledger. Only silence doesn't.

## Disclosure log

- **v0.1.1 — gate bypass fixed.** The intake hook originally matched only
  Bash, so an agent's file-write tools could forge the pass marker. Found in
  our own first live-session test; fixed the same day (broadened matcher plus
  a signed marker). Logged here because a gate that quietly patches its
  bypasses is not a gate you should trust.

## What a clean scan means

"No known-shape red flags found." Never "safe." Pattern matching cannot catch
cleverly worded natural-language manipulation — we ship working examples of
exactly that in `corpus/misses/`. The instruction-environment inventory the
scan prints is arguably its most important output; read it.
