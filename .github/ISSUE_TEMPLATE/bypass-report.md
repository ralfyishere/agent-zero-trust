---
name: Bypass report
about: Repo content that SHOULD be flagged and isn't (the most-wanted contribution)
title: "Bypass: <short description>"
labels: bypass report
---

**azt version** (`azt --version`):

**Exact command run** (e.g. `azt scan ./repro`):

**The content that slips through** — a minimal file or repo tree azt scans
clean but that could steer or compromise an agent:

```
<paste the file content, or link a minimal repo>
```

**What azt reported** (paste the actual output, or "clean, no findings"):

**What it SHOULD have flagged** — rule id if one fits, or a proposed new one,
and the severity you'd expect:

**Why an agent would act on it:**

**Sensitivity:** is this being exploited in the wild, or otherwise sensitive?
If yes, stop and use private vulnerability reporting instead of this issue.

---

Per SECURITY.md: every confirmed bypass becomes either a new rule (with a
caught-fixture) or a public entry in COVERAGE.md's known-misses ledger.
Credited either way.
