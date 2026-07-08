---
name: Bypass report
about: Repo content that SHOULD be flagged and isn't (the most-wanted contribution)
title: "Bypass: <short description>"
labels: bypass report
---

**The content that slips through** (a file or minimal repo azt scans clean but
that could steer/compromise an agent):

```
<paste the file content, or link a minimal repo>
```

**Why an agent would act on it:**

**What azt currently reports** (`azt scan <path>` output):

Per SECURITY.md: every confirmed bypass becomes either a new rule (with a
caught-fixture) or a public entry in COVERAGE.md's known-misses ledger.
Credited either way.
