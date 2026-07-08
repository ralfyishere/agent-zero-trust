---
name: False positive
about: Benign content azt wrongly flags (treated as a bug, not noise)
title: "False positive: <rule id>"
labels: false positive
---

**Rule that fired:** (e.g. `net.pipe_shell`)

**Benign content that tripped it:**

```
<paste the line/file>
```

**Why it's benign:**

This becomes a regression line in `corpus/benign-repo/` or a rule refinement.
The benign-repo fixture is asserted at zero MEDIUM+ findings in CI, so your
example is protected against future rules.
