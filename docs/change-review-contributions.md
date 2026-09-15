# Three small contributor issues (drafts, not posted)

1. **Add one independently reproduced saved-report regression.** Supply synthetic
   before/after reports demonstrating an incorrect delta, plus a benign control.
   Definition of done: a failing test in `tests/test_review.py`, a narrow fix,
   updated frozen case list and actual installed-wheel result. No private paths.
2. **Improve one rule's contextual guidance.** Choose an ambiguous legitimate
   use, cite a primary specification if needed and propose clearer manual review.
   Definition of done: all five catalog fields remain useful, offline `explain`
   and HTML export agree, unknown-rule behavior and catalog coverage tests pass.
   Do not weaken a detection just to make the example green.
3. **Reproduce the four-case lab on another supported Linux installation.**
   Definition of done: exact source/wheel hash, Python/platform, complete output,
   all four outcomes and installation errors; no Docker or target execution.
   Distinguish a contributor reproduction from the maintainer's repeated runs.
