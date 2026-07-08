# Contributing

The house rule from the sibling repos applies: no claims without receipts.

**New rule** = the rule + a corpus fixture that trips it + a benign line that
must NOT trip it (false positives are bugs here, not noise). PRs that add a
rule without both fixtures will be asked for them.

**Bypass report** = the most valuable contribution (see SECURITY.md).

**False positive report** = second most valuable: real-world content that azt
wrongly flags. It becomes a regression line in corpus/benign-repo/ or a
rule refinement.

Run before pushing: `python test_azt.py && python azt.py scan . --fail-on high`

Related projects: agent-side tool scanning is
[mcp-scan / Snyk agent-scan](https://github.com/invariantlabs-ai/mcp-scan)'s
lane; behavioral rules testing is [rulebench](https://github.com/ralfyishere/rulebench);
the failure taxonomy is [agent-failure-modes](https://github.com/ralfyishere/agent-failure-modes).
