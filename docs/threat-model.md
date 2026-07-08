# Threat model

## The premise

An AI coding agent reads files and follows instructions with tool access. To
such an agent, a repository is not data — it is an **instruction
environment**: every Markdown file, agent config, hook definition, MCP server
entry, lifecycle script, and CI workflow is potentially executable influence.
Cloning an unknown repo and starting an agent in it is running untrusted code
with your credentials.

## Attacker stories (in scope)

1. **The malicious repo you clone.** A plausible-looking project whose
   TROUBLESHOOTING.md, CONTRIBUTING.md, or hidden HTML comments instruct the
   agent to fetch-and-execute, exfiltrate environment data, or conceal
   activity from the user. Documented in the wild (HTML-comment injection,
   "helpful diagnostic command" lures).
2. **The malicious contribution into a repo you trust.** A PR or dependency
   adds an instruction file, an MCP server, a postinstall script, a
   pull_request_target workflow, or a devcontainer command that activates the
   next time an agent (or CI) touches the repo.
3. **The compromised instruction file.** A previously benign CLAUDE.md /
   .cursor/rules / skill / hook edited to add an always-run directive or an
   exfiltration step — small diffs in files humans rarely re-read.

## What azt does about them

- **Inventory** the full instruction environment (14+ file classes) so nothing
  influences an agent invisibly.
- **Flag known shapes**: pipe-to-shell, encoded execution, reverse shells,
  DNS-TXT command retrieval, exfiltration pipes, credential reads,
  instruction overrides, concealment directives, agent-directed imperatives
  in human docs, hidden unicode, HTML-comment imperatives, auto-exec configs
  (MCP servers, folderOpen tasks, .envrc, lifecycle scripts, hooks,
  pull_request_target checkouts), token shapes, private keys, symlink escapes.
- **Gate, optionally**: `azt install-hook` blocks an agent's shell access in a
  workspace until `azt scan --gate` has passed, so intake cannot be forgotten.

## Design commitments

- **The core is deterministic and offline — never an agent, never a model
  call.** There is a bootstrap paradox in LLM-based screening: content being
  judged can inject the judge. A security scanner vulnerable to the attack it
  screens is worse than none, because it manufactures false confidence. azt's
  core cannot be prompt-injected because nothing in it interprets prompts.
- **Findings are evidence, not verdicts.** Every finding carries the rule id,
  file, line, and excerpt so a human can check the claim in seconds.
- **False positives are treated as bugs** (rule-scoped, path-scoped
  `.azt-ignore`; a benign-repo regression fixture in CI).

## Explicit non-goals (out of scope)

- **Semantic judgment of natural language.** Pure social engineering with no
  trigger shapes will pass the scan. This is a hard limit of pattern
  matching, we publish the misses (corpus/misses/, COVERAGE.md), and the
  trust verdict says so on every clean scan.
- **Secrets scanning depth.** We flag token *shapes* we meet along the way;
  run a dedicated tool (gitleaks, trufflehog) for real secrets coverage.
- **Your agent's own tool stack.** MCP servers configured on YOUR machine,
  marketplace skills, and agent app configs are [Snyk agent-scan /
  mcp-scan](https://github.com/invariantlabs-ai/mcp-scan)'s territory; azt
  scans the REPO you're about to enter. Run both — they compose.
- **Runtime behavior monitoring.** azt is static intake. What the agent does
  after admission is the discipline layer's job
  ([rules-with-receipts](https://github.com/ralfyishere/rules-with-receipts)).
- **Sandboxing / policy enforcement frameworks.** See Microsoft's
  agent-governance-toolkit for that layer.

## Residual risk after a clean scan

Real and stated on every run: novel shapes, natural-language manipulation,
instructions split across files, content fetched at runtime, and anything in
files over 1 MB or binary formats. A clean scan buys you an inventory and the
absence of known shapes — nothing more. Read the instruction environment.
