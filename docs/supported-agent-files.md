# Input formats and analysis depth

The inventory identifies potential influence surfaces. It is not a complete
catalog of every file an agent or tool can read. Ordinary supported text files
also receive content-pattern analysis even when they are not in the inventory.

| Input | Inventory | Analysis beyond text patterns |
| --- | --- | --- |
| `CLAUDE.md`, `AGENTS.md`, `AGENTS.override.md`, `GEMINI.md`; Cursor/Cline/Windsurf rule names; `*.mdc`; Copilot instructions | Yes, using the patterns in `AGENT_SURFACE` | None |
| `.claude/skills/**`, commands and agent definitions | Yes | None; content patterns only |
| `.codex/config.toml` | Yes | None; no TOML parser or complete Codex configuration coverage |
| `.claude/settings.json`, `.claude/settings.local.json` | Yes | Bounded JSON parsing; selected hook and permission field validation; command-hook and dangerous allow-pattern findings |
| `.mcp.json`, `mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.gemini/settings.json` | Yes | Bounded JSON parsing; selected `mcpServers`/`servers`, command, arguments and URL field validation; server declarations reported |
| `package.json` | Yes | Bounded JSON parsing; script types validated; preinstall, postinstall, prepare and preprepare declarations reported |
| `.vscode/tasks.json` | Yes | Bounded JSON parsing and selected task-field validation; textual `runOn: folderOpen` detection |
| `.devcontainer/devcontainer.json`, `devcontainer.json` | Yes | None; lifecycle fields are not structurally parsed |
| `.envrc`, `.githooks/*`, `.husky/*` | Yes | None; commands are never executed |
| `.github/workflows/*.yml` and `*.yaml` | Yes | A textual pattern for selected `pull_request_target` plus PR-ref checkout shapes; no YAML parser or complete workflow semantics |
| `.azt-ignore` | Recorded as a target request | Requests counted and file hashed; never used as authoritative policy |

Inventory matching uses glob patterns against path suffixes in `azt.py`.
A recognized name can match at multiple depths; this is not a claim that any
specific agent version loads every such path.

JSON validation covers the fields used by AZT's scanners, not the complete
schema of every provider. Unsupported JSONC/comments or malformed supported
JSON produce incomplete inspection. For formats without a structural JSON
scanner, malformed configuration may still receive only text analysis.

MCP declarations are review signals. A local command, an auto-install command
and a remote endpoint do not imply identical behavior. AZT does not launch
servers, fetch their content or verify what tools they expose. It inventories
repository-local configuration; it does not discover installed user-level
agent configuration or every machine-wide skill.

## General text and scope

Supported extensions currently include Markdown/MDC/text, shell scripts,
Python, JavaScript, TypeScript, JSON, YAML, TOML, CFG, INI, envrc and extensionless
files. The report lists the exact extension set and applied analyses.
An inventoried file is eligible for text scanning even without a listed extension.

Unsupported extensions are ordinarily hashed only. Built-in VCS, dependency
and build exclusions and explicit external-policy exclusions appear in
`scope.skipped`. Skipped directories are not traversed. Symlinks and special
files are not read; they cause incomplete inspection. Relevant unreadable,
oversized, invalidly encoded or structurally invalid inputs cannot yield
passing admission.

See [COVERAGE.md](../COVERAGE.md) for limits and known misses and
[the threat model](threat-model.md) for what content binding does not enforce.
