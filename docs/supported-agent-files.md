# Supported instruction-environment surface

Files azt inventories and why they can influence an agent. If your agent
reads a file class not listed here, that is an issue worth opening.

| Class | Files | Why it matters |
|---|---|---|
| Standing instructions | `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.cursor/rules/*`, `.clinerules`, `.windsurfrules`, `.github/copilot-instructions.md`, `*.mdc` (any depth for CLAUDE/AGENTS) | Loaded as rules the agent follows |
| Skills / commands / subagents | `.claude/skills/**`, `.claude/commands/*`, `.claude/agents/*` | Loadable procedures the agent executes |
| Agent settings & hooks | `.claude/settings.json`, `.claude/settings.local.json` | Hooks run shell commands on agent events |
| MCP configs | `.mcp.json`, `mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.gemini/settings.json` | Servers launch arbitrary commands at session start |
| Auto-exec on entry | `.envrc` (direnv), `.vscode/tasks.json` (`runOn: folderOpen`), `devcontainer.json` (`postCreateCommand` etc.) | Executes without any explicit action |
| Git hooks | `.githooks/*`, `.husky/*` | Shell scripts wired to git operations |
| Package lifecycle | `package.json` (`preinstall`/`postinstall`/`prepare`) | Runs on `npm install` |
| CI workflows | `.github/workflows/*` | Automation an agent can trigger by pushing; `pull_request_target` + PR-head checkout is a takeover shape |

Plus content-level scanning of all text files for injection, execution,
exfiltration, concealment, and hidden-text shapes — full rule list in
`azt.py` (it is one readable file on purpose).
