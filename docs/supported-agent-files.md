# Supported instruction-environment surface

The files `azt` inventories, and why each can influence an agent. If your agent
reads a file class not listed here, that's an issue worth opening.

## Standing instructions (loaded as rules the agent follows)

- `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` (any depth for CLAUDE/AGENTS)
- `.cursorrules`, `.cursor/rules/*`, `.clinerules`, `.windsurfrules`, `*.mdc`
- `.github/copilot-instructions.md`

## Skills, commands, subagents (loadable procedures the agent may run)

- `.claude/skills/**`
- `.claude/commands/*`
- `.claude/agents/*`

## Agent settings and hooks (shell commands on agent events)

- `.claude/settings.json`, `.claude/settings.local.json`

## MCP configs (servers launch arbitrary commands at session start)

- `.mcp.json`, `mcp.json`
- `.cursor/mcp.json`, `.vscode/mcp.json`, `.gemini/settings.json`

## Auto-execution on entry (runs without any explicit action)

- `.envrc` (direnv)
- `.vscode/tasks.json` with `runOn: folderOpen`
- `devcontainer.json` / `.devcontainer/devcontainer.json` (`postCreateCommand`, etc.)

## Git hooks (shell scripts wired to git operations)

- `.githooks/*`, `.husky/*`

## Package lifecycle (runs on `npm install`)

- `package.json` → `preinstall` / `postinstall` / `prepare`

## CI workflows (automation an agent can trigger by pushing)

- `.github/workflows/*` — `pull_request_target` + PR-head checkout is a
  takeover shape

---

Plus content-level scanning of every text file for injection, execution,
exfiltration, concealment, and hidden-text shapes. The full rule list lives in
`azt.py` — it is one readable file on purpose.
