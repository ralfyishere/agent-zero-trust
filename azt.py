"""agent-zero-trust (azt) — zero-trust repo intake for AI coding agents.

A repository is no longer just code: for an AI coding agent it is an
INSTRUCTION ENVIRONMENT. Markdown files, agent config files, hooks, MCP
server definitions, package scripts, and CI workflows can all steer or
compromise an agent that reads them. `azt scan` inventories that instruction
environment and flags known-shape risks BEFORE an agent enters the repo.

Design commitments (see docs/threat-model.md):
- Deterministic and offline. No model calls, ever, in the core scan. A
  scanner that asks an LLM whether content is safe to show an LLM is itself
  injectable by that content.
- Honest scope. Pattern matching catches known shapes; it CANNOT catch
  cleverly worded natural-language social engineering. A clean scan means
  "no known-shape red flags", never "safe". Known misses are published in
  corpus/misses/ and COVERAGE.md.
- Single file, stdlib only, Python 3.9+. Read what you run.

Engine provenance: extracted and extended from `rulebench vet`
(https://github.com/ralfyishere/rulebench), same maintainer, same rules
lineage; rulebench now covers the rules-file niche, azt covers whole-repo
intake.
"""
import argparse
import fnmatch
import json
import os
import re
import sys
import time
import unicodedata
from pathlib import Path

__version__ = "0.1.0"

SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}

# ---------------------------------------------------------------------------
# Rule set. Each: (id, severity, explanation, regex).
# HIGH = plausible direct harm if an agent follows it. MEDIUM = read before
# trusting. INFO = part of the instruction-environment map.
# ---------------------------------------------------------------------------
TEXT_RULES = [
    # --- network / execution ---
    ("net.pipe_shell", "HIGH",
     "Pipe-to-shell: downloads and executes remote code in one step",
     r"(?:curl|wget|iwr|invoke-webrequest)\b[^\n|]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|python3?|node|pwsh)"),
    ("net.fetch_unknown", "MEDIUM",
     "Network fetch to a non-allowlisted host in an instruction/setup context",
     r"\b(?:curl|wget)\s+[^\n]*https?://(?!(?:github\.com|raw\.githubusercontent\.com|docs\.|localhost|127\.0\.0\.1))"),
    ("net.reverse_shell", "HIGH",
     "Reverse-shell shape (nc -e, /dev/tcp, socket-to-shell)",
     r"\bnc\b[^\n]{0,40}\s-e\s|/dev/tcp/|\bsocat\b[^\n]{0,40}exec|\bsh\s+-i\s+[^\n]{0,20}(?:&|\|)"),
    ("net.dns_exec", "HIGH",
     "Command material retrieved via DNS TXT records",
     r"(?:dig|nslookup|host)\b[^\n]{0,60}\btxt\b[^\n]{0,60}\|"),
    ("exec.encoded", "HIGH",
     "Encoded-then-executed content (base64/hex decoded into a shell or eval)",
     r"base64\s+(?:-d|--decode)[^\n]{0,40}\|[^\n]{0,30}(?:bash|sh|python|eval)|echo\s+[A-Za-z0-9+/=]{40,}[^\n]{0,30}\|\s*base64|eval\s*\(\s*atob|exec\s*\(\s*(?:base64|bytes\.fromhex)"),
    ("exec.always_run", "MEDIUM",
     "Always-run directive: pressures the agent to execute on every session / without asking",
     r"(?:always|every\s+time|automatically|without\s+(?:asking|confirmation|approval)|before\s+(?:anything|responding|you\s+(?:start|begin)))[^\n]{0,60}(?:run|execute|exec|source|install|fetch|send|upload)"),
    ("exec.destructive", "HIGH",
     "Destructive command: irreversible deletion or force operations",
     r"\brm\s+-[rf]{1,2}\b\s+(?:~|/|\$HOME)|\bgit\s+push\s+(?:-f|--force)|\bdrop\s+(?:table|database)\b|\bmkfs\b|\bdd\s+if="),
    # --- credentials / exfiltration ---
    ("cred.env_source", "HIGH",
     "Credential access: sources or reads secret/env/key files",
     r"(?:source|cat|read|export|load|dotenv)[^\n]{0,40}(?:\.env\b|\.npmrc|\.netrc|credentials|secrets?\b|id_rsa|\.pem|\.aws|\.ssh)"),
    ("exfil.pipe_out", "HIGH",
     "Exfiltration shape: reads local data then sends it to a network endpoint",
     r"(?:cat|read|find|env|printenv|history)\b[^\n]{0,60}\|[^\n]{0,40}(?:curl|wget|nc|netcat|mail)|curl\s+[^\n]{0,60}(?:-d|--data|-F|--upload-file)\s+@"),
    ("secret.token_shape", "MEDIUM",
     "Token-shaped string present in the tree (verify it is a placeholder)",
     r"\b(?:sk-ant-[A-Za-z0-9-]{20,}|ghp_[A-Za-z0-9]{30,}|gho_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[0-9A-Z]{16}|xox[bp]-[A-Za-z0-9-]{20,})"),
    ("secret.private_key", "HIGH",
     "Private key material in the tree",
     r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    # --- agent-directed manipulation ---
    ("inject.instruction_override", "HIGH",
     "Instruction-override language aimed at the agent",
     r"(?:ignore|disregard|override|forget)\s+(?:all\s+)?(?:previous|prior|above|earlier|your)\s+(?:instructions|rules|guidelines|prompt)"),
    ("inject.concealment", "HIGH",
     "Tells the agent to hide activity from the human",
     r"do\s+not\s+(?:tell|mention|inform|alert|show)[^\n]{0,40}\buser\b|without\s+(?:telling|informing|notifying)\s+the\s+user|\bsecretly\b|keep\s+this\s+(?:hidden|secret)\s+from"),
    ("inject.agent_directed", "MEDIUM",
     "Agent-directed imperative in a general doc (docs are for humans; direct agent address is a smell)",
     r"^\s*(?:>\s*)?(?:if\s+you\s+are\s+an?\s+(?:ai|llm|agent|assistant)|as\s+an?\s+(?:ai|llm)\s|dear\s+(?:ai|assistant|claude|copilot|cursor|gemini))"),
    ("stealth.html_comment_imperative", "HIGH",
     "Imperative instruction hidden in an HTML comment (invisible when rendered, visible to the model)",
     r"<!--[^>]{0,200}\b(?:run|execute|curl|wget|ignore|disregard|source|install|upload|send|fetch)\b"),
    ("stealth.hidden_unicode", "HIGH",
     "Zero-width or bidirectional-override characters (can hide text from human review)",
     "[​‌‍‎‏‪-‮⁠-⁤⁦-⁩﻿]"),
]
COMPILED = [(rid, sev, desc, re.compile(pat, re.I)) for rid, sev, desc, pat in TEXT_RULES]

# Rules whose signal depends on a shell pipe; markdown table rows use `|` as a
# separator, so skip those rules on table-looking lines (false-positive class
# inherited from rulebench vet's regression suite).
PIPE_DEPENDENT = {"net.pipe_shell", "exfil.pipe_out", "net.dns_exec"}
MD_TABLE = re.compile(r"^\s*\|.*\|\s*$|^\s*\|?[\s:-]+\|[\s:|-]*$")

# ---------------------------------------------------------------------------
# Instruction-environment inventory: files that can influence an agent.
# (class, severity-of-presence, glob patterns, why it matters)
# ---------------------------------------------------------------------------
AGENT_SURFACE = [
    ("instructions", "INFO",
     ["CLAUDE.md", "AGENTS.md", "GEMINI.md", ".cursorrules", ".clinerules",
      ".windsurfrules", ".cursor/rules/*", ".github/copilot-instructions.md",
      "**/CLAUDE.md", "**/AGENTS.md", "*.mdc"],
     "read as standing instructions by coding agents"),
    ("skills_commands", "INFO",
     [".claude/skills/**/SKILL.md", ".claude/commands/*", ".claude/agents/*"],
     "loadable procedures/commands an agent may execute"),
    ("agent_settings", "MEDIUM",
     [".claude/settings.json", ".claude/settings.local.json"],
     "can define hooks that execute shell commands on agent events"),
    ("mcp_config", "MEDIUM",
     [".mcp.json", "mcp.json", ".cursor/mcp.json", ".vscode/mcp.json",
      ".gemini/settings.json"],
     "MCP servers launch arbitrary commands when a session starts"),
    ("auto_exec", "MEDIUM",
     [".envrc", ".vscode/tasks.json", ".devcontainer/devcontainer.json",
      "devcontainer.json"],
     "can auto-execute on folder open / environment entry"),
    ("git_hooks", "MEDIUM",
     [".githooks/*", ".husky/*"],
     "shell scripts wired to git operations"),
    ("package_scripts", "INFO",
     ["package.json"],
     "lifecycle scripts (preinstall/postinstall) run on install"),
    ("ci_workflows", "INFO",
     [".github/workflows/*.yml", ".github/workflows/*.yaml"],
     "automation an agent may trigger by pushing"),
]

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist",
             "build", ".tox", ".mypy_cache", "target", ".next"}
TEXT_EXT = {".md", ".mdc", ".txt", ".sh", ".bash", ".zsh", ".py", ".js", ".ts",
            ".json", ".yml", ".yaml", ".toml", ".cfg", ".ini", ".envrc", ""}
MAX_BYTES = 1_000_000


def walk_repo(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            yield Path(dirpath) / name


def classify_surface(root, files):
    """Map each agent-surface file to its class."""
    hits = []
    rels = {str(f.relative_to(root)).replace(os.sep, "/"): f for f in files}
    for cls, sev, globs, why in AGENT_SURFACE:
        for rel, f in rels.items():
            for g in globs:
                if fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(Path(rel).name, g):
                    hits.append({"class": cls, "severity": sev, "path": rel, "why": why})
                    break
    seen, out = set(), []
    for h in hits:
        if h["path"] not in seen:
            seen.add(h["path"]); out.append(h)
    return out


def scan_text_file(rel, text):
    findings = []
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        table_row = bool(MD_TABLE.match(line)) or line.count("|") >= 3
        for rid, sev, desc, pat in COMPILED:
            if table_row and rid in PIPE_DEPENDENT:
                continue
            if pat.search(line):
                excerpt = line.strip()
                if len(excerpt) > 120:
                    excerpt = excerpt[:117] + "..."
                # Make hidden unicode visible in the excerpt
                if rid == "stealth.hidden_unicode":
                    excerpt = "".join(
                        "\\u%04x" % ord(c) if unicodedata.category(c) in ("Cf", "Co") else c
                        for c in excerpt)[:120]
                findings.append({"rule": rid, "severity": sev, "description": desc,
                                 "path": rel, "line": i, "excerpt": excerpt})
    return findings


# --- structural scanners ----------------------------------------------------

def scan_mcp(rel, text):
    out = []
    try:
        cfg = json.loads(text)
    except Exception:
        return out
    servers = cfg.get("mcpServers") or cfg.get("servers") or {}
    for name, s in (servers.items() if isinstance(servers, dict) else []):
        cmd = " ".join([str(s.get("command", ""))] + [str(a) for a in s.get("args", [])])
        sev, why = "MEDIUM", "MCP server '%s' executes at session start: %s" % (name, cmd.strip())
        if re.search(r"curl|wget|bash\s+-c|https?://", cmd, re.I):
            sev, why = "HIGH", "MCP server '%s' fetches/executes remote content: %s" % (name, cmd.strip())
        elif re.search(r"npx\s+(-y|--yes)", cmd):
            why += " (npx -y auto-installs the package unprompted)"
        out.append({"rule": "mcp.server", "severity": sev, "description": why,
                    "path": rel, "line": 0, "excerpt": cmd.strip()[:120]})
    return out


def scan_claude_settings(rel, text):
    out = []
    try:
        cfg = json.loads(text)
    except Exception:
        return out
    hooks = cfg.get("hooks", {})
    for event, entries in (hooks.items() if isinstance(hooks, dict) else []):
        for e in entries if isinstance(entries, list) else []:
            for h in e.get("hooks", []):
                cmd = str(h.get("command", ""))
                sev = "HIGH" if re.search(r"curl|wget|\bnc\b|base64", cmd, re.I) else "MEDIUM"
                out.append({"rule": "hooks.claude", "severity": sev,
                            "description": "Claude Code %s hook runs a shell command — read it before starting a session" % event,
                            "path": rel, "line": 0, "excerpt": cmd[:120]})
    return out


def scan_package_json(rel, text):
    out = []
    try:
        pkg = json.loads(text)
    except Exception:
        return out
    for script in ("preinstall", "postinstall", "prepare", "preprepare"):
        cmd = (pkg.get("scripts") or {}).get(script)
        if cmd:
            sev = "HIGH" if re.search(r"curl|wget|https?://|base64|\bnode\s+-e\b", cmd, re.I) else "MEDIUM"
            out.append({"rule": "pkg.lifecycle", "severity": sev,
                        "description": "package.json %s runs automatically on install" % script,
                        "path": rel, "line": 0, "excerpt": cmd[:120]})
    return out


def scan_workflow(rel, text):
    out = []
    if re.search(r"^\s*pull_request_target\s*:", text, re.M) and re.search(r"ref:\s*\$\{\{\s*github\.event\.pull_request", text):
        out.append({"rule": "ci.prt_checkout", "severity": "HIGH",
                    "description": "workflow runs on pull_request_target AND checks out the PR head — classic CI takeover shape",
                    "path": rel, "line": 0, "excerpt": ""})
    return out


def scan_tasks_json(rel, text):
    out = []
    if re.search(r'"runOn"\s*:\s*"folderOpen"', text):
        out.append({"rule": "auto.vscode_folderopen", "severity": "HIGH",
                    "description": "VS Code task auto-runs when the folder is opened",
                    "path": rel, "line": 0, "excerpt": ""})
    return out


def scan_symlinks(root):
    out = []
    for f in walk_repo(root):
        if f.is_symlink():
            try:
                resolved = f.resolve()
                if root.resolve() not in resolved.parents and resolved != root.resolve():
                    out.append({"rule": "fs.symlink_escape", "severity": "MEDIUM",
                                "description": "symlink resolves outside the repository",
                                "path": str(f.relative_to(root)), "line": 0,
                                "excerpt": "-> %s" % resolved})
            except Exception:
                pass
    return out


STRUCTURAL = [
    (re.compile(r"(^|/)(\.mcp\.json|mcp\.json)$"), scan_mcp),
    (re.compile(r"(^|/)\.claude/settings(\.local)?\.json$"), scan_claude_settings),
    (re.compile(r"(^|/)package\.json$"), scan_package_json),
    (re.compile(r"(^|/)\.github/workflows/[^/]+\.ya?ml$"), scan_workflow),
    (re.compile(r"(^|/)\.vscode/tasks\.json$"), scan_tasks_json),
]


# --- ignore mechanism ---------------------------------------------------------

def load_ignores(root):
    """.azt-ignore lines: 'RULE_ID path-glob' (glob optional, '*' default)."""
    ig = []
    p = root / ".azt-ignore"
    if p.exists():
        for line in p.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            ig.append((parts[0], parts[1] if len(parts) > 1 else "*"))
    return ig


def is_ignored(finding, ignores):
    for rule, glob in ignores:
        if (rule == "*" or finding["rule"] == rule or finding["rule"].startswith(rule + ".")) \
                and fnmatch.fnmatch(finding["path"], glob):
            return True
    return False


# --- scan orchestration ---------------------------------------------------------

def scan_repo(root):
    root = Path(root)
    files = [f for f in walk_repo(root) if not f.is_symlink()]
    inventory = classify_surface(root, files)
    findings = []
    for f in files:
        rel = str(f.relative_to(root)).replace(os.sep, "/")
        try:
            if f.stat().st_size > MAX_BYTES or f.suffix.lower() not in TEXT_EXT:
                continue
            text = f.read_text(errors="replace")
        except Exception:
            continue
        for pat, scanner in STRUCTURAL:
            if pat.search(rel):
                findings += scanner(rel, text)
        findings += scan_text_file(rel, text)
    findings += scan_symlinks(root)
    ignores = load_ignores(root)
    findings = [f for f in findings if not is_ignored(f, ignores)]
    findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["path"], f["line"]))
    return inventory, findings


def print_report(root, inventory, findings):
    print("agent-zero-trust v%s — repo intake scan of %s\n" % (__version__, root))
    print("INSTRUCTION ENVIRONMENT: %d file(s) can influence an agent here" % len(inventory))
    by_class = {}
    for h in inventory:
        by_class.setdefault(h["class"], []).append(h["path"])
    for cls, paths in sorted(by_class.items()):
        print("  %-16s %s" % (cls, ", ".join(sorted(paths)[:6]) + (" (+%d more)" % (len(paths) - 6) if len(paths) > 6 else "")))
    print()
    high = [f for f in findings if f["severity"] == "HIGH"]
    med = [f for f in findings if f["severity"] == "MEDIUM"]
    if not findings:
        print("FINDINGS: none — no known-shape risks found")
    else:
        print("FINDINGS: %d HIGH, %d MEDIUM" % (len(high), len(med)))
        for f in findings:
            loc = ":%d" % f["line"] if f["line"] else ""
            print("  [%-6s] %s  %s%s" % (f["severity"], f["rule"], f["path"], loc))
            print("           %s" % f["description"])
            if f["excerpt"]:
                print("           > %s" % f["excerpt"])
    print()
    print("TRUST VERDICT: ", end="")
    if high:
        print("HIGH RISK — do not run an agent in this repo until the findings above are reviewed by a human.")
    elif med:
        print("REVIEW FIRST — read each MEDIUM finding before letting an agent operate here.")
    else:
        print("no known-shape red flags. This is NOT a safety guarantee: pattern matching cannot catch"
              "\ncleverly worded natural-language manipulation (see COVERAGE.md and corpus/misses/). Skim"
              "\nthe instruction-environment files above before trusting them.")


def cmd_scan(args):
    root = Path(args.target)
    if not root.is_dir():
        print("azt: %s is not a directory" % root, file=sys.stderr)
        return 2
    inventory, findings = scan_repo(root)
    if args.json:
        print(json.dumps({"version": __version__, "inventory": inventory,
                          "findings": findings}, indent=2))
    else:
        print_report(root, inventory, findings)
    thresh = {"high": 0, "medium": 1, "any": 2}[args.fail_on]
    worst = min((SEV_ORDER[f["severity"]] for f in findings), default=99)
    failed = worst <= thresh
    if args.gate and not failed:
        marker = root / ".claude" / ".azt-intake-pass"
        marker.parent.mkdir(exist_ok=True)
        marker.touch()
        print("\n(gate opened: %s)" % marker)
    return 1 if failed else 0


GATE_HOOK_CMD = "azt gate-check"


def cmd_install_hook(args):
    """Wire a PreToolUse hook: no tool runs until an intake scan has passed."""
    root = Path(args.target)
    settings = root / ".claude" / "settings.json"
    settings.parent.mkdir(exist_ok=True)
    cfg = {}
    if settings.exists():
        cfg = json.loads(settings.read_text())
    pre = cfg.setdefault("hooks", {}).setdefault("PreToolUse", [])
    if any(GATE_HOOK_CMD in h.get("command", "") for e in pre for h in e.get("hooks", [])):
        print("azt: intake gate already wired in %s" % settings)
        return 0
    pre.append({"matcher": "Bash",
                "hooks": [{"type": "command", "command": GATE_HOOK_CMD}]})
    settings.write_text(json.dumps(cfg, indent=2) + "\n")
    print("azt: intake gate wired in %s" % settings)
    print("Sessions in this repo now require a fresh `azt scan --gate .` pass "
          "before Bash commands run (TTL %d min; AZT_INTAKE_TTL_MIN overrides)." % default_ttl())
    return 0


def default_ttl():
    try:
        return int(os.environ.get("AZT_INTAKE_TTL_MIN", "1440"))
    except ValueError:
        return 1440


def cmd_gate_check(_args):
    root = Path(os.environ.get("CLAUDE_PROJECT_DIR", "."))
    marker = root / ".claude" / ".azt-intake-pass"
    if marker.exists():
        age_min = (time.time() - marker.stat().st_mtime) / 60
        if age_min <= default_ttl():
            return 0
        stale = " (last pass %dmin ago; TTL %dmin)" % (age_min, default_ttl())
    else:
        stale = ""
    sys.stderr.write(
        "BLOCKED by agent-zero-trust intake gate: this workspace has no fresh intake scan%s.\n"
        "Run: azt scan --gate .   — review any findings with the user before proceeding.\n"
        "The user can force-open with: touch .claude/.azt-intake-pass\n" % stale)
    return 2


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="azt",
        description="Zero-trust repo intake for AI coding agents. Offline, deterministic, no model calls. "
                    "A clean scan means 'no known-shape red flags', NOT 'safe'.")
    ap.add_argument("--version", action="version", version="agent-zero-trust %s" % __version__)
    sub = ap.add_subparsers(dest="cmd")
    sp = sub.add_parser("scan", help="scan a repository before an agent enters it")
    sp.add_argument("target", nargs="?", default=".")
    sp.add_argument("--json", action="store_true", help="machine-readable output")
    sp.add_argument("--fail-on", choices=["high", "medium", "any"], default="high")
    sp.add_argument("--gate", action="store_true",
                    help="on pass, write .claude/.azt-intake-pass (opens the intake gate)")
    ih = sub.add_parser("install-hook", help="wire the intake gate into .claude/settings.json")
    ih.add_argument("target", nargs="?", default=".")
    sub.add_parser("gate-check", help="(hook entrypoint) exit 2 unless a fresh intake pass exists")
    args = ap.parse_args(argv)
    if args.cmd == "scan":
        return cmd_scan(args)
    if args.cmd == "install-hook":
        return cmd_install_hook(args)
    if args.cmd == "gate-check":
        return cmd_gate_check(args)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
