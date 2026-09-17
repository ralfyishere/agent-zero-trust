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
  arbitrary natural-language social engineering. Selected bounded English
  sensitive-disclosure requests are analyzed contextually. A clean scan means
  "no known-shape red flags", never "safe". Known misses are published in
  corpus/misses/ and COVERAGE.md.
- Stdlib only, Python 3.9+. Read what you run.

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

import azt_intake
import azt_gate

__version__ = "0.1.15"

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
     r"\b(?:curl|wget)\s+[^\n]*https?://(?!(?:[a-z0-9-]+\.)*(?:github\.com|githubusercontent\.com|localhost|127\.0\.0\.1)(?:[:/?#]|$))"),
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

# Rules whose signal is JUST a bare shell pipe `|`; markdown table rows use `|`
# as a cell separator, so these are skipped on table-looking lines to avoid a
# false-positive class. Only net.dns_exec qualifies: its regex ends in a bare
# `|` that a table separator satisfies. net.pipe_shell and exfil.pipe_out were
# REMOVED (2026-07-10) because their regexes require a specific dangerous command
# on BOTH sides of the pipe (curl…|…bash, cat…|…curl), which does not occur in
# benign tables — so suppressing them only created a bypass: wrapping a payload
# in a table cell (`| curl x | bash |`) downgraded a HIGH finding to a passing
# MEDIUM. Residual (ledgered): a table-wrapped `dig … txt … | sh` still evades
# net.dns_exec; net.dns_exec is obscure and its bare trailing pipe cannot be run
# on tables without a large FP class. See test_azt.py ("unit checks: evasion bypasses").
PIPE_DEPENDENT = {"net.dns_exec"}
MD_TABLE = re.compile(r"^\s*\|.*\|\s*$|^\s*\|?[\s:-]+\|[\s:|-]*$")

# ---------------------------------------------------------------------------
# Instruction-environment inventory: files that can influence an agent.
# (class, severity-of-presence, glob patterns, why it matters)
# ---------------------------------------------------------------------------
AGENT_SURFACE = [
    ("instructions", "INFO",
     ["CLAUDE.md", "AGENTS.md", "AGENTS.override.md", "GEMINI.md", ".cursorrules", ".clinerules",
      ".windsurfrules", ".cursor/rules/*", ".github/copilot-instructions.md",
      "**/CLAUDE.md", "**/AGENTS.md", "*.mdc"],
     "read as standing instructions by coding agents"),
    ("skills_commands", "INFO",
     [".claude/skills/*", ".claude/commands/*", ".claude/agents/*"],
     "loadable procedures/commands an agent may execute"),
    ("agent_settings", "MEDIUM",
     [".claude/settings.json", ".claude/settings.local.json"],
     "can define hooks that execute shell commands on agent events"),
    ("agent_config", "INFO", [".codex/config.toml"],
     "agent configuration; text patterns only, no TOML structural analysis"),
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




def classify_surface(root, files):
    """Map each agent-surface file to its class."""
    hits = []
    rels = {str(f.relative_to(root)).replace(os.sep, "/"): f for f in files}
    for cls, sev, globs, why in AGENT_SURFACE:
        for rel, f in rels.items():
            for g in globs:
                if any(fnmatch.fnmatchcase("/".join(rel.split("/")[i:]), g)
                       for i in range(len(rel.split("/")))):
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
    servers = list((cfg.get("mcpServers") or {}).items()) + list((cfg.get("servers") or {}).items())
    for name, s in servers:
        cmd = " ".join([str(s.get("command", ""))] + [str(a) for a in s.get("args", [])])
        sev, why = "MEDIUM", "MCP server '%s' executes at session start: %s" % (name, cmd.strip())
        if re.search(r"curl|wget|bash\s+-c|https?://", cmd, re.I):
            sev, why = "HIGH", "MCP server '%s' fetches/executes remote content: %s" % (name, cmd.strip())
        elif re.search(r"npx\s+(-y|--yes)", cmd):
            why += " (npx -y auto-installs the package unprompted)"
        if s.get("url"):
            sev = "MEDIUM"
            if cmd.strip():
                sev = "HIGH" if re.search(r"curl|wget|bash\s+-c|https?://", cmd, re.I) else "MEDIUM"
        out.append({"rule": "mcp.server", "severity": sev, "description": why,
                    "path": rel, "line": 0, "excerpt": cmd.strip()[:120]})
    return out


# settings.json permissions.allow can pre-approve commands so they run WITHOUT the
# human confirmation prompt — the most dangerous field in the file. Flag unrestricted
# Bash (Bash(*) / Bash(:*)) and any allow entry granting a dangerous command.
PERM_UNRESTRICTED = re.compile(r"\bBash\(\s*:?\*\s*\)", re.I)
PERM_DANGER = re.compile(r"\b(?:rm\s+-[rf]|curl|wget|nc|netcat|base64|chmod|sudo|mkfs|dd\s+if=|eval)", re.I)


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
    perms = cfg.get("permissions", {})
    allow = perms.get("allow", []) if isinstance(perms, dict) else []
    for entry in allow if isinstance(allow, list) else []:
        s = str(entry)
        if PERM_UNRESTRICTED.search(s) or PERM_DANGER.search(s):
            out.append({"rule": "perm.auto_approve", "severity": "HIGH",
                        "description": "settings pre-approve a dangerous/unrestricted command — it will run without the human confirmation prompt",
                        "path": rel, "line": 0, "excerpt": s[:120]})
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




STRUCTURAL = [
    (re.compile(r"(^|/)(\.mcp\.json|mcp\.json|\.gemini/settings\.json)$"), scan_mcp),
    (re.compile(r"(^|/)\.claude/settings(\.local)?\.json$"), scan_claude_settings),
    (re.compile(r"(^|/)package\.json$"), scan_package_json),
    (re.compile(r"(^|/)\.github/workflows/[^/]+\.ya?ml$"), scan_workflow),
    (re.compile(r"(^|/)\.vscode/tasks\.json$"), scan_tasks_json),
]


# --- scan orchestration ---------------------------------------------------------

def scan_report(root, policy=None, fail_on="high", capture=None):
    report = azt_intake.inspect(root, sys.modules[__name__], policy, capture=capture)
    import azt_review
    report["engine"] = azt_review.engine_identity(sys.modules[__name__])
    threshold = {"high": 0, "medium": 1, "any": 2}[fail_on]
    failed = any(SEV_ORDER[f["severity"]] <= threshold for f in report["findings"])
    report["threshold"] = fail_on
    report["decision"] = "incomplete" if not report["scope"]["complete"] else ("deny" if failed else "pass")
    return report


def scan_repo(root):
    """Compatibility tuple API; findings are always unsuppressed by the target.

    New consumers should use scan_report to inspect completeness and policy.
    """
    report = scan_report(root)
    return report["inventory"], report["findings"]


def print_report(root, inventory, findings, summary=None):
    print("agent-zero-trust — repo intake scan of %s\n" % azt_intake.safe_label(root))
    if summary:
        print(summary + '\n')
    print("RECOGNIZED SPECIAL SURFACES: %d file(s) match inventory patterns" % len(inventory))
    print("Other inspected content, including README files, can also influence an agent.")
    by_class = {}
    for h in inventory:
        by_class.setdefault(h["class"], []).append(h["path"])
    for cls, paths in sorted(by_class.items()):
        print("  %-16s %s" % (cls, ", ".join(azt_intake.safe_label(p) for p in sorted(paths)[:6]) + (" (+%d more)" % (len(paths) - 6) if len(paths) > 6 else "")))
    print()
    high = [f for f in findings if f["severity"] == "HIGH"]
    med = [f for f in findings if f["severity"] == "MEDIUM"]
    if not findings:
        print("FINDINGS: none — no known-shape risks found")
    else:
        print("FINDINGS: %d HIGH, %d MEDIUM, %d INFO" %
              (len(high), len(med), sum(f['severity'] == 'INFO' for f in findings)))
        for f in findings:
            loc = ":%d" % f["line"] if f["line"] else ""
            print("  [%-6s] %s  %s%s" % (f["severity"], f["rule"], azt_intake.safe_label(f["path"]), loc))
            print("           %s" % azt_intake.safe_label(f["description"]))
            if 'sensitive_request' in f:
                import azt_sensitive
                print(azt_sensitive.summary(f['sensitive_request']))
                if 'exception_refusal' in f:
                    print('Exception not applied: '+f['exception_refusal'])
            if f["excerpt"]:
                print("           > %s" % f["excerpt"])
    print()
    print("REVIEW GUIDANCE: ", end="")
    if high:
        print("HIGH RISK — do not run an agent in this repo until the findings above are reviewed by a human.")
    elif med:
        print("REVIEW FIRST — read each MEDIUM finding before letting an agent operate here.")
    else:
        print("no known-shape red flags. This is NOT a safety guarantee: pattern matching cannot catch"
              "\ncleverly worded natural-language manipulation (see COVERAGE.md and corpus/misses/). Skim"
              "\nthe instruction-environment files above before trusting them.")


def emit_error(args, message, decision="error"):
    message = azt_intake.safe_label(message)
    if getattr(args, "json", False):
        print(json.dumps({"schema_version": 1, "version": __version__,
                          "decision": decision, "error": message}, sort_keys=True))
    print("azt: " + message, file=sys.stderr)
    return 2


def cmd_scan(args):
    try:
        report = scan_report(args.target, args.policy, args.fail_on)
        if args.gate and report["decision"] == "pass":
            # A second bounded read catches normal concurrent edits. This is not
            # an atomic filesystem snapshot or hostile-writer runtime boundary.
            second = scan_report(args.target, args.policy, args.fail_on)
            if second != report:
                raise azt_intake.IntakeError("workspace or policy changed during admission; retry on a quiescent tree")
            report["admission"] = azt_gate.issue(args.target, args.state_dir, report,
                                                args.fail_on, args.ttl_minutes)
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True))
        else:
            import azt_review
            print_report(args.target, report["inventory"], report["findings"],
                         azt_review.scan_summary(report))
            scope = report["scope"]
            for item in scope["errors"] + scope["skipped"]:
                print("  %s: %s" % (azt_intake.safe_label(item["path"]), azt_intake.safe_label(item["reason"])))
            print("EXCEPTIONS: %d target requests (not applied); %d trusted suppressed findings" %
                  (sum(r["requested_lines"] for r in report["target_requests"]), len(report["suppressed_findings"])))
            for request in report["target_requests"]:
                print("  target request source %s: %d lines, not applied (sha256 %s)" %
                      (azt_intake.safe_label(request["path"]), request["requested_lines"], request["sha256"]))
            for finding in report["suppressed_findings"]:
                print("  %s %s: %s; policy %s (%s)" %
                      (finding["rule"], azt_intake.safe_label(finding["path"]),
                       azt_intake.safe_label(finding["exception"]["reason"]),
                       azt_intake.safe_label(report["policy"]["source"]), report["policy"]["digest"]))
            if "admission" in report:
                print("Snapshot admitted; receipt stored outside workspace. No runtime containment.")
        return {"pass": 0, "deny": 1, "incomplete": 2}[report["decision"]]
    except (OSError, ValueError, RuntimeError) as exc:
        return emit_error(args, str(exc) if isinstance(exc, azt_intake.IntakeError) else
                          "input or evidence-store operation failed; no admission issued")


GATE_HOOK_CMD = "azt gate-check"


class GateDeadline(Exception):
    """Must propagate through per-file error handling to stop the whole check."""


def cmd_install_hook(args):
    """Install an honest workflow hook using descriptor-relative safe writes."""
    import shlex
    root = Path(os.path.abspath(args.target))
    fd = None
    try:
        # Validate operator storage before touching the target.
        store = azt_gate.open_store(args.state_dir, root, create=True)
        os.close(store)
        # Validate policy now so installation cannot embed a target-owned policy.
        scan_report(root, args.policy, args.fail_on)
        fd = azt_intake.open_absolute(root, directory=True)
        try:
            os.mkdir(".claude", 0o755, dir_fd=fd)
        except FileExistsError:
            pass
        child = os.open(".claude", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        os.close(fd)
        fd = child
        cfg = {}
        try:
            source = os.open("settings.json", os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=fd)
        except FileNotFoundError:
            pass
        else:
            try:
                raw, _ = azt_intake.read_fd(source, MAX_BYTES)
                cfg = azt_intake.json_object(raw.decode("utf-8"))
                azt_intake.validate_config("scan_claude_settings", cfg)
            finally:
                os.close(source)
        command = [str(Path(sys.executable).resolve()), str(Path(__file__).resolve()), "gate-check",
                   "--state-dir", str(Path(os.path.abspath(args.state_dir))), "--fail-on", args.fail_on]
        if args.policy:
            command.extend(["--policy", str(Path(os.path.abspath(args.policy)))])
        pre = cfg.setdefault("hooks", {}).setdefault("PreToolUse", [])
        if cfg.get("disableAllHooks"):
            raise azt_intake.IntakeError("project settings disable all hooks; installation refused")
        try:
            local = os.open("settings.local.json", os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=fd)
        except FileNotFoundError:
            pass
        else:
            try:
                raw, _ = azt_intake.read_fd(local, MAX_BYTES)
                local_cfg = azt_intake.json_object(raw.decode("utf-8"))
                azt_intake.validate_config("scan_claude_settings", local_cfg)
                if local_cfg.get("disableAllHooks"):
                    raise azt_intake.IntakeError("local settings disable all hooks; installation refused")
            finally:
                os.close(local)
        entry = {"matcher": "Bash|Write|Edit|NotebookEdit",
                 "hooks": [{"type": "command", "command": shlex.join(command) + " || exit 2", "timeout": 30}]}
        if entry not in pre:
            pre.append(entry)
        data = json.dumps(cfg, indent=2).encode() + b"\n"
        import secrets
        temp = ".azt-settings-" + secrets.token_hex(12)
        out = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        try:
            if os.write(out, data) != len(data):
                raise azt_intake.IntakeError("settings write failed")
            os.fsync(out)
        finally:
            os.close(out)
        os.replace(temp, "settings.json", src_dir_fd=fd, dst_dir_fd=fd)
        result = {"schema_version": 1, "decision": "installed",
                  "next": "Run scan --gate with the same state directory and policy from an operator terminal before starting the agent.",
                  "limitation": "Workflow hook only; same-user code can alter hook, policy, and issuer key."}
        print(json.dumps(result, sort_keys=True) if args.json else result["next"] + "\n" + result["limitation"])
        return 0
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        return emit_error(args, str(exc) if isinstance(exc, azt_intake.IntakeError) else "hook installation failed")
    finally:
        if fd is not None:
            os.close(fd)


def cmd_gate_check(args):
    import signal
    root = args.target or os.environ.get("CLAUDE_PROJECT_DIR", ".")
    def timed_out(_signum, _frame):
        raise GateDeadline("gate inspection timed out")
    previous = signal.signal(signal.SIGALRM, timed_out) if hasattr(signal, "SIGALRM") else None
    try:
        if previous is not None:
            signal.setitimer(signal.ITIMER_REAL, 10)
        report = scan_report(root, args.policy, args.fail_on)
        result = azt_gate.verify(root, args.state_dir, report, args.fail_on)
        if args.json:
            print(json.dumps(dict(result, schema_version=1), sort_keys=True))
        return 0
    except (azt_intake.IntakeError, FileNotFoundError):
        return emit_error(args, "gate blocked: receipt missing, invalid, expired, or snapshot changed. "
                          "Legacy workspace markers are not accepted. Review and re-admit from an operator terminal "
                          "using scan --gate with the same --state-dir, --policy, and --fail-on.", decision="deny")
    except (OSError, ValueError, RuntimeError, GateDeadline):
        return emit_error(args, "operational failure during gate inspection; no authorization granted")
    finally:
        if previous is not None:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)


def main(argv=None):
    class Parser(argparse.ArgumentParser):
        def error(self, message):
            arguments = sys.argv[1:] if argv is None else argv
            wants_json = ("--json" in arguments or "--format=json" in arguments or
                          any(arguments[i:i+2] == ["--format", "json"] for i in range(len(arguments))))
            if wants_json:
                print(json.dumps({"schema_version": 1, "version": __version__,
                                  "decision": "error", "error": "invalid command arguments"}, sort_keys=True))
            super().error(message)
    ap = Parser(
        prog="azt",
        description="Repository intake for AI coding agents. Offline, deterministic, no model calls. "
                    "A clean scan means 'no known-shape red flags', NOT 'safe'.")
    ap.add_argument("--version", action="version", version="agent-zero-trust %s" % __version__)
    sub = ap.add_subparsers(dest="cmd")
    sp = sub.add_parser("scan", help="scan a repository before an agent enters it")
    sp.add_argument("target", nargs="?", default=".")
    sp.add_argument("--gate", action="store_true", help="issue an external authenticated snapshot receipt on a complete passing scan")
    sp.add_argument("--ttl-minutes", type=int, default=60, help="receipt lifetime, 1–1440 minutes (default: 60)")
    ih = sub.add_parser("install-hook", help="install an honest workflow intake hook; not a sandbox")
    ih.add_argument("target", nargs="?", default=".")
    gc = sub.add_parser("gate-check", help="verify current snapshot against an operator-issued receipt")
    gc.add_argument("target", nargs="?", default=None)
    for parser in (sp, ih, gc):
        parser.add_argument("--json", action="store_true", help="machine-readable output")
        parser.add_argument("--policy", help="explicit operator policy JSON outside the workspace")
        parser.add_argument("--state-dir", help="private external operator state directory (required for gate operations)")
        parser.add_argument("--fail-on", choices=["high", "medium", "any"], default="high")
    doctor = sub.add_parser("doctor", help="report runtime prerequisites; containment integration is not yet available")
    doctor.add_argument("--backend", default="bubblewrap")
    doctor.add_argument("--json", action="store_true")
    import azt_safety
    azt_safety.add_parser(sub)
    import azt_review
    azt_review.add_parsers(sub)
    import azt_research
    azt_research.add_parser(sub)
    args = ap.parse_args(argv)
    if args.cmd == "research":
        return azt_research.command(args)
    if args.cmd in ("changes", "explain", "report"):
        return azt_review.command(args)
    if args.cmd == "safety":
        return azt_safety.command(args)
    if args.cmd == "scan":
        return cmd_scan(args)
    if args.cmd == "install-hook":
        return cmd_install_hook(args)
    if args.cmd == "gate-check":
        return cmd_gate_check(args)
    if args.cmd == "doctor":
        import azt_runtime
        report = azt_runtime.runtime_doctor(args.backend)
        print(json.dumps(report, indent=2, sort_keys=True))
        return azt_runtime.doctor_exit_code(report)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
