"""Bounded intake and explicit operator policy. No target code is executed."""
import hashlib
import json
import os
import stat
from pathlib import Path, PurePosixPath

MAX_FILES = 10000
MAX_TOTAL_BYTES = 32_000_000
MAX_DEPTH = 64
MAX_LINE = 4096
MAX_FINDINGS = 10000
POLICY_LIMIT = 256_000


class IntakeError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def safe_label(value):
    return str(value).encode("unicode_escape").decode("ascii")[:512]


def json_object(raw):
    # Bound parser nesting before invoking the stdlib decoder, including strings.
    depth, quoted, escaped = 0, False, False
    for c in raw:
        if quoted:
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == '"':
                quoted = False
        elif c == '"':
            quoted = True
        elif c in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise IntakeError("JSON nesting exceeds limit")
        elif c in "]}":
            depth -= 1
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise IntakeError("duplicate JSON key")
            out[key] = value
        return out
    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(IntakeError("non-finite JSON")))
    except (ValueError, RecursionError) as exc:
        raise IntakeError("invalid JSON configuration") from exc
    if not isinstance(value, dict):
        raise IntakeError("configuration must be an object")
    return value


def relative_path(value):
    if (not isinstance(value, str) or not value or len(value) > 512
            or any(c in value for c in "\\*?[]")
            or any(ord(c) < 32 or ord(c) > 126 for c in value)
            or PurePosixPath(value).is_absolute()
            or any(p in ("", ".", "..") for p in value.split("/"))
            or ":" in value):
        raise IntakeError("policy paths must be exact, canonical relative POSIX paths")
    return value


def open_absolute(path, directory=False):
    """Open each component without following links (POSIX dirfd authority)."""
    if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
        raise IntakeError("safe descriptor-relative input handling unavailable on this platform")
    path = Path(os.path.abspath(path))
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for i, part in enumerate(path.parts[1:]):
            is_dir = i < len(path.parts[1:]) - 1 or directory
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if is_dir:
                flags |= os.O_DIRECTORY
            nxt = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_fd(fd, limit):
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode):
        raise IntakeError("not a regular file")
    if before.st_nlink != 1:
        raise IntakeError("hardlinked or unlinked file not inspected")
    if before.st_size > limit:
        raise IntakeError("file size limit exceeded")
    chunks, size = [], 0
    while True:
        chunk = os.read(fd, min(65536, limit + 1 - size))
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
        if size > limit:
            raise IntakeError("file size limit exceeded")
    after = os.fstat(fd)
    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise IntakeError("file changed during inspection")
    return b"".join(chunks), before


def load_policy(path, root, rules):
    policy = {"schema_version": 1, "exceptions": [], "exclusions": []}
    if path is None:
        return policy, {"source": "built-in", "digest": digest(policy)}
    path = Path(os.path.abspath(path))
    if path == root or root in path.parents:
        raise IntakeError("trusted policy must be outside the target workspace")
    fd = open_absolute(path)
    try:
        raw, meta = read_fd(fd, POLICY_LIMIT)
        if meta.st_uid != os.getuid() or meta.st_mode & 0o022 or meta.st_nlink != 1:
            raise IntakeError("policy must be operator-owned, singly linked, and not group/world writable")
    finally:
        os.close(fd)
    try:
        policy = json_object(raw.decode("utf-8"))
    except UnicodeError as exc:
        raise IntakeError("policy must be UTF-8") from exc
    if (set(policy) != {"schema_version", "exceptions", "exclusions"}
            or type(policy["schema_version"]) is not int or policy["schema_version"] != 1):
        raise IntakeError("invalid policy schema")
    seen = set()
    for kind in ("exceptions", "exclusions"):
        if not isinstance(policy[kind], list) or len(policy[kind]) > 1000:
            raise IntakeError("invalid policy entry list")
        for entry in policy[kind]:
            fields = {"path", "reason"} | ({"rule", "sha256"} if kind == "exceptions" else set())
            if not isinstance(entry, dict) or set(entry) != fields:
                raise IntakeError("invalid policy entry fields")
            relative_path(entry["path"])
            if not isinstance(entry["reason"], str) or not entry["reason"].strip() or len(entry["reason"]) > 512:
                raise IntakeError("policy entry requires a bounded reason")
            if kind == "exceptions":
                if not isinstance(entry["rule"], str) or entry["rule"] not in rules:
                    raise IntakeError("exception must name an exact known rule")
                sha = entry["sha256"]
                if not isinstance(sha, str) or len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
                    raise IntakeError("exception requires a SHA-256 file digest")
            key = (kind, entry["path"], entry.get("rule"))
            if key in seen:
                raise IntakeError("duplicate policy entry")
            seen.add(key)
    return policy, {"source": str(path), "digest": hashlib.sha256(raw).hexdigest()}


def inspect(root, engine, policy_path=None):
    root = Path(os.path.abspath(root))
    rules = {r[0] for r in engine.TEXT_RULES} | {
        "mcp.server", "hooks.claude", "perm.auto_approve", "pkg.lifecycle",
        "ci.prt_checkout", "auto.vscode_folderopen", "fs.symlink_escape"}
    policy, provenance = load_policy(policy_path, root, rules)
    scope = {"complete": True, "inspected": [], "skipped": [], "errors": [],
             "limits": {"file_bytes": engine.MAX_BYTES, "total_bytes": MAX_TOTAL_BYTES,
                        "entries": MAX_FILES, "depth": MAX_DEPTH, "line_characters": MAX_LINE,
                        "findings": MAX_FINDINGS},
             "builtin_excluded_directories": sorted(engine.SKIP_DIRS),
             "text_extensions": sorted(engine.TEXT_EXT), "bytes_read": 0}
    findings, files, manifest, requests = [], [], [], []
    excluded = {e["path"]: e for e in policy["exclusions"]}
    visited = 0

    def issue(rel, reason):
        scope["complete"] = False
        scope["errors"].append({"path": rel, "reason": reason})

    def traverse(fd, parent="", depth=0):
        nonlocal visited
        if depth > MAX_DEPTH:
            issue(parent, "directory depth limit exceeded")
            return
        entries = []
        with os.scandir(fd) as iterator:
            for entry in iterator:
                visited += 1
                if visited > MAX_FILES:
                    issue(parent, "entry count limit exceeded")
                    return
                entries.append(entry.name)
        for name in sorted(entries):
            rel = parent + "/" + name if parent else name
            try:
                meta = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISLNK(meta.st_mode):
                    target = os.readlink(name, dir_fd=fd)
                    manifest.append({"path": rel, "kind": "symlink", "target_digest": digest(target)})
                    issue(rel, "symlink not followed")
                    resolved = (root / rel).resolve()
                    if resolved != root and root not in resolved.parents:
                        findings.append({"rule": "fs.symlink_escape", "severity": "MEDIUM",
                                         "description": "symlink resolves outside the repository",
                                         "path": rel, "line": 0, "excerpt": "[target omitted]"})
                    continue
                if rel in excluded or (stat.S_ISDIR(meta.st_mode) and name in engine.SKIP_DIRS):
                    reason = excluded[rel]["reason"] if rel in excluded else "built-in dependency/VCS/build exclusion"
                    source = provenance if rel in excluded else {"source": "built-in"}
                    item = {"path": rel, "reason": reason, "policy": source}
                    scope["skipped"].append(item)
                    manifest.append({"path": rel, "kind": "excluded"})
                    continue
                if stat.S_ISDIR(meta.st_mode):
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        manifest.append({"path": rel, "kind": "directory"})
                        traverse(child, rel, depth + 1)
                    finally:
                        os.close(child)
                    continue
                if not stat.S_ISREG(meta.st_mode):
                    issue(rel, "special file not read")
                    continue
                files.append(root / rel)
                limit = min(engine.MAX_BYTES, MAX_TOTAL_BYTES - scope["bytes_read"])
                file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                try:
                    raw, opened = read_fd(file_fd, limit)
                    if (opened.st_dev, opened.st_ino) != (meta.st_dev, meta.st_ino):
                        raise IntakeError("path changed during inspection")
                finally:
                    os.close(file_fd)
                scope["bytes_read"] += len(raw)
                sha = hashlib.sha256(raw).hexdigest()
                manifest.append({"path": rel, "kind": "file", "sha256": sha,
                                 "executable": bool(opened.st_mode & 0o111)})
                supported = Path(rel).suffix.lower() in engine.TEXT_EXT
                inventoried = bool(engine.classify_surface(root, [root / rel]))
                if not supported and not inventoried:
                    scope["skipped"].append({"path": rel, "reason": "unsupported extension; content hashed only"})
                    continue
                try:
                    text = raw.decode("utf-8")
                except UnicodeError:
                    issue(rel, "unsupported encoding; UTF-8 required")
                    continue
                if "\x00" in text:
                    issue(rel, "NUL in supported text input")
                    continue
                if any(len(line) > MAX_LINE for line in text.splitlines()):
                    issue(rel, "line length limit exceeded")
                    continue
                if name == ".azt-ignore":
                    requests.append({"path": rel, "sha256": sha, "status": "untrusted; not applied",
                                     "requested_lines": sum(bool(l.strip()) and not l.lstrip().startswith("#") for l in text.splitlines())})
                analyses = ["text-patterns"]
                for pattern, scanner in engine.STRUCTURAL:
                    if pattern.search(rel):
                        try:
                            if rel.endswith(".json"):
                                cfg = json_object(text)
                                validate_config(scanner.__name__, cfg)
                            findings.extend(scanner(rel, text))
                            analyses.append(scanner.__name__)
                        except (ValueError, TypeError, AttributeError, KeyError, RecursionError):
                            issue(rel, "malformed supported configuration or structural analysis failure")
                findings.extend(engine.scan_text_file(rel, text))
                scope["inspected"].append({"path": rel, "analyses": analyses})
                if len(findings) > MAX_FINDINGS:
                    del findings[MAX_FINDINGS:]
                    issue(rel, "finding count limit exceeded")
                    return
            except IntakeError as exc:
                issue(rel, str(exc))
            except OSError as exc:
                issue(rel, "filesystem operation failed (errno %s)" % exc.errno)
            except (ValueError, RuntimeError):
                issue(rel, "analysis failed or link could not be resolved")

    fd = open_absolute(root, directory=True)
    try:
        traverse(fd)
    finally:
        os.close(fd)
    manifest.sort(key=lambda e: e["path"])
    hashes = {e["path"]: e.get("sha256") for e in manifest}
    suppressed, active = [], []
    for finding in findings:
        # No raw snippets or config commands: arbitrary credentials cannot be reliably redacted.
        finding["excerpt"] = "[content omitted; inspect the indicated file locally]"
        if finding["rule"] == "mcp.server":
            finding["description"] = "MCP server declaration; review command, arguments, and remote endpoints"
        if finding["rule"] == "hooks.claude":
            finding["description"] = "Claude hook declaration; review the command locally"
        match = next((e for e in policy["exceptions"] if e["rule"] == finding["rule"]
                      and e["path"] == finding["path"] and e["sha256"] == hashes.get(finding["path"])), None)
        if match:
            suppressed.append(dict(finding, exception={"reason": match["reason"], "policy": provenance}))
        else:
            active.append(finding)
    key = lambda f: (engine.SEV_ORDER.get(f["severity"], 9), f["path"], f["line"], f["rule"])
    scope["errors"].sort(key=lambda e: (e["path"], e["reason"]))
    return {"schema_version": 1, "version": engine.__version__, "inventory": engine.classify_surface(root, files),
            "findings": sorted(active, key=key), "suppressed_findings": sorted(suppressed, key=key),
            "target_requests": requests, "policy": provenance, "scope": scope,
            "manifest": manifest, "input_digest": digest(manifest)}


def validate_config(scanner, cfg):
    """Validate the supported fields before structural scanners touch them."""
    def require(value, kind):
        if not isinstance(value, kind):
            raise IntakeError("invalid configuration field type")
        return value
    if scanner == "scan_mcp":
        for field in ("mcpServers", "servers"):
            for server in require(cfg.get(field, {}), dict).values():
                require(server, dict)
                if "command" in server:
                    require(server["command"], str)
                for arg in require(server.get("args", []), list):
                    require(arg, str)
                if "url" in server:
                    require(server["url"], str)
    elif scanner == "scan_claude_settings":
        if "disableAllHooks" in cfg and type(cfg["disableAllHooks"]) is not bool:
            raise IntakeError("disableAllHooks must be a boolean")
        for entries in require(cfg.get("hooks", {}), dict).values():
            for entry in require(entries, list):
                for hook in require(require(entry, dict).get("hooks", []), list):
                    require(hook, dict)
                    if "command" in hook:
                        require(hook["command"], str)
        for permission in require(require(cfg.get("permissions", {}), dict).get("allow", []), list):
            require(permission, str)
    elif scanner == "scan_package_json":
        for command in require(cfg.get("scripts", {}), dict).values():
            require(command, str)
    elif scanner == "scan_tasks_json":
        for task in require(cfg.get("tasks", []), list):
            require(task, dict)
            options = require(task.get("runOptions", {}), dict)
            if "runOn" in options:
                require(options["runOn"], str)
