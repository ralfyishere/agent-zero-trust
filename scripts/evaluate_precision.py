"""Measure the frozen precision pack through an explicitly installed candidate.

Use --python /external/venv/bin/python --output /new/external/result.json.
The same expected observations apply to baseline and candidate; known baseline
mismatches are retained and return 1. Setup/command failures return 2. No fixture
instruction executes. The bundled manifest is data, never a loader or policy.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import resource
import selectors
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
PACK = ROOT / "examples/sensitive-request/precision-v1.json"
RULE = "request.sensitive_disclosure"
MAX_OUTPUT = 8 * 1024 * 1024
COMPONENT = '''import hashlib,json,sys
from pathlib import Path
import azt,azt_sensitive,azt_review
modules=[azt,azt_sensitive,azt_review]
assert all(Path(sys.prefix).resolve() in Path(m.__file__).resolve().parents for m in modules)
rows=[]
for case in json.load(sys.stdin):
 snapshots={p:{'text':t,'sha256':hashlib.sha256(t.encode()).hexdigest()} for p,t in case['files'].items()}
 findings,errors=azt_sensitive.analyze(snapshots,{})
 rows.append({'id':case['id'],'findings':findings,'errors':errors})
print(json.dumps({'version':azt.__version__,'engine':azt_review.engine_identity(azt),'python':sys.version.split()[0],
 'module_sha256':{m.__name__:hashlib.sha256(Path(m.__file__).read_bytes()).hexdigest() for m in modules},'cases':rows}))
'''


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pack_data():
    raw = PACK.read_bytes()
    if len(raw) > 256 * 1024:
        raise ValueError("oversized bundled pack")
    pack = json.loads(raw)
    if pack.get("schema") != "azt.sensitive-precision.v1" or not 1 <= len(pack["cases"]) <= 32:
        raise ValueError("invalid bundled pack")
    names = set()
    for case in pack["cases"]:
        name = case["id"]
        if not re.fullmatch(r"P[0-9]{2}", name) or name in names or not 1 <= len(case["files"]) <= 8:
            raise ValueError("invalid case identity or file count")
        names.add(name)
        for name, text in case["files"].items():
            path = PurePosixPath(name)
            if (not re.fullmatch(r"[A-Za-z0-9_. /-]{1,256}", name) or path.is_absolute() or
                    str(path) != name or any(p in ("", ".", "..") for p in name.split("/")) or
                    not isinstance(text, str) or len(text.encode()) > 16384):
                raise ValueError("unsafe or oversized fixture data")
    if any(c[side] not in names for c in pack.get("comparisons", []) for side in ("before", "after")):
        raise ValueError("unknown comparison case")
    return pack, digest(raw)


def invoke(python, work, args, data=None):
    """Bound captured bytes and wall time while running only reviewed commands."""
    env = {"PATH": os.defpath, "PYTHONNOUSERSITE": "1", "PIP_CONFIG_FILE": os.devnull}
    started, chunks, error = time.monotonic(), {"stdout": bytearray(), "stderr": bytearray()}, None
    result = {"exit": None, "error": None}
    try:
        # File-backed input avoids a blocked pipe when the installed program
        # fails before consuming it. The workload receives only synthetic data.
        with tempfile.TemporaryFile() as input_file:
            if data is not None:
                input_file.write(data.encode("utf-8"))
                input_file.seek(0)
            child = subprocess.Popen([str(python), "-I"] + list(args), cwd=work, env=env,
                                     stdin=input_file, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ, "stdout")
                    selector.register(child.stderr, selectors.EVENT_READ, "stderr")
                    while selector.get_map():
                        if time.monotonic() - started > 30:
                            raise TimeoutError("command deadline")
                        for key, _ in selector.select(0.1):
                            chunk = os.read(key.fd, 65536)
                            if not chunk:
                                selector.unregister(key.fileobj)
                                continue
                            limit = MAX_OUTPUT if key.data == "stdout" else 65536
                            if len(chunks[key.data]) + len(chunk) > limit:
                                raise ValueError("command output limit")
                            chunks[key.data].extend(chunk)
                    child.wait(timeout=max(0.1, 30 - (time.monotonic() - started)))
                    result["exit"] = child.returncode
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=5)
                child.stdout.close()
                child.stderr.close()
    except (OSError, ValueError, TimeoutError, subprocess.TimeoutExpired) as exc:
        error = type(exc).__name__
    result.update(error=error, seconds=round(time.monotonic() - started, 6),
                  stdout_bytes=len(chunks["stdout"]), stderr_bytes=len(chunks["stderr"]),
                  stdout_sha256=digest(chunks["stdout"]), stderr_sha256=digest(chunks["stderr"]))
    return result, bytes(chunks["stdout"])


def parsed(raw):
    try:
        value = json.loads(raw)
        return value if isinstance(value, dict) else {}
    except (ValueError, UnicodeError):
        return {}


def component_row_valid(row, name):
    return (isinstance(row, dict) and row.get("id") == name and
            isinstance(row.get("findings"), list) and all(isinstance(f, dict) for f in row["findings"]) and
            isinstance(row.get("errors"), list) and all(isinstance(e, dict) for e in row["errors"]))


def observations(findings, files):
    """Keep only maintained observation fields; independently check input hashes."""
    if not isinstance(findings, list) or any(not isinstance(f, dict) for f in findings):
        return [], False
    hashes = {p: digest(t.encode()) for p, t in files.items()}
    rows, bound = [], True
    for finding in findings:
        if finding.get("rule") != RULE:
            continue
        request = finding.get("sensitive_request", {})
        if not isinstance(request, dict):
            return [], False
        support, refs = request.get("support", []), request.get("references", [])
        if (not isinstance(support, list) or not isinstance(refs, list) or
                any(not isinstance(row, dict) for row in support + refs) or
                not isinstance(finding.get("path"), str) or
                not isinstance(request.get("destination"), dict)):
            return [], False
        for source in support:
            path = source.get("path")
            if not isinstance(path, str):
                return [], False
            bound = bound and source.get("sha256") == hashes.get(path) and path in files
            if path in files:
                first, last = source.get("start_line"), source.get("end_line")
                bound = bound and type(first) is int and type(last) is int and 1 <= first <= last <= max(1, len(files[path].splitlines()))
        for ref in refs:
            if ref.get("path") is not None and not isinstance(ref["path"], str):
                return [], False
            if ref.get("sha256") is not None:
                bound = bound and ref["sha256"] == hashes.get(ref.get("path"))
        rows.append({"path": finding.get("path"), "classes": request.get("information_classes"),
                     "destination": {k: request.get("destination", {}).get(k) for k in ("status", "count")},
                     "references": [{k: ref.get(k) for k in ("path", "status")} for ref in refs],
                     "support_paths": sorted(source.get("path") for source in support)})
        bound = bound and finding.get("severity") == "MEDIUM" and bool(support)
    return sorted(rows, key=lambda row: row["path"]), bool(bound)


def evaluate(python, output):
    pack, pack_hash = pack_data()
    output = output.absolute()
    if (output.exists() or output.is_symlink() or output.parent.resolve() != output.parent or
            not output.parent.is_dir() or ROOT == output.parent or ROOT in output.parents):
        raise ValueError("use a new output file in an existing canonical external directory")
    started, rows, comparisons, operational = time.monotonic(), [], [], []
    with tempfile.TemporaryDirectory(prefix="azt precision ") as temporary:
        work = Path(temporary).resolve()
        code, raw = invoke(python, work, ["-c", COMPONENT], json.dumps(pack["cases"]))
        component = parsed(raw)
        component_cases = component.get("cases", [])
        if not isinstance(component_cases, list):
            component_cases = []
        component_rows = {row["id"]: row for row in component_cases
                          if isinstance(row, dict) and isinstance(row.get("id"), str)}
        if code["exit"] != 0 or code["error"] or len(component_rows) != len(pack["cases"]):
            operational.append("installed component unavailable or incomplete")
        reports = {}
        for case in pack["cases"]:
            target = work / (case["id"] + " project")
            target.mkdir()
            for rel, text in case["files"].items():
                path = target / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("x", encoding="utf-8") as stream:
                    stream.write(text)
            observed = component_rows.get(case["id"], {})
            valid_row = component_row_valid(observed, case["id"])
            if not valid_row or observed.get("errors"):
                operational.append(case["id"] + ": component result missing, malformed or incomplete")
            component_observations, component_bound = observations(observed.get("findings", []), case["files"])
            failures, scans = [], []
            if (not valid_row or code["exit"] != 0 or code["error"] or
                    component_observations != case["expected"] or observed.get("errors") or not component_bound):
                failures.append("component observation or identity mismatch")
            for threshold in ("high", "medium"):
                command, raw = invoke(python, work, ["-m", "azt", "scan", "--json", "--fail-on", threshold, "--", str(target)])
                report = parsed(raw)
                found, bound = observations(report.get("findings", []), case["files"])
                complete = report.get("scope", {}).get("complete") is True
                exit_matches = command["exit"] == {"pass": 0, "deny": 1, "incomplete": 2}.get(report.get("decision"))
                if command["error"] or command["exit"] not in (0, 1) or not complete or not exit_matches:
                    operational.append(case["id"] + ": " + threshold + " scan failure")
                path = work / (case["id"] + " " + threshold + " scan.json")
                path.write_bytes(raw)
                if threshold == "high":
                    reports[case["id"]] = path
                exported = work / (case["id"] + " " + threshold + " review.json")
                export_command, _ = invoke(python, work, ["-m", "azt", "report", "--input", str(path), "--format", "json", "--output", str(exported)])
                export_bytes = exported.read_bytes() if exported.is_file() and exported.stat().st_size <= MAX_OUTPUT else b""
                exported_record = parsed(export_bytes)
                clean = bool(export_bytes) and not any(value.encode() in export_bytes for value in pack["redaction_sentinels"])
                export_found, export_bound = observations(exported_record.get("scan", {}).get("findings", []), case["files"])
                export_valid = (export_command["exit"] == 0 and not export_command["error"] and
                                exported_record.get("schema") == "azt.review.v2" and export_found == found and export_bound and clean)
                if not export_valid:
                    operational.append(case["id"] + ": " + threshold + " report validation/redaction failure")
                if found != case["expected"] or not bound:
                    failures.append(threshold + ": observation or identity mismatch")
                scans.append({"threshold": threshold, "command": command, "complete": complete,
                              "exit_matches_decision": exit_matches, "decision": report.get("decision"),
                              "input_digest": report.get("input_digest"), "observations": found,
                              "bound_identities": bound, "all_rules": dict(Counter(f.get("rule") for f in report.get("findings", []))),
                              "export": {"command": export_command, "validated": export_valid, "recipient_values_omitted": clean,
                                         "sha256": digest(export_bytes), "bytes": len(export_bytes)}})
            rows.append({"id": case["id"], "family": case["family"], "role": case["role"],
                         "expected": case["expected"], "file_sha256": {p: digest(t.encode()) for p, t in case["files"].items()},
                         "component": {"observations": component_observations, "bound_identities": component_bound,
                                       "result_present_and_structured": valid_row,
                                       "error_count": len(observed["errors"]) if valid_row else None}, "scans": scans,
                         "failures": failures, "passed": not failures and all(s["complete"] and s["exit_matches_decision"] and s["export"]["validated"] and not s["command"]["error"] for s in scans)})
        for spec in pack.get("comparisons", []):
            command, raw = invoke(python, work, ["-m", "azt", "changes", "--before", str(reports[spec["before"]]), "--after", str(reports[spec["after"]]), "--json"])
            report = parsed(raw)
            groups = {key: [f for f in report.get("findings", {}).get(key, []) if f.get("rule") == RULE]
                      for key in ("new", "persisting", "no_longer_observed", "unresolved")}
            observed = {"meaningful_delta": report.get("meaningful_delta"), "comparability": report.get("comparability", {}).get("status"),
                        "dependency_changed_sensitive": sum(f.get("dependencies_changed") is True for f in groups["persisting"])}
            observed.update({key + "_sensitive": len(value) for key, value in groups.items()})
            if command["exit"] != 0 or command["error"] or report.get("schema") != "azt.changes.v2":
                operational.append(spec["id"] + ": comparison operation failed")
            comparisons.append({"id": spec["id"], "expected": spec["expected"], "observed": observed, "command": command,
                                "passed": command["exit"] == 0 and not command["error"] and observed == spec["expected"]})
    by_family = {}
    for family in sorted({r["family"] for r in rows}):
        subset = [r for r in rows if r["family"] == family]
        by_family[family] = {"total": len(subset), "passed": sum(r["passed"] for r in subset)}
    result = {"schema": "azt.precision-evaluation.v1", "pack_sha256": pack_hash, "runner_sha256": digest(Path(__file__).read_bytes()),
              "version": component.get("version"), "engine": component.get("engine"), "python": component.get("python"),
              "module_sha256": component.get("module_sha256"), "component_command": code,
              "platform": platform.system() + " " + platform.release(), "seconds": round(time.monotonic() - started, 6),
              "peak_child_rss_bytes": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * (1 if platform.system() == "Darwin" else 1024),
              "cases": rows, "comparisons": comparisons, "operational_failures": operational,
              "counts": {"cases": len(rows), "passed": sum(r["passed"] for r in rows), "failed": sum(not r["passed"] for r in rows),
                         "false_alert_cases": sum(not r["expected"] and any(s["complete"] and s["command"]["exit"] in (0, 1) and not s["command"]["error"] and s["observations"] for s in r["scans"]) for r in rows),
                         "missed_request_cases": sum(bool(r["expected"]) and any(s["complete"] and s["command"]["exit"] in (0, 1) and not s["command"]["error"] and not s["observations"] for s in r["scans"]) for r in rows),
                         "comparisons": len(comparisons), "comparisons_passed": sum(r["passed"] for r in comparisons)},
              "families": by_family, "limitations": pack["limitations"] + ["Timing includes subprocess startup and report export; child RSS is a single high-water measurement", "Reports are validated derivatives; their digest is not the original scan digest or authenticated issuance"]}
    with output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 2 if operational else int(result["counts"]["failed"] > 0 or result["counts"]["comparisons_passed"] != len(comparisons))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        return evaluate(args.python.absolute(), args.output)
    except (OSError, ValueError, KeyError, TypeError):
        print('Precision evaluation setup/output failed; use an installed interpreter and a new external output file.', file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
