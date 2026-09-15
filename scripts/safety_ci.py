"""Bounded GitHub-hosted adapter for the existing FS-001 integration script.

No backend, pack, expectation or image downloader lives here. Setup downloads
are separate explicit workflow steps. Export only selected synthetic records to
the log (no chargeable artifact upload). Local tests do not launch this path.
"""
import argparse
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from azt_docker import Docker, bounded_command

IMAGE = "docker.io/library/python@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea"
ENDPOINT = "unix:///var/run/docker.sock"
LABEL = "org.azt.pack=AZT-FS-001-v1"
MODULES = ("azt.py", "azt_intake.py", "azt_gate.py", "azt_runtime.py",
           "azt_config.py", "azt_docker.py", "azt_safety.py", "azt_safety_pack.py")


def host_guard():
    # Routing guard, not operator authentication. Never use this to claim that
    # a hostile same-user host process is constrained.
    if (os.environ.get("GITHUB_ACTIONS") != "true" or
            os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted" or
            os.environ.get("GITHUB_REPOSITORY") != "ralfyishere/agent-zero-trust"):
        raise ValueError("this adapter is restricted to the approved GitHub-hosted job")


def read_json(path):
    if path.is_symlink() or path.stat().st_size > 65536:
        raise ValueError("unsafe or oversized CI record")
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path, value):
    raw = json.dumps(value, sort_keys=True, ensure_ascii=True)
    if len(raw.encode()) > 65536:
        raise ValueError("CI evidence limit exceeded")
    with path.open("x", encoding="utf-8") as stream:
        stream.write(raw)


def git(*args):
    code, out, _ = bounded_command(["/usr/bin/git", "-C", str(ROOT), *args])
    if code:
        raise ValueError("source identity check failed")
    return out.decode().strip()


def image_compatibility(data):
    # Metadata compatibility only; actual interpreter/task execution belongs to
    # the unchanged three-phase test. Neither a label nor image metadata is denial.
    if data.get("Os") != "linux" or data.get("Architecture") != "amd64":
        raise ValueError("approved image must be linux/amd64")
    versions = [e.split("=", 1)[1] for e in data.get("Config", {}).get("Env", [])
                if e.startswith("PYTHON_VERSION=")]
    if len(versions) != 1 or not re.fullmatch(r"3\.12\.\d+", versions[0]):
        raise ValueError("approved image must declare Python 3.12")
    return {"os": "linux", "architecture": "amd64", "declared_python": versions[0],
            "scope": "image metadata; execution checked by three-phase task"}


def run(wheel, output):
    record = {"schema_version": 2, "status": "setup_failed", "integration_invoked": False, "cases": {}}
    try:
        sha = git("rev-parse", "HEAD")
        if sha != os.environ.get("GITHUB_SHA") or git("status", "--porcelain", "--untracked-files=no"):
            raise ValueError("checkout must exactly match the triggering SHA with no tracked changes")
        modules = {}
        with zipfile.ZipFile(wheel) as archive:
            for name in MODULES:
                git("ls-files", "--error-unmatch", name)
                raw = (ROOT / name).read_bytes()
                if archive.read(name) != raw:
                    raise ValueError("wheel module differs from reviewed checkout")
                modules[name] = hashlib.sha256(raw).hexdigest()
        sdists = list(wheel.parent.glob("agent_zero_trust-*.tar.gz"))
        if len(sdists) != 1:
            raise ValueError("expected the single tested source distribution")
        record.update(source_sha=sha, source_tree=git("rev-parse", "HEAD^{tree}"),
                      module_sha256=modules, wheel=wheel.name, wheel_sha256=hashlib.sha256(wheel.read_bytes()).hexdigest(),
                      sdist=sdists[0].name, sdist_sha256=hashlib.sha256(sdists[0].read_bytes()).hexdigest(),
                      platform={"system": platform.system(), "release": platform.release(),
                                "machine": platform.machine(), "controller_python": platform.python_version()},
                      runner_image=os.environ.get("ImageOS"), runner_image_version=os.environ.get("ImageVersion"),
                      run_id=os.environ.get("GITHUB_RUN_ID"), run_attempt=os.environ.get("GITHUB_RUN_ATTEMPT"))
        control = output / "preflight"
        control.mkdir(mode=0o700)
        docker = Docker(ENDPOINT, control)
        preflight = docker.preflight(IMAGE)
        record["backend"] = preflight
        if preflight["status"] != "available":
            record["status"] = "prerequisite_blocked"
            return 2
        _, info, _ = docker.command("info", "--format", "{{json .}}")
        info = json.loads(info)
        record["observed_daemon_controls"] = {key: info.get(key) for key in
            ("CgroupVersion", "MemoryLimit", "SwapLimit", "CpuCfsQuota", "PidsLimit")}
        _, image, _ = docker.command("image", "inspect", preflight["image_id"], "--format", "{{json .}}")
        record["image_compatibility"] = image_compatibility(json.loads(image))
        _, existing, _ = docker.command("ps", "-aq", "--filter", "label=" + LABEL)
        if existing.strip():
            raise ValueError("unexpected preexisting pack containers; no cleanup authority acquired")
        write_json(output / "cleanup-scope.json", {"empty_at_start": True, "label": LABEL})
        record["integration_invoked"] = True
        for case in ("canonical", "variant"):
            code, stdout, _ = bounded_command([sys.executable, str(ROOT / "scripts/test_safety_integration.py"),
                "--case", case, "--wheel", str(wheel), "--output", str(output / case), "--image", preflight["image_id"],
                "--docker-host", ENDPOINT], timeout=90, limit=65536)
            record["cases"][case] = {"exit": code, "summary": json.loads(stdout)}
            if code:
                # No subsequent case after an uncertain/failed first case.
                record["status"] = "case_failed_or_blocked"
                return code if code in (1, 2) else 2
        record["status"] = "passed"
        return 0
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, zipfile.BadZipFile):
        record["status"] = "operational_failure"
        record["error"] = "setup/controller failed; no denial credited (see bounded workflow setup logs)"
        return 2
    finally:
        write_json(output / "ci-run.json", record)


def cleanup(docker):
    _, raw, _ = docker.command("ps", "-a", "--filter", "label=" + LABEL, "--format", "{{.Names}}", limit=4096)
    names = raw.decode().splitlines()
    if len(names) > 3 or any(not re.fullmatch(r"azt-fs001-[0-9a-f]{24}", n) for n in names):
        raise ValueError("unexpected cleanup target; refusing broad removal")
    for name in names:
        docker.command("rm", "--force", name, timeout=5)
    _, remaining, _ = docker.command("ps", "-aq", "--filter", "label=" + LABEL, limit=4096)
    if remaining.strip():
        raise ValueError("pack containers remain after cleanup")
    return {"status": "verified_absent", "removed_names": names}


def finish(output):
    envelope = {"schema": "azt.fs001-ci-export.v2", "records": {}, "cleanup": {"status": "not_acquired"}}
    failed = False
    if (output / "cleanup-scope.json").is_file():
        try:
            if read_json(output / "cleanup-scope.json") != {"empty_at_start": True, "label": LABEL}:
                raise ValueError("invalid cleanup scope")
            control = output / "cleanup"
            control.mkdir(mode=0o700)
            envelope["cleanup"] = cleanup(Docker(ENDPOINT, control))
        except (OSError, ValueError, subprocess.SubprocessError):
            envelope["cleanup"] = {"status": "failed", "note": "job VM disposal remains final cleanup; not a tested supervisor-death guarantee"}
            failed = True
    for name in ("ci-run.json", "canonical/evidence.json", "canonical/artifact.json",
                 "variant/evidence.json", "variant/artifact.json"):
        path = output / name
        try:
            if path.is_file():
                envelope["records"][name] = read_json(path)
            else:
                envelope.setdefault("record_errors", {})[name] = "missing; outcome unobserved"
                failed = True
        except (OSError, ValueError):
            envelope.setdefault("record_errors", {})[name] = "unreadable_or_invalid; outcome unknown"
            failed = True
    if "ci-run.json" not in envelope["records"]:
        envelope["setup"] = "controller record missing; outcome unknown; inspect partial evidence and workflow step status"
    # No raw proposals, stdout from the workload, env dumps, Docker auth files,
    # canary values or arbitrary directory upload. Nested claims in evidence.json
    # are JSON-escaped data from the bundled synthetic probe, not commands.
    raw = json.dumps(envelope, sort_keys=True, ensure_ascii=True)
    raw = raw.replace(str(ROOT), "$SOURCE_ROOT").replace(str(output), "$CI_OUTPUT")
    if len(raw.encode()) > 65536:
        raise ValueError("CI export exceeds 64 KiB")
    print("AZT_FS001_EVIDENCE_BEGIN")
    print(raw)
    print("AZT_FS001_EVIDENCE_END")
    return int(failed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("run", "finish"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--wheel", type=Path)
    args = parser.parse_args()
    host_guard()
    if args.operation == "run":
        if args.wheel is None:
            parser.error("run requires --wheel")
        return run(args.wheel, args.output)
    return finish(args.output)


if __name__ == "__main__":
    sys.exit(main())
