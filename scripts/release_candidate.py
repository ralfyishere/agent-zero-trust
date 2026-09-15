"""Build/test one release candidate. Offline after explicit tool preparation.

Run in a clean checkout: python scripts/release_candidate.py --output <new-dir>.
No upload, deployment, credentials or Docker execution occurs here.
"""
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
TOOLS = {"setuptools": "83.0.0", "wheel": "0.47.0", "packaging": "26.0"}
TESTS = ("scanner", "unit", "installed-artifacts")
BUILD_PROGRAM = ("import sys,setuptools.build_meta as b; destination=sys.argv[1]; "
                 "b.build_wheel(destination); b.build_sdist(destination)")


def digest(path):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 16 * 1024 * 1024:
        raise ValueError("unsafe, empty or oversized artifact")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args], timeout=10).decode().strip()


def source_identity(event, expected, tag):
    sha = git("rev-parse", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or (expected and sha != expected):
        raise ValueError("source does not match selected SHA")
    if git("status", "--porcelain", "--untracked-files=no"):
        raise ValueError("tracked source is not clean")
    versions = re.findall(r'^version = "([0-9]+\.[0-9]+\.[0-9]+)"$', (ROOT / "pyproject.toml").read_text(), re.M)
    if len(versions) != 1:
        raise ValueError("unsupported package version declaration")
    version = versions[0]
    if event not in ("local", "pull_request", "workflow_dispatch", "release"):
        raise ValueError("unsupported event")
    if event == "release":
        if tag != "v" + version or git("rev-parse", "--verify", "refs/tags/" + tag + "^{commit}") != sha:
            raise ValueError("release tag, source and package version must agree")
    elif tag:
        raise ValueError("non-release build must not claim a release tag")
    return {"sha": sha, "tree": git("rev-parse", "HEAD^{tree}"), "version": version, "tag": tag}


def distributions(dist, version):
    names = ("agent_zero_trust-" + version + "-py3-none-any.whl",
             "agent_zero_trust-" + version + ".tar.gz")
    if dist.is_symlink() or {p.name for p in dist.iterdir()} != set(names):
        raise ValueError("expected only one wheel and one source distribution")
    return {name: {"sha256": digest(dist / name), "bytes": (dist / name).stat().st_size} for name in names}


def execute(label, command, output):
    """Fixed trusted test/build commands, finite deadlines, bounded retained log."""
    start = time.monotonic()
    result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
    raw = result.stdout
    # These are bundled build/tests, not arbitrary evaluated workloads.
    if len(raw) > 512 * 1024:
        raise ValueError("build/test output exceeded retention limit")
    text = raw.decode("utf-8", errors="replace").replace(str(ROOT), "$SOURCE").replace(str(output), "$OUTPUT")
    print(label + ": exit=" + str(result.returncode))
    print(text[-16000:])
    record = {"name": label, "exit_code": result.returncode, "seconds": round(time.monotonic() - start, 3),
              "output_sha256": hashlib.sha256(raw).hexdigest(), "output_bytes": len(raw)}
    count = re.search(r"Ran (\d+) tests? in ", text)
    if count:
        record["reported_unit_tests"] = int(count.group(1))
    if result.returncode:
        raise ValueError(label + " failed; no publishable manifest issued")
    return record


def build_candidate(output, event="local", expected="", tag=""):
    source = source_identity(event, expected, tag)
    dependencies = {name: importlib.metadata.version(name) for name in TOOLS}
    if dependencies != TOOLS:
        raise ValueError("prepare the documented exact build tools first")
    output = output.absolute()
    if output.exists() or output.is_symlink() or ROOT == output.resolve() or ROOT in output.resolve().parents:
        raise ValueError("use a new output directory outside the source checkout")
    output.mkdir(mode=0o700)
    dist = output / "dist"
    dist.mkdir()
    build = execute("build-once", [sys.executable, "-c", BUILD_PROGRAM, str(dist)], output)
    before = distributions(dist, source["version"])
    commands = ([sys.executable, "test_azt.py"],
                [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
                [sys.executable, "scripts/test_artifact.py", str(dist)])
    tests = [execute(label, command, output) for label, command in zip(TESTS, commands)]
    if distributions(dist, source["version"]) != before or source_identity(event, expected, tag) != source:
        raise ValueError("source or distributions changed during verification")
    manifest = {"schema": "azt.release-manifest.v1", "status": "verified",
                "source": source, "event": event, "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
                "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "1"),
                "repository": os.environ.get("GITHUB_REPOSITORY", "local"),
                "python": platform.python_version(), "pip": importlib.metadata.version("pip"), "dependencies": dependencies,
                "build": build, "tests": tests, "distributions": before,
                "scope": "offline scanner/unit/installed wheel/extracted sdist tests; no new runtime trial"}
    raw = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    with (output / "release-manifest.json").open("x") as stream:
        stream.write(raw)
    summary = ("## Tested release candidate (not published)\n\nSource: `" + source["sha"] +
               "`\n\nTag: `" + (tag or "none — non-publishing validation") +
               "`\n\nRun: " + manifest["run_id"] + ", attempt " + manifest["run_attempt"] +
               "\n\nAll three offline test groups passed; see release-manifest.json.\n\n")
    for name, value in before.items():
        summary += "- `" + name + "`: SHA-256 `" + value["sha256"] + "`\n"
    summary += "\nOwner approval must refer to this source and these bytes. Checksums are not independent proof of a trustworthy build. No FS-001 rerun.\n"
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as stream:
            stream.write(summary)
    print(raw)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        build_candidate(args.output, os.environ.get("GITHUB_EVENT_NAME", "local"),
                        os.environ.get("GITHUB_SHA", ""), os.environ.get("AZT_RELEASE_TAG", ""))
    except (ValueError, OSError, subprocess.SubprocessError, importlib.metadata.PackageNotFoundError) as error:
        print("release validation failed: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
