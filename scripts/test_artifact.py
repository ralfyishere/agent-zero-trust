"""Install the built candidate wheel offline and test the installed CLI.

Run after building: python scripts/test_artifact.py dist
Only test-owned virtual environments are installed into. Corpus files are data.
"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tarfile
import venv


def test_action_inputs(root):
    """Exercise the real action shell with a recording pipx function (no install)."""
    action = (root / "action.yml").read_text(encoding="utf-8")
    block = action.split("      run: |\n", 1)[1]
    script = "\n".join(line[8:] for line in block.splitlines())
    assert "${{" not in script, "action inputs must not be interpolated into shell code"
    recorder = "pipx() { \"$AZT_TEST_PYTHON\" -c 'import json,sys; print(json.dumps(sys.argv[1:]))' \"$@\"; }\n"
    with tempfile.TemporaryDirectory(prefix="azt-action-test-") as temp:
        marker = Path(temp) / "executed"
        payload = '$(touch "%s")`touch "%s"`; echo injected' % (marker, marker)
        env = dict(os.environ, AZT_TEST_PYTHON=sys.executable,
                   GITHUB_ACTION_PATH=str(root), AZT_ACTION_VERSION="",
                   AZT_FAIL_ON="high", AZT_SCAN_PATH=payload)

        def invoke(**changes):
            return subprocess.run(["bash", "-s"], input=recorder + script,
                                  env=dict(env, **changes), capture_output=True,
                                  text=True, timeout=10)

        result = invoke()
        assert result.returncode == 0, result.stderr
        args = json.loads(result.stdout)
        assert args[args.index("--spec") + 1] == str(root)
        assert args[-2:] == ["--", payload]
        assert not marker.exists(), "shell metacharacters in input executed"
        assert json.loads(invoke(AZT_SCAN_PATH="--gate").stdout)[-2:] == ["--", "--gate"]
        assert invoke(AZT_ACTION_VERSION=payload).returncode == 2
        assert invoke(AZT_FAIL_ON=payload).returncode == 2
        args = json.loads(invoke(AZT_ACTION_VERSION="0.1.7").stdout)
        assert args[args.index("--spec") + 1] == "agent-zero-trust==0.1.7"
        args = json.loads(invoke(AZT_ACTION_VERSION="latest").stdout)
        assert args[args.index("--spec") + 1] == "agent-zero-trust"
        assert not marker.exists()
    print("ACTION ARGUMENT PASS: 6 cases; shell metacharacters stay data; invalid inputs fail; local candidate default")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dist", type=Path, nargs="?", default=Path("dist"))
    parser.add_argument("--action-only", action="store_true",
                        help="test action shell argument handling without building or installing")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    test_action_inputs(root)
    if args.action_only:
        return 0
    wheels = sorted(args.dist.resolve().glob("agent_zero_trust-*.whl"))
    if len(wheels) != 1:
        parser.error("expected exactly one candidate wheel; use a clean dist directory")
    version = re.search(r'^version = "([^"]+)"',
                        (root / "pyproject.toml").read_text(), re.M).group(1)
    sdists = sorted(args.dist.resolve().glob("agent_zero_trust-*.tar.gz"))
    if len(sdists) != 1:
        parser.error("expected exactly one candidate source distribution")
    with tempfile.TemporaryDirectory(prefix="azt-sdist-") as temporary:
        unpack = Path(temporary).resolve()
        with tarfile.open(sdists[0]) as archive:
            for member in archive.getmembers():
                path = Path(member.name)
                if path.is_absolute() or ".." in path.parts or not (member.isdir() or member.isfile()):
                    raise AssertionError("unsafe source archive member")
            # Link and traversal entries rejected above, including on Python 3.9
            # where tarfile's newer extraction filter is unavailable.
            archive.extractall(unpack)
        source = unpack / ("agent_zero_trust-" + version)
        for needed in ("action.yml", "schemas/policy-v1.schema.json", "corpus/hook-trap/.claude/settings.json",
                       "packs/AZT-FS-001/v1/candidate.compose.json", "packs/AZT-FS-001/v1/variant/candidate.compose.json",
                       "schemas/safety-evidence-v2.schema.json", "scripts/test_safety_integration.py",
                       "examples/change-review/fixtures.json", "azt_resources/guidance-v1.json",
                       "azt_resources/changes-v1.schema.json", "azt_sensitive.py",
                       "azt_resources/scan-v2.schema.json", "azt_resources/review-v2.schema.json",
                       "azt_resources/changes-v2.schema.json", "examples/sensitive-request/challenge-v1.json",
                       "scripts/sensitive_request_lab.py"):
            assert (source / needed).is_file(), "sdist missing " + needed
        assert not (source / ".azt-local").exists(), "private continuity state must not ship"
        result = subprocess.run([sys.executable, "test_azt.py"], cwd=source,
                                capture_output=True, text=True, timeout=90)
        assert result.returncode == 0, "sdist corpus tests failed: " + result.stdout + result.stderr
        result = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-q"],
                                cwd=source, capture_output=True, text=True, timeout=90)
        assert result.returncode == 0, "sdist unit tests failed: " + result.stdout + result.stderr
        print("SDIST PASS: extracted source runs corpus tests; hidden fixtures and schema included")
    with tempfile.TemporaryDirectory(prefix="azt-artifact-") as temp:
        work = Path(temp).resolve()
        environment = work / "venv"
        venv.EnvBuilder(with_pip=True).create(environment)
        bindir = environment / ("Scripts" if os.name == "nt" else "bin")
        python = bindir / ("python.exe" if os.name == "nt" else "python")
        cli = bindir / ("azt.exe" if os.name == "nt" else "azt")
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        env.pop("PYTHONHOME", None)
        env.update(PYTHONNOUSERSITE="1", PIP_CONFIG_FILE=os.devnull)

        def run(command, expected=0):
            result = subprocess.run([str(value) for value in command], cwd=work,
                                    env=env, capture_output=True, text=True, timeout=90)
            if result.returncode != expected:
                raise AssertionError("expected exit %d, got %d: %s\n%s" %
                                     (expected, result.returncode, result.stdout, result.stderr))
            return result.stdout

        run([python, "-m", "pip", "install", "--no-index", "--no-deps", wheels[0]])
        loaded = run([python, "-I", "-c", "import azt; print(azt.__file__)"]).strip()
        if environment.resolve() not in Path(loaded).resolve().parents:
            raise AssertionError("scanner imported from outside clean installed environment")
        assert "scan" in run([cli, "--help"])
        assert run([cli, "--version"]).strip() == "agent-zero-trust " + version
        benign = [cli, "scan", root / "corpus" / "benign-repo", "--json"]
        first = run(benign)
        assert first == run(benign), "repeated JSON scans must be byte-identical"
        report = json.loads(first)
        assert report["version"] == version
        assert not any(f["severity"] in ("HIGH", "MEDIUM") for f in report["findings"])
        assert report["scope"]["complete"] is True
        malicious = json.loads(run([cli, "scan", root / "corpus" / "malicious-markdown",
                                    "--json"], expected=1))
        assert any(f["rule"] == "net.pipe_shell" and f["severity"] == "HIGH"
                   for f in malicious["findings"]), "expected finding required, not arbitrary failure"
        invalid = json.loads(run([cli, "scan", work / "missing", "--json"], expected=2))
        assert isinstance(invalid, dict)
        compare = [cli, "safety", "compare", "--baseline", root / "packs/AZT-FS-001/v1/baseline.compose.json",
                   "--candidate", root / "packs/AZT-FS-001/v1/candidate.compose.json",
                   "--protected-source", "./synthetic-vault", "--json"]
        safety_first = run(compare + ["--output", work / "review-one"])
        assert safety_first == run(compare + ["--output", work / "review-two"])
        assert json.loads(safety_first)["comparison"]["candidate_declares_protected_access"] is True
        for test in ("test_config.py", "test_safety.py", "test_safety_reporting.py"):
            run([python, "-I", "-m", "unittest", "discover", "-s", root / "tests", "-p", test, "-q"])
        print("SAFETY ARTIFACT PASS: installed adapter/evaluator tests; repeatable CLI comparison; no Docker trials")
        run([python, "-I", "-m", "unittest", "discover", "-s", root / "tests", "-p", "test_review.py", "-q"])
        for test in ('test_sensitive.py', 'test_sensitive_review.py', 'test_sensitive_associations.py'):
            run([python, "-I", "-m", "unittest", "discover", "-s", root / "tests", "-p", test, "-q"])
        for resource in ("review-v1", "changes-v1", "guidance-v1", "scan-v2", "review-v2", "changes-v2"):
            run([python, "-I", "-c", "from importlib.resources import files; import json; json.loads(files('azt_resources').joinpath('"+resource+".schema.json').read_text())"])
        run([python, "-I", root / "scripts/change_review_lab.py", "--cli", cli, "--output", work / "lab"])
        print("REVIEW ARTIFACT PASS: installed review regressions, catalog/schemas, four-case scan/compare/explain/HTML/JSON lab")
        run([python, "-I", root / "scripts/sensitive_request_lab.py", "--cli", cli, "--output", work / "sensitive lab"])
        run([python, root / "scripts/evaluate_sensitive.py", "--cli", cli, "--output", work / "sensitive challenge"])
        run([python, root / "scripts/evaluate_associations.py", "--python", python, "--output", work / "associations.json"])
        print("SENSITIVE ARTIFACT PASS: installed analysis/dependency/exception regressions; 5 development + 8 reviewer-authored inputs; no runtime trials")
        print("ARTIFACT PASS: clean offline wheel install; installed import; help/version; "
              "deterministic JSON; benign=0; malicious=1 with net.pipe_shell; invalid target=2")
    return 0


if __name__ == "__main__":
    sys.exit(main())
