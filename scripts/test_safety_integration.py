"""Run AZT-FS-001 from an installed wheel. No image pull/build or host workload.

Exit 0: all three runtime phases verified. 1: executed check failed.
2: input/prerequisite blocked. This is separate from intake ContainmentBench.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import venv


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--docker-host", default="unix:///var/run/docker.sock")
    parser.add_argument("--image", default="python:3.12-slim")
    parser.add_argument("--case", choices=("canonical", "variant"), default="canonical",
                        help="explicit bundled input; never discovered from a scanned repository")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    case_root = root / "packs/AZT-FS-001/v1"
    protected = "./synthetic-vault"
    if args.case == "variant":
        case_root = case_root / "variant"
        protected = "./resources/nested-vault"
    wheel = args.wheel.resolve(strict=True)
    output = args.output.absolute()
    if output.exists():
        parser.error("output must not exist")
    start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="azt-installed-safety-") as temp:
        temp = Path(temp).resolve()
        venv.EnvBuilder(with_pip=True).create(temp / "venv")
        python = temp / "venv/bin/python"
        subprocess.run([str(python), "-m", "pip", "install", "--no-index", "--no-deps", str(wheel)],
                       check=True, capture_output=True, timeout=60)
        result = subprocess.run([str(python), "-I", "-m", "azt", "safety", "check",
            "--baseline", str(case_root / "baseline.compose.json"),
            "--candidate", str(case_root / "candidate.compose.json"),
            "--protected-source", protected, "--output", str(output),
            "--docker-host", args.docker_host, "--image", args.image, "--json"],
            cwd=temp, capture_output=True, text=True, timeout=150)
        report = json.loads(result.stdout)
        if report.get("execution") is None:
            print(result.stdout)
            return 2
        execution = report["execution"]
        if result.returncode == 0:
            assert report["schema_version"] == execution["schema_version"] == 2
            assert execution["status"] == "passed" and execution["counts"]["outcomes"]["passed"] == 3
            assert all(n == 3 for n in execution["counts"]["stages"].values())
            assert [r["independent_checks"]["challenge_response_verified"] for r in execution["trials"]] == [False, True, False]
            assert all(r["independent_checks"]["legitimate_task_completed"] for r in execution["trials"])
        else:
            assert result.returncode in (1, 2), "unexpected command failure is not a denial"
        artifact = {"schema_version": 2, "pack": "AZT-FS-001", "pack_version": 1, "case": args.case,
                    "artifact": wheel.name, "artifact_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
                    "package_version": execution["source"]["package_version"],
                    "integration_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    "result": execution["status"], "exit_code": result.returncode,
                    "runtime_counts": execution["counts"], "elapsed_seconds_including_install": round(time.monotonic()-start, 3),
                    "configuration_sha256": execution["configuration_sha256"],
                    "protected_source": protected,
                    "command": "python scripts/test_safety_integration.py --case " + args.case + " --wheel <candidate.whl> --output <new-private-directory> --docker-host <local-unix-endpoint> --image <approved-preloaded-image>",
                    "limitations": "Project-owned evaluator, not a third-party audit. No model calls. Blocked is not runtime denial."}
        # The CLI already reserved the private directory and removed its sessions.
        # Keep artifact identity next to the actual emitted report, not fabricated logs.
        with (output / "artifact.json").open("x", encoding="utf-8") as stream:
            json.dump(artifact, stream, indent=2, sort_keys=True)
        print(json.dumps(artifact, indent=2, sort_keys=True))
        return result.returncode


if __name__ == "__main__":
    sys.exit(main())
