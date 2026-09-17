"""Capture two frozen synthetic cases with the exact released AZT wheel.

Stdlib-only asset tooling: creates an external temporary environment, installs
only the explicit wheel without an index, and runs reviewed AZT commands. It
never follows the requests in the fixture text or contacts their destinations.
"""

import argparse
import datetime
import hashlib
import json
import os
import platform
import subprocess
import tempfile
import venv
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
VERSION = "0.1.14"
SOURCE = "fce49dd727f1be4ba4407394a6b4f544e763ef20"
WHEEL_SHA256 = "be250d871a1b3783423ac92e96238e5154beec4b358015c07371ddecdf98db68"
PACK_SHA256 = "10929881e531a9de75e9f71b40a2db1a55f6c1e95178ea078860b7b04c8d9941"
MAX_OUTPUT = 2_000_000


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path,
                        help="new output directory; never overwrite an old capture")
    args = parser.parse_args()
    wheel_path = args.wheel.resolve(strict=True)
    require(digest(wheel_path.read_bytes()) == WHEEL_SHA256,
            "The wheel does not match the reviewed 0.1.14 release artifact.")
    output = args.output.absolute()
    require(not output.exists() and not output.is_symlink(), "Output already exists.")
    output.parent.resolve(strict=True)
    pack_bytes = (ROOT / "examples/sensitive-request/development-v1.json").read_bytes()
    require(digest(pack_bytes) == PACK_SHA256, "The frozen development pack changed.")
    pack = json.loads(pack_bytes)
    selected = {case["id"]: case for case in pack["cases"]
                if case["id"] in ("limited", "broad-original")}
    require(len(selected) == 2, "The two reviewed cases are required.")
    products = {}
    commands = []
    observations = {}
    with tempfile.TemporaryDirectory(prefix="azt diagnostic capture ",
                                     dir=Path(tempfile.gettempdir()).resolve()) as temporary:
        work = Path(temporary)
        (work / "home").mkdir()
        environment = {"PATH": os.defpath, "HOME": str(work / "home"),
                       "TMPDIR": str(work), "PYTHONNOUSERSITE": "1",
                       "PIP_CONFIG_FILE": os.devnull}
        env_path = work / "installed environment"
        venv.EnvBuilder(with_pip=True).create(env_path)
        python = str(env_path / "bin/python")

        def execute(arguments, expected=0, timeout=20):
            with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                completed = subprocess.run(arguments, cwd=work, env=environment,
                                           stdout=stdout, stderr=stderr, timeout=timeout)
                stdout.seek(0)
                stderr.seek(0)
                result, errors = stdout.read(MAX_OUTPUT + 1), stderr.read(MAX_OUTPUT + 1)
            require(len(result) <= MAX_OUTPUT and len(errors) <= MAX_OUTPUT,
                    "Capture exceeded the output limit.")
            require(completed.returncode == expected,
                    "A reviewed command returned exit " + str(completed.returncode) +
                    " rather than " + str(expected) + ".")
            return result, errors

        execute([python, "-I", "-m", "pip", "--isolated", "install",
                 "--no-index", "--no-deps", str(wheel_path)], timeout=90)
        identity_bytes, errors = execute([
            python, "-I", "-c",
            "import hashlib,importlib,json,pathlib,platform,sys; "
            "names=['azt','azt_sensitive','azt_intake','azt_review']; "
            "modules={n:pathlib.Path(importlib.import_module(n).__file__) for n in names}; "
            "print(json.dumps({'python':platform.python_version(),'modules':"
            "{n:{'environment_relative_path':str(p.relative_to(sys.prefix)),"
            "'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for n,p in modules.items()}}))"
        ])
        require(not errors, "Installed identity check wrote diagnostics.")
        installed_identity = json.loads(identity_bytes)
        with zipfile.ZipFile(wheel_path) as wheel:
            for name, identity in installed_identity["modules"].items():
                require(identity["sha256"] == digest(wheel.read(name + ".py")),
                        "An installed module differs from the release wheel.")

        def azt(label, arguments, expected=0, save_as=None):
            result, errors = execute([python, "-I", "-m", "azt", *map(str, arguments)], expected)
            require(not errors, "An AZT command wrote unexpected diagnostics.")
            commands.append({"command": label, "exit": expected,
                             "stdout_sha256": digest(result), "stderr_bytes": 0,
                             "stdout_file": save_as})
            if save_as:
                products[save_as] = result
            return result

        require(azt("azt --version", ["--version"]).decode().strip() ==
                "agent-zero-trust " + VERSION, "Unexpected installed AZT version.")
        reports = work / "reports"
        reports.mkdir()
        fixtures = {}
        for name in ("limited", "broad-original"):
            target = work / "fixtures" / name
            target.mkdir(parents=True)
            fixtures[name] = {}
            # Only these reviewed case paths are eligible; pack metadata never
            # chooses a command, import, expected exit or output location.
            for relative, text in selected[name]["files"].items():
                require(relative in ("README.md", "docs/maintainer-contact.txt"),
                        "Unexpected fixture path.")
                path = target / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                data = text.encode("utf-8")
                path.write_bytes(data)
                fixtures[name][relative] = {"text": text, "sha256": digest(data)}
            saved = "before.json" if name == "limited" else "after.json"
            scan_bytes = azt("azt scan fixtures/" + name + " --json",
                             ["scan", target, "--json"], save_as=saved)
            scan = json.loads(scan_bytes)
            require(scan["scope"]["complete"] is True and not scan["scope"]["errors"],
                    "A fixture inspection was incomplete.")
            findings = scan["findings"]
            if name == "limited":
                require(findings == [], "The minimized control unexpectedly has findings.")
            else:
                require(len(findings) == 1 and findings[0]["rule"] ==
                        "request.sensitive_disclosure" and findings[0]["severity"] == "MEDIUM",
                        "The broad case did not yield the expected single MEDIUM review finding.")
                request = findings[0]["sensitive_request"]
                require(request["information_classes"] ==
                        ["configuration", "environment", "shell-history"],
                        "The broad request's observed information classes changed.")
                require(request["destination"] ==
                        {"status": "explicit", "kind": "email", "count": 1},
                        "The synthetic referenced destination was not established as expected.")
            # The external working directory permits real relative CLI paths,
            # so the human scan output needs no personal-path substitution.
            human_filename = "before.txt" if name == "limited" else "after.txt"
            azt("azt scan fixtures/" + name,
                ["scan", Path("fixtures") / name], save_as=human_filename)
            (reports / saved).write_bytes(scan_bytes)
            observations[name] = {"input_digest": scan["input_digest"], "engine": scan["engine"],
                                  "scope_complete": True, "threshold": scan["threshold"],
                                  "scan_exit": 0, "findings": findings,
                                  "inspected_paths": [entry["path"] for entry in scan["scope"]["inspected"]]}
            medium_exit = 1 if name == "broad-original" else 0
            azt("azt scan fixtures/" + name + " --fail-on medium --json",
                ["scan", target, "--fail-on", "medium", "--json"], medium_exit,
                name + "-medium-scan.json")
            observations[name]["medium_exit"] = medium_exit
        comparison_arguments = ["changes", "--before", reports / "before.json",
                                "--after", reports / "after.json"]
        comparison = json.loads(azt(
            "azt changes --before before.json --after after.json --json",
            comparison_arguments + ["--json"], save_as="changes.json"))
        require(comparison["meaningful_delta"] is True and
                comparison["comparability"] == {"status": "comparable", "reasons": []},
                "The recorded comparison is not complete and comparable.")
        require(len(comparison["findings"]["new"]) == 1 and
                comparison["findings"]["new"][0]["rule"] == "request.sensitive_disclosure",
                "The comparison did not identify the one expected new sensitive request.")
        azt("azt changes --before before.json --after after.json",
            comparison_arguments, save_as="changes.txt")
        azt("azt explain request.sensitive_disclosure",
            ["explain", "request.sensitive_disclosure"], save_as="explanation.txt")
        for format_name in ("text", "html", "json"):
            filename = "report." + {"text": "txt", "html": "html", "json": "json"}[format_name]
            azt("azt report --input after.json --format " + format_name,
                ["report", "--input", reports / "after.json", "--format", format_name],
                save_as=filename)
        # Verify the documented --output operation, not just equivalent stdout.
        exported = reports / "local review.html"
        azt("azt report --input after.json --format html --output 'local review.html'",
            ["report", "--input", reports / "after.json", "--format", "html",
             "--output", exported])
        require(exported.read_bytes() == products["report.html"], "HTML export bytes differ.")
        transcript = ["AZT 0.1.14: recorded synthetic diagnostic-request workflow",
                      "Command paths are portable labels. Output below is actual CLI stdout; bracketed exit records are capture metadata.", ""]
        transcript_files = {"before.txt", "after.txt", "changes.txt", "explanation.txt"}
        for command in commands:
            filename = command["stdout_file"]
            if filename in transcript_files:
                transcript.extend(["$ " + command["command"],
                                   products[filename].decode("utf-8").rstrip("\n"),
                                   "[recorded exit: " + str(command["exit"]) + "]", ""])
        require(commands[-1]["stdout_sha256"] == digest(b""),
                "The documented file export unexpectedly wrote stdout.")
        transcript.extend(["$ " + commands[-1]["command"],
                           "[recorded stdout: empty; exit: 0; exported HTML matches report.html]", ""])
        products["transcript.txt"] = "\n".join(transcript).encode("utf-8")
        for data in products.values():
            require(str(work).encode() not in data and str(ROOT).encode() not in data,
                    "An output contains a machine-specific source or temporary path.")
            require(b"diagnostics@example.invalid" not in data,
                    "A report exposed a recipient value instead of the maintained safe observation.")
        # The only raw source text published is this explicitly synthetic fixture
        # record. CLI reports themselves retain the product's default omissions.
        products["fixtures.json"] = (json.dumps(fixtures, indent=2, sort_keys=True) + "\n").encode()
        capture = {
            "schema": "azt.editorial-capture.v1", "version": VERSION, "source": SOURCE,
            "release_run": "https://github.com/ralfyishere/agent-zero-trust/actions/runs/35176398216",
            "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "wheel": {"filename": wheel_path.name, "sha256": WHEEL_SHA256},
            "pack": {"path": "examples/sensitive-request/development-v1.json", "sha256": PACK_SHA256,
                     "cases": ["limited", "broad-original"]},
            "helper_sha256": digest(Path(__file__).read_bytes()),
            "environment": {"system": platform.system(), "release": platform.release(),
                            "architecture": platform.machine()},
            "installed_identity": installed_identity, "commands": commands, "cases": observations,
            "comparison": {"meaningful_delta": True, "comparability": "comparable"},
            "outputs": {name: digest(data) for name, data in products.items()},
            "scope": "Two frozen synthetic development cases; not held-out evaluation, an executed target, live agent, or runtime protection test.",
            "notes": "Command labels use portable paths; saved stdout bytes are unchanged. Fixture source text is synthetic. Reports omit request text and recipient values by default. The app-startup scenario is editorial framing, not a fixture quote or an observed application failure."
        }
    products["capture.json"] = (json.dumps(capture, indent=2, sort_keys=True) + "\n").encode()
    output.mkdir()
    for filename, data in products.items():
        (output / filename).write_bytes(data)
    print("Captured two frozen scans, threshold checks, comparison, guidance and local exports; all assertions passed.")


if __name__ == "__main__":
    main()
