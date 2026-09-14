"""Explicit, synthetic check–repair–retest orchestration; never runs user code."""
import argparse
import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import re
import platform
import subprocess
import tempfile
import time

import azt_config as adapter
from azt_docker import Docker, BackendBlocked
from azt_intake import IntakeError, open_absolute
from azt_safety_pack import PACK_ID, PACK_VERSION, BEFORE, AFTER, KEEPER, WORKLOAD


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def contains(parent, child):
    return parent == child or parent in child.parents


def protected_path(config, value):
    # Explicit lexical authority, not host discovery or realpath traversal.
    return adapter._source(value, config.path.parent)


def execution_plan(baseline, candidate, repaired, protected):
    """Resolve ONLY a reproducible synthetic subset, never read mount sources."""
    configs = (baseline, candidate, repaired)
    root = candidate.path.parent
    if any(c.path.parent != root for c in configs):
        raise BackendBlocked("execution requires configuration inputs in one directory")
    secret = Path(protected)
    if not contains(root, secret) or secret == root:
        raise BackendBlocked("execution requires a protected source below the explicit configuration directory")
    project = None
    for config in configs:
        workspace = [m for m in config.mounts if m["target"] == "/workspace"]
        if len(workspace) != 1 or workspace[0]["read_only"]:
            raise BackendBlocked("execution requires one writable /workspace declaration")
        current = Path(workspace[0]["source"])
        if project is None:
            project = current
        if current != project or contains(project, secret) or contains(secret, project):
            raise BackendBlocked("project must be unchanged and disjoint from the protected source")
        for mount in config.mounts:
            source, target = Path(mount["source"]), PurePosixPath(mount["target"])
            if not contains(root, source) or source == root or not mount["declared_source"].startswith("./"):
                raise BackendBlocked("execution accepts only ./relative synthetic sources, not host inputs")
            if target == PurePosixPath("/workspace"):
                continue
            reserved = ("/workspace", "/input", "/azt-pack", "/tmp", "/proc", "/sys", "/dev",
                        "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/run", "/root", "/home")
            if (not mount["read_only"] or any(contains(PurePosixPath(p), target) or
                    contains(target, PurePosixPath(p)) for p in reserved)):
                raise BackendBlocked("additional mounts must be read-only and outside runtime/control paths")
            if contains(source, project) or contains(project, source):
                raise BackendBlocked("additional source overlaps the coding project")
    exposed = [m for m in candidate.mounts if contains(Path(m["source"]), secret)]
    if len(exposed) != 1:
        raise BackendBlocked("this execution case requires exactly one candidate exposure")
    if adapter.compare_configs(baseline, candidate, protected)["baseline_declares_protected_access"]:
        raise BackendBlocked("reviewed baseline already declares the protected access")
    mount = exposed[0]
    probe = str(PurePosixPath(mount["target"]) / secret.relative_to(mount["source"]) / "canary.bin")
    return {"root": root, "project": project, "protected": secret, "probe": probe}


def evaluate(record, challenge, canary, expected_access, original_ok, protected_ok):
    """Expectations belong to this evaluator, not the workload or pack JSON."""
    claim = record.get("workload_claim")
    claim = claim if isinstance(claim, dict) else {}
    expected = hmac.new(canary, challenge.encode(), hashlib.sha256).hexdigest()
    response = claim.get("response", "")
    obtained = (isinstance(response, str) and re.fullmatch(r"[0-9a-f]{64}", response) is not None
                and hmac.compare_digest(response, expected))
    probe = (claim.get("probe_executed") is True and claim.get("challenge") == challenge
             and claim.get("uid") == 65532)
    read_matches = (obtained and claim.get("read") == "obtained") if expected_access else (
        not obtained and claim.get("read") == "unavailable" and claim.get("errno") in (1, 2, 13)
        and "response" not in claim)
    # Bytes are copied back independently through the trusted daemon, not merely
    # a statement that a file was edited. Executed output is still observed stdout,
    # not a syscall audit: the mounted bundled probe is part of the TCB.
    task = (record.pop("result_bytes", None) == AFTER.encode() and claim.get("task_exit") == 0
            and claim.get("task_stdout") == "5 0\n")
    complete = record.get("status") == "executed" and record.get("cleanup") == "removed"
    return {"challenge_response_verified": obtained, "probe_protocol_completed": probe,
            "expected_access": expected_access, "access_expectation_met": bool(read_matches and probe),
            "legitimate_task_completed": task, "original_project_unchanged": original_ok,
            "protected_resource_exists_and_unchanged": protected_ok,
            "passed": bool(complete and probe and read_matches and task and original_ok and protected_ok)}


def reserve_output(path):
    """New directory only, held by descriptor. No aliases, overwrites or extraction."""
    target = Path(os.path.abspath(path))
    if any(c in str(path) for c in "\n\r\x00") or ".." in Path(path).parts:
        raise IntakeError("output must be a new canonical directory")
    parent = open_absolute(target.parent, directory=True)
    try:
        if os.fstat(parent).st_uid != os.getuid() or os.fstat(parent).st_mode & 0o022:
            raise IntakeError("output parent must be operator-owned and not group/world writable")
        os.mkdir(target.name, mode=0o700, dir_fd=parent)
        return os.open(target.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    finally:
        os.close(parent)


def write_output(fd, name, raw):
    if not re.fullmatch(r"[a-z][a-z0-9.-]{0,63}", name) or ".." in name:
        raise IntakeError("invalid export basename")
    if len(raw) > 512 * 1024:
        raise IntakeError("evidence export bound exceeded")
    out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    with os.fdopen(out, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def source_identity():
    import azt
    import azt_docker
    import azt_safety_pack
    import azt_intake
    modules = (azt, adapter, azt_docker, azt_safety_pack, azt_intake)
    files = {Path(m.__file__).name: sha(Path(m.__file__).read_bytes()) for m in modules}
    files[Path(__file__).name] = sha(Path(__file__).read_bytes())
    return {"package_version": azt.__version__, "module_sha256": files}


def run_check(baseline, candidate, protected, proposal, endpoint, image):
    repaired_bytes = adapter.verify_repair(candidate.path, proposal, baseline, protected)
    repaired = adapter.parse_config(repaired_bytes, candidate.path, candidate.service)
    plan = execution_plan(baseline, candidate, repaired, protected)
    started = time.monotonic()
    report = {"schema_version": 1, "pack": PACK_ID, "pack_version": PACK_VERSION,
              "source": source_identity(), "status": "blocked", "trials": [],
              "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "probe_sha256": sha(WORKLOAD.encode()), "keeper_sha256": sha(KEEPER.encode()),
              "input_sha256": sha(BEFORE.encode()), "repair_sha256": proposal["repaired_sha256"],
              "configuration_sha256": {"baseline": baseline.sha256, "candidate": candidate.sha256},
              "observation_scope": "bundled probe protocol, HMAC challenge, exported task bytes, host fixture integrity and Docker control readback",
              "limitations": ["synthetic mount substitution; no actual host credentials or user workload executed",
                  "denial relies on bundled probe plus successful positive control, not arbitrary workload assertions",
                  "network, resource exhaustion, controller death and descendant stop are not exercised by this case",
                  "Docker/kernel/image/operator/evaluator are trusted; same-user hostile host code is out of scope",
                  "no model or cloud agent integration; no complete syscall or mutation trace"]}
    policy = {"backend": "docker-native-linux-v1", "network": "none", "cpu_cores": 0.5,
              "memory_bytes": 100663296, "memory_swap_bytes": 100663296, "pids": 32,
              "workspace_bytes": 4194304, "tmp_bytes": 4194304, "shm_bytes": 1048576,
              "file_bytes": 1048576, "keeper_seconds": 20, "probe_seconds": 8,
              "probe_output_bytes": 8192, "archive_output_bytes": 16384,
              "source_mapping": "test-owned synthetic substitution; no host input directories",
              "approved_image_override": image}
    report["requested_policy"] = policy
    report["policy_sha256"] = sha(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode())
    report["platform"] = {"system": platform.system(), "release": platform.release(), "machine": platform.machine()}
    with tempfile.TemporaryDirectory(prefix="azt-fs001-") as temp:
        temp = Path(temp).resolve()
        docker = Docker(endpoint, temp)
        report["backend"] = docker.preflight(image)
        if report["backend"]["status"] != "available":
            report["trials"] = [{"phase": phase, "status": "blocked", "reason": report["backend"]["reason"],
                                 "legitimate_task_completed": None} for phase in ("baseline", "misconfigured", "repaired")]
        else:
            resources, pack = temp / "resources", temp / "probe"
            resources.mkdir(mode=0o755)
            pack.mkdir(mode=0o755)
            for name, content in (("keeper.py", KEEPER), ("workload.py", WORKLOAD)):
                (pack / name).write_text(content, encoding="utf-8")
                (pack / name).chmod(0o444)
            def synthetic(source):
                return resources / Path(source).relative_to(plan["root"])
            for config in (baseline, candidate, repaired):
                for mount in config.mounts:
                    synthetic(mount["source"]).mkdir(parents=True, exist_ok=True, mode=0o755)
            project, protected_dir = synthetic(plan["project"]), synthetic(plan["protected"])
            protected_dir.mkdir(parents=True, exist_ok=True)
            task_file, secret_file = project / "task.py", protected_dir / "canary.bin"
            task_file.write_bytes(BEFORE.encode())
            canary, challenge = secrets.token_bytes(32), secrets.token_hex(32)
            secret_file.write_bytes(canary)
            task_file.chmod(0o444)
            secret_file.chmod(0o444)
            for directory, _, _ in os.walk(resources):
                Path(directory).chmod(0o755)
            report["synthetic_inputs"] = {"project": "task.py", "canary_bytes": 32,
                                           "canary_value_exported": False, "challenge": challenge,
                                           "probe_target": plan["probe"]}
            for phase, config, expected_access in (("baseline", baseline, False),
                    ("misconfigured", candidate, True), ("repaired", repaired, False)):
                mounts = [(synthetic(m["source"]), m["target"], m["read_only"])
                          for m in config.mounts if m["target"] != "/workspace"]
                record = docker.trial("azt-fs001-" + secrets.token_hex(12), report["backend"]["image_id"],
                                      pack, project, mounts, challenge, plan["probe"])
                record["phase"] = phase
                record["independent_checks"] = evaluate(record, challenge, canary, expected_access,
                    task_file.is_file() and task_file.read_bytes() == BEFORE.encode(),
                    secret_file.is_file() and secret_file.read_bytes() == canary)
                report["trials"].append(record)
                if record["cleanup"] == "failed":
                    break  # Do not start more sessions after failed required cleanup.
            positive = any(r["phase"] == "misconfigured" and r["independent_checks"]["passed"]
                           for r in report["trials"])
            for record in report["trials"]:
                checks = record["independent_checks"]
                checks["positive_control_confirmed"] = positive
                if not checks["expected_access"] and not positive:
                    checks["passed"] = False
                    checks["access_expectation_met"] = False
            report["status"] = "passed" if len(report["trials"]) == 3 and all(
                r["independent_checks"]["passed"] for r in report["trials"]) else "failed"
    report["counts"] = {"planned": 3, "executed": sum(r["status"] == "executed" for r in report["trials"]),
                        "passed": sum(r.get("independent_checks", {}).get("passed", False) for r in report["trials"]),
                        "blocked": sum(r["status"] == "blocked" for r in report["trials"]),
                        "not_run": 3 - len(report["trials"])}
    report["elapsed_seconds"] = round(time.monotonic() - started, 3)
    return report


def add_parser(sub):
    parser = sub.add_parser("safety", help="compare explicit mount declarations; optionally run bundled synthetic regression")
    parser.add_argument("operation", choices=("compare", "check"))
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--protected-source", required=True, help="explicit lexical source, e.g. ./synthetic-vault; never discovered")
    parser.add_argument("--service", default="worker")
    parser.add_argument("--output", required=True, help="new evidence/proposal directory under an operator-owned private parent")
    parser.add_argument("--docker-host", default="unix:///var/run/docker.sock")
    parser.add_argument("--image", default="python:3.12-slim", help="explicitly approved, preloaded image; never pulled")
    parser.add_argument("--json", action="store_true")


def command(args):
    fd = None
    try:
        baseline, candidate = adapter.load_config(args.baseline, args.service), adapter.load_config(args.candidate, args.service)
        protected = protected_path(candidate, args.protected_source)
        comparison = adapter.compare_configs(baseline, candidate, protected)
        proposal = adapter.propose_repair(baseline, candidate, protected)
        fd = reserve_output(args.output)
        # Store review materials before execution. If this fails no workload starts.
        for name, raw in (("proposal.json", json.dumps(proposal, indent=2, sort_keys=True).encode()),
                          ("repair.diff", proposal["diff"].encode()), ("repaired.compose.json", proposal["repaired_content"].encode())):
            write_output(fd, name, raw)
        report = {"schema_version": 1, "operation": args.operation, "status": "compared",
                  "comparison": comparison, "repair": {k: proposal[k] for k in
                    ("status", "original_sha256", "repaired_sha256", "affected_indices")}, "execution": None}
        if args.operation == "check":
            report["execution"] = run_check(baseline, candidate, protected, proposal, args.docker_host, args.image)
            report["status"] = report["execution"]["status"]
        # Selected config paths are useful locally but avoid machine-specific root
        # in the export. Actual proposed configuration remains review-only input.
        encoded = json.dumps(report, indent=2, sort_keys=True).replace(str(candidate.path.parent), "$CONFIG_ROOT")
        write_output(fd, "evidence.json", encoded.encode())
        if args.json:
            print(encoded)
        else:
            print("Declared protected access: %s → %s. Repair: %s (%d mount changes)." % (
                comparison["baseline_declares_protected_access"], comparison["candidate_declares_protected_access"],
                proposal["status"], len(proposal["affected_indices"])))
            print("Result: %s. Review repair.diff and evidence.json in the requested output directory." % report["status"])
            if report["execution"]:
                print("Runtime: %s. Legitimate task and access checks are recorded per phase; blocked is not denied." % report["execution"]["counts"])
            else:
                print("Static declarations only; no effective access or runtime repair verified.")
        return 0 if report["status"] in ("compared", "passed") else (2 if report["status"] == "blocked" else 1)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.SubprocessError) as exc:
        report = {"schema_version": 1, "status": "blocked" if isinstance(exc, BackendBlocked) else "error",
                  "error": str(exc) if isinstance(exc, IntakeError) else "input, backend or export operation failed",
                  "runtime_denial_credited": False}
        print(json.dumps(report, sort_keys=True) if args.json else report["error"])
        return 2
    finally:
        if fd is not None:
            os.close(fd)
