"""Parser, evaluator, bounded local subprocess and orchestration checks.

No Docker workload is launched here. Mocks verify construction/failure paths,
never containment. Runtime evidence requires the separate Linux integration.
"""
import copy
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

import azt_config
import azt_docker
import azt_safety
from azt_intake import IntakeError
from azt_safety_pack import AFTER


class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.protected = str(self.root / "alternate-vault")
        self.baseline_data = {"services": {"worker": {"image": "python:3.12-slim", "volumes": [
            self.mount("./coding-project", "/workspace", False)]}}}
        self.candidate_data = copy.deepcopy(self.baseline_data)
        self.candidate_data["services"]["worker"]["volumes"].append(
            self.mount("./alternate-vault", "/selected-resource"))

    @staticmethod
    def mount(source, target, read_only=True):
        return {"type": "bind", "source": source, "target": target, "read_only": read_only}

    def configs(self, candidate_data=None):
        candidate_data = candidate_data or self.candidate_data
        for name, data in (("baseline.json", self.baseline_data), ("candidate.json", candidate_data)):
            (self.root / name).write_text(json.dumps(data, indent=2) + "\n")
        baseline = azt_config.load_config(self.root / "baseline.json")
        candidate = azt_config.load_config(self.root / "candidate.json")
        proposal = azt_config.propose_repair(baseline, candidate, self.protected)
        repaired = azt_config.parse_config(proposal["repaired_content"].encode(), candidate.path)
        return baseline, candidate, repaired, proposal

    def test_execution_plan_resolves_alternate_synthetic_name_without_reading_it(self):
        baseline, candidate, repaired, _ = self.configs()
        self.assertFalse(Path(self.protected).exists())
        plan = azt_safety.execution_plan(baseline, candidate, repaired, self.protected)
        self.assertEqual("/selected-resource/canary.bin", plan["probe"])
        self.assertEqual(self.root / "coding-project", plan["project"])
        self.assertFalse(Path(self.protected).exists())

    def test_execution_plan_blocks_runtime_paths_and_writable_additions(self):
        for target in ("/input", "/azt-pack/subdir", "/etc", "/usr/local", "/proc", "/tmp", "/home/example"):
            data = copy.deepcopy(self.candidate_data)
            data["services"]["worker"]["volumes"][-1]["target"] = target
            baseline, candidate, repaired, _ = self.configs(data)
            with self.subTest(target=target), self.assertRaises(azt_docker.BackendBlocked):
                azt_safety.execution_plan(baseline, candidate, repaired, self.protected)
        data = copy.deepcopy(self.candidate_data)
        data["services"]["worker"]["volumes"][-1]["read_only"] = False
        baseline, candidate, repaired, _ = self.configs(data)
        with self.assertRaises(azt_docker.BackendBlocked):
            azt_safety.execution_plan(baseline, candidate, repaired, self.protected)

    def test_execution_plan_blocks_host_sources_and_missing_positive_control(self):
        data = copy.deepcopy(self.candidate_data)
        data["services"]["worker"]["volumes"][-1]["source"] = self.protected
        baseline, candidate, repaired, _ = self.configs(data)
        with self.assertRaises(azt_docker.BackendBlocked):
            azt_safety.execution_plan(baseline, candidate, repaired, self.protected)
        baseline, candidate, repaired, _ = self.configs(self.baseline_data)
        with self.assertRaises(azt_docker.BackendBlocked):
            azt_safety.execution_plan(baseline, candidate, repaired, self.protected)
        with self.assertRaises(azt_docker.BackendBlocked):
            azt_safety.execution_plan(baseline, candidate, repaired, str(self.root.parent / "outside"))

    def test_execution_plan_parent_mount_keeps_probe_relative_to_resource(self):
        self.protected = str(self.root / "resources" / "nested-vault")
        data = copy.deepcopy(self.candidate_data)
        data["services"]["worker"]["volumes"][-1]["source"] = "./resources"
        baseline, candidate, repaired, _ = self.configs(data)
        plan = azt_safety.execution_plan(baseline, candidate, repaired, self.protected)
        self.assertEqual("/selected-resource/nested-vault/canary.bin", plan["probe"])

    @staticmethod
    def record(access):
        challenge, canary = "random-test-challenge", bytes(range(32))
        claim = {"challenge": challenge, "probe_executed": True, "uid": 65532,
                 "task_exit": 0, "task_stdout": "5 0\n", "read": "obtained" if access else "unavailable"}
        if access:
            claim["response"] = hmac.new(canary, challenge.encode(), hashlib.sha256).hexdigest()
        else:
            claim["errno"] = 2
        return {"status": "executed", "cleanup": "removed", "workload_claim": claim,
                "result_bytes": AFTER.encode()}, challenge, canary

    def test_evaluator_checks_positive_control_and_denial_separately(self):
        for access in (False, True):
            record, challenge, canary = self.record(access)
            result = azt_safety.evaluate(record, challenge, canary, access, True, True)
            self.assertTrue(result["passed"])
            self.assertEqual(access, result["challenge_response_verified"])
            self.assertNotIn("result_bytes", record)

    def test_evaluator_rejects_claim_only_success_and_wrong_hmac(self):
        mutations = [("response", "0" * 64), ("response", "forged"),
                     ("challenge", "another-trial"), ("uid", 0), ("probe_executed", False),
                     ("task_exit", 1), ("task_stdout", "tests passed")]
        for key, value in mutations:
            record, challenge, canary = self.record(True)
            record["workload_claim"][key] = value
            with self.subTest(key=key):
                self.assertFalse(azt_safety.evaluate(record, challenge, canary, True, True, True)["passed"])
        record, challenge, canary = self.record(False)
        self.assertFalse(azt_safety.evaluate(record, challenge, canary, True, True, True)["passed"])

    def test_evaluator_rejects_malformed_response_without_crashing(self):
        for response in (None, [], {}, "\u00e9" * 64):
            record, challenge, canary = self.record(True)
            record["workload_claim"]["response"] = response
            with self.subTest(response=response):
                self.assertFalse(azt_safety.evaluate(record, challenge, canary, True, True, True)["passed"])

    def test_evaluator_requires_exported_edit_integrity_and_cleanup(self):
        for field, value in (("result_bytes", b"wrong output"), ("result_bytes", None),
                             ("cleanup", "failed"), ("status", "failed")):
            record, challenge, canary = self.record(False)
            record[field] = value
            self.assertFalse(azt_safety.evaluate(record, challenge, canary, False, True, True)["passed"])
        for original, protected in ((False, True), (True, False)):
            record, challenge, canary = self.record(False)
            self.assertFalse(azt_safety.evaluate(record, challenge, canary, False, original, protected)["passed"])

    def test_bounded_subprocess_success_and_environment_are_real_local_checks(self):
        with patch.dict(os.environ, {"AZT_TEST_SECRET": "synthetic-not-forwarded"}):
            code, out, err = azt_docker.bounded_command([sys.executable, "-I", "-c",
                "import os; print('AZT_TEST_SECRET' in os.environ); print(os.read(0,1))"], timeout=3)
        self.assertEqual(0, code)
        self.assertEqual(b"False\nb''\n", out)
        self.assertEqual(b"", err)

    def test_bounded_subprocess_limits_output_and_deadline(self):
        with self.assertRaisesRegex(azt_docker.ExecutionFailed, "output"):
            azt_docker.bounded_command([sys.executable, "-I", "-c", "print('x'*10000)"], limit=512, timeout=3)
        started = time.monotonic()
        with self.assertRaises((azt_docker.ExecutionFailed, subprocess.TimeoutExpired)):
            azt_docker.bounded_command([sys.executable, "-I", "-c", "import time; time.sleep(2)"], timeout=0.05)
        self.assertLess(time.monotonic() - started, 1.5)

    @staticmethod
    def archive(name="task.py", data=b"result", mode="w", kind=tarfile.REGTYPE, pax=None):
        target = io.BytesIO()
        with tarfile.open(fileobj=target, mode=mode, format=tarfile.PAX_FORMAT) as archive:
            info = tarfile.TarInfo(name)
            info.type = kind
            info.size = len(data) if kind == tarfile.REGTYPE else 0
            if kind == tarfile.SYMTYPE:
                info.linkname = "/outside"
            if pax:
                info.pax_headers = pax
            archive.addfile(info, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
        return target.getvalue()

    def test_result_tar_accepts_plain_bounded_result_and_small_pax(self):
        self.assertEqual(b"result", azt_docker.result_from_tar(self.archive()))
        self.assertEqual(b"result", azt_docker.result_from_tar(self.archive(pax={"mtime": "1.5"})))

    def test_result_tar_rejects_compression_names_links_and_metadata_bombs(self):
        archives = [self.archive(mode="w:gz"), self.archive(name="../task.py"),
                    self.archive(name="/task.py"), self.archive(kind=tarfile.SYMTYPE),
                    self.archive(data=b"x" * 4097), self.archive(pax={"comment": "x" * 5000}),
                    self.archive(mode="w:gz", pax={"comment": "x" * 1048576}),
                    self.archive(pax={"GNU.sparse.name": "task.py"})]
        for index, raw in enumerate(archives):
            with self.subTest(index=index), self.assertRaises((azt_docker.ExecutionFailed, tarfile.TarError)):
                azt_docker.result_from_tar(raw)

    def test_output_rejects_symlinks_existing_paths_and_oversize(self):
        existing = self.root / "existing"
        existing.mkdir()
        link = self.root / "link"
        link.symlink_to(existing, target_is_directory=True)
        for output in (existing, link, link / "child", self.root / ".." / "escape"):
            with self.subTest(output=output), self.assertRaises((OSError, IntakeError)):
                azt_safety.reserve_output(output)
        output = self.root / "fresh"
        fd = azt_safety.reserve_output(output)
        self.addCleanup(os.close, fd)
        azt_safety.write_output(fd, "evidence.json", b"{}")
        with self.assertRaises(OSError):
            azt_safety.write_output(fd, "evidence.json", b"replace")
        with self.assertRaises(IntakeError):
            azt_safety.write_output(fd, "oversized", b"x" * (512 * 1024 + 1))
        self.assertEqual(b"{}", (output / "evidence.json").read_bytes())

    def test_output_file_name_cannot_escape_directory(self):
        fd = azt_safety.reserve_output(self.root / "fresh")
        self.addCleanup(os.close, fd)
        for name in ("../escape", "/absolute", "nested/path"):
            with self.subTest(name=name), self.assertRaises((IntakeError, OSError)):
                azt_safety.write_output(fd, name, b"unsafe")
        self.assertFalse((self.root / "escape").exists())

    def test_mocked_missing_client_classification_is_not_runtime_evidence(self):
        baseline, candidate, _, proposal = self.configs()
        with patch("azt_docker.docker_binary", return_value=None):
            result = azt_safety.run_check(baseline, candidate, self.protected, proposal,
                                          "unix:///definitely-absent-azt-test.sock", "python:3.12-slim")
        self.assertEqual("blocked", result["status"])
        self.assertEqual("missing_client", result["backend"]["reason"])
        self.assertEqual({"planned": 3, "executed": 0, "passed": 0, "blocked": 3, "not_run": 0}, result["counts"])
        self.assertTrue(all(trial["legitimate_task_completed"] is None for trial in result["trials"]))

    def test_mocked_construction_does_not_launch_or_pull(self):
        with patch("azt_docker.docker_binary", return_value=None):
            docker = azt_docker.Docker("unix:///unused.sock", self.root)
        args = docker.create_args("test-owned", "sha256:" + "a" * 64, self.root / "probe",
                                  self.root / "project", [(self.root / "vault", "/selected", True)])
        self.assertEqual("never", args[args.index("--pull") + 1])
        self.assertEqual("none", args[args.index("--network") + 1])
        self.assertIn("--no-healthcheck", args)
        self.assertIn("--read-only", args)
        self.assertNotIn("--privileged", args)
        with self.assertRaises(azt_docker.BackendBlocked):
            docker.create_args("test-owned", "image", self.root, self.root, [(self.root, "/extra", False)])

    def test_nonlocal_endpoint_is_rejected_before_client_invocation(self):
        for endpoint in ("tcp://example.invalid:2375", "ssh://example.invalid", "unix:///tmp/../daemon.sock"):
            with self.subTest(endpoint=endpoint), self.assertRaises(azt_docker.BackendBlocked):
                azt_docker.Docker(endpoint, self.root)

    def test_mocked_malformed_result_and_cleanup_failure_never_credit_denial(self):
        with patch("azt_docker.docker_binary", return_value=None):
            docker = azt_docker.Docker("unix:///unused.sock", self.root)
        for cleanup_fails in (False, True):
            calls = []

            def command(*args, **kwargs):
                calls.append(args)
                if args[0] == "exec":
                    return 0, b'{"read":"unavailable"}', b""
                if args[0] == "cp":
                    return 0, b"not a tar archive", b""
                if args[0] == "rm" and cleanup_fails:
                    raise azt_docker.ExecutionFailed("synthetic cleanup failure")
                return 0, b"", b""

            with patch.object(docker, "command", side_effect=command), patch.object(docker, "inspect_controls", return_value={}):
                record = docker.trial("test-owned", "image", self.root / "probe", self.root / "project",
                                      [], "challenge", "/selected/canary.bin")
            self.assertEqual("failed", record["status"])
            self.assertEqual("failed" if cleanup_fails else "removed", record["cleanup"])
            self.assertIn(("rm", "--force", "test-owned"), calls)
            self.assertNotIn("result_bytes", record)

    def test_cli_repeated_static_compare_and_missing_endpoint_are_machine_readable(self):
        baseline, candidate, _, _ = self.configs()
        script = str(Path(azt_safety.__file__).with_name("azt.py"))
        common = [sys.executable, script, "safety", "compare", "--baseline", str(baseline.path),
                  "--candidate", str(candidate.path), "--protected-source", "./alternate-vault", "--json"]
        for index in range(2):
            process = subprocess.run(common + ["--output", str(self.root / ("compare-" + str(index)))],
                                     capture_output=True, text=True, timeout=10)
            self.assertEqual(0, process.returncode, process.stderr)
            report = json.loads(process.stdout)
            self.assertEqual("compared", report["status"])
            self.assertIsNone(report["execution"])
        common[3] = "check"
        process = subprocess.run(common + ["--output", str(self.root / "blocked"), "--docker-host",
            "unix://" + str(self.root / "not-a-docker-socket")], capture_output=True, text=True, timeout=15)
        self.assertEqual(2, process.returncode, process.stderr)
        report = json.loads(process.stdout)
        self.assertEqual("blocked", report["status"])
        self.assertEqual(0, report["execution"]["counts"]["executed"])
        self.assertEqual(candidate.raw, candidate.path.read_bytes())


if __name__ == "__main__":
    unittest.main()
