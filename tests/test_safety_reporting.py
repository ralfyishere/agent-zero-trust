"""Offline controller/evaluator failure tests; mocked Docker is not isolation evidence."""
import copy
import json
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import azt_docker as backend
import azt_safety as safety
import test_safety as fixtures


class ReportingTests(unittest.TestCase):
    def test_frozen_variant_through_normal_cli_and_no_change(self):
        pack = Path(__file__).resolve().parents[1] / "packs/AZT-FS-001/v1/variant"
        for name, digest in (("baseline", "f8f771828b138c05eaec93a0576d425ae91056d9862e6543ac8b4f4290e2b4b6"),
                             ("candidate", "ac8273cbd3a49a6fdf8dfa4f1a9a1b267a276866bf8813ce9f47fa01a456f3c2")):
            self.assertEqual(digest, hashlib.sha256((pack / (name + ".compose.json")).read_bytes()).hexdigest())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            def invoke(candidate, output, operation="compare"):
                result = subprocess.run([sys.executable, str(Path(safety.__file__).with_name("azt.py")),
                    "safety", operation, "--baseline", str(pack / "baseline.compose.json"),
                    "--candidate", str(candidate), "--protected-source", "./resources/nested-vault",
                    "--output", str(root / output), "--json"], cwd=root, capture_output=True, text=True, timeout=10)
                return result.returncode, json.loads(result.stdout)
            code, report = invoke(pack / "candidate.compose.json", "review")
            self.assertEqual(0, code)
            self.assertTrue(report["comparison"]["candidate_declares_protected_access"])
            self.assertFalse(report["comparison"]["access_exercised"])
            self.assertEqual(json.loads((pack / "baseline.compose.json").read_text()),
                             json.loads((root / "review/repaired.compose.json").read_text()))
            self.assertIn("/review-material", (root / "review/repair.diff").read_text())
            code, report = invoke(pack / "baseline.compose.json", "unchanged")
            self.assertEqual((0, "no_change"), (code, report["repair"]["status"]))
            self.assertEqual("", (root / "unchanged/repair.diff").read_text())
            code, report = invoke(pack / "baseline.compose.json", "no-exposure", "check")
            self.assertEqual(2, code)
            self.assertNotEqual("passed", report["status"])
            invalid = json.loads((pack / "candidate.compose.json").read_text())
            invalid["include"] = ["unreviewed.json"]
            path = root / "unsupported.json"
            path.write_text(json.dumps(invalid))
            code, report = invoke(path, "unsupported")
            self.assertEqual((2, "error"), (code, report["status"]))

    def test_actual_controller_progress_survives_later_failures(self):
        for failure in ("start", "probe", "archive", "export", "cleanup", None):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temp:
                record, challenge, canary = fixtures.SafetyTests.record(True)
                with patch("azt_docker.docker_binary", return_value=None):
                    docker = backend.Docker("unix:///unused.sock", Path(temp))
                def command(*args, **kwargs):
                    if args[0] == "start" and failure == "start":
                        raise backend.ExecutionFailed("synthetic start failure")
                    if args[0] == "rm" and failure == "cleanup":
                        raise backend.ExecutionFailed("synthetic cleanup failure")
                    if "/usr/bin/tar" in args:
                        if failure == "export":
                            raise backend.ExecutionFailed("synthetic export failure")
                        return 0, (b"invalid" if failure == "archive" else fixtures.SafetyTests.archive(data=safety.AFTER.encode())), b""
                    if args[0] == "exec":
                        if failure == "probe":
                            raise backend.ExecutionFailed("synthetic probe failure")
                        return 0, json.dumps(record["workload_claim"]).encode(), b""
                    return 0, b"", b""
                with patch.object(docker, "command", side_effect=command), patch.object(docker, "inspect_controls", return_value={}):
                    result = docker.trial("owned", "image", Path(temp), Path(temp), [], challenge, "/canary")
                result["phase"] = "misconfigured"
                result["independent_checks"] = safety.evaluate(result, challenge, canary, True, True, True)
                stages = result["stages"]
                self.assertEqual(failure != "start", stages["container_started"])
                self.assertEqual(failure not in ("start", "probe"), stages["probe_protocol_completed"])
                self.assertEqual(failure not in ("start", "probe", "export"), stages["result_exported"])
                self.assertEqual(failure in (None, "cleanup"), stages["archive_validated"])
                self.assertEqual(failure in (None, "cleanup"), stages["verification_completed"])
                # A failed later stage must retain the independently verified exposure.
                self.assertEqual(failure not in ("start", "probe"), result["independent_checks"]["challenge_response_verified"])
                counts = safety.finalize_trials([result])
                self.assertEqual(3, sum(counts["outcomes"].values()))
                self.assertEqual(2, counts["outcomes"]["unknown"])
                self.assertEqual(int(failure is None), counts["outcomes"]["passed"])

    def test_failed_positive_control_cannot_credit_denials(self):
        for defect in ("challenge", "bytes", "cleanup"):
            trials = []
            for phase, access in zip(safety.PHASES, (False, True, False)):
                record, challenge, canary = fixtures.SafetyTests.record(access)
                record["phase"] = phase
                if access:
                    if defect == "challenge":
                        record["workload_claim"]["response"] = "0" * 64
                    elif defect == "bytes":
                        record["result_bytes"] = b"wrong"
                    else:
                        record["cleanup"] = "failed"
                record["independent_checks"] = safety.evaluate(record, challenge, canary, access, True, True)
                trials.append(record)
            counts = safety.finalize_trials(trials)
            self.assertEqual(3, counts["outcomes"]["failed"])
            self.assertTrue(all(r["stages"]["verification_completed"] for r in trials))
            self.assertFalse(any(r["independent_checks"]["positive_control_confirmed"] for r in trials))
            self.assertFalse(trials[0]["independent_checks"]["access_expectation_met"])

    def test_workload_claim_does_not_set_controller_stage(self):
        record, challenge, canary = fixtures.SafetyTests.record(True)
        record["stages"] = backend.empty_stages()
        checks = safety.evaluate(record, challenge, canary, True, True, True)
        self.assertTrue(checks["challenge_response_verified"])
        self.assertFalse(checks["probe_protocol_completed"])
        self.assertFalse(checks["passed"])

    def test_unknown_missing_records_and_explicit_not_run_are_distinct(self):
        trials = [{"phase": "baseline", "status": "failed", "stages": backend.empty_stages()},
                  {"phase": "misconfigured", "status": "not_run", "stages": backend.empty_stages()}]
        self.assertEqual({"passed": 0, "failed": 1, "blocked": 0, "not_run": 1, "unknown": 1},
                         safety.finalize_trials(trials)["outcomes"])
        self.assertEqual("unknown", trials[-1]["status"])


if __name__ == "__main__":
    unittest.main()
