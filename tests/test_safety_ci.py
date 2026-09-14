"""CI routing/export/failure tests; mocks are NOT Docker execution evidence."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile

SPEC = importlib.util.spec_from_file_location("safety_ci", Path(__file__).resolve().parent.parent / "scripts/safety_ci.py")
ci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci)


class SafetyCITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def test_host_routing_guard_blocks_normal_local_use(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(ValueError):
            ci.host_guard()

    def test_image_metadata_is_not_execution_and_requires_exact_family(self):
        data = {"Os": "linux", "Architecture": "amd64", "Config": {"Env": ["PYTHON_VERSION=3.12.12"]}}
        self.assertEqual("3.12.12", ci.image_compatibility(data)["declared_python"])
        for version in ("3.13.0", "", "3.12.0-rc", "3.12.1\n"):
            data["Config"]["Env"] = ["PYTHON_VERSION=" + version]
            with self.assertRaises(ValueError):
                ci.image_compatibility(data)
        data["Architecture"] = "arm64"
        with self.assertRaises(ValueError):
            ci.image_compatibility(data)

    def test_mocked_cleanup_is_exact_and_bounded(self):
        name = "azt-fs001-" + "a" * 24
        docker = Mock()
        docker.command.side_effect = [(0, name.encode(), b""), (0, b"", b""), (0, b"", b"")]
        self.assertEqual([name], ci.cleanup(docker)["removed_names"])
        docker.command.assert_any_call("rm", "--force", name, timeout=5)
        for names in ("other-container", "azt-fs001-../../escape", "\n".join([name] * 4)):
            docker = Mock()
            docker.command.return_value = (0, names.encode(), b"")
            with self.assertRaises(ValueError):
                ci.cleanup(docker)
            self.assertEqual(1, docker.command.call_count)

    def test_mocked_cleanup_requires_absence_readback(self):
        docker = Mock()
        docker.command.side_effect = [(0, b"", b""), (0, b"remaining-id", b"")]
        with self.assertRaises(ValueError):
            ci.cleanup(docker)

    def test_export_setup_failure_not_success_and_no_unselected_files(self):
        (self.root / "proposal.json").write_text('"synthetic-secret-not-for-export"')
        with contextlib.redirect_stdout(io.StringIO()) as stream:
            self.assertEqual(0, ci.finish(self.root))
        text = stream.getvalue()
        value = json.loads(text.splitlines()[1])
        self.assertIn("outcome unknown", value["setup"])
        self.assertNotIn("synthetic-secret", text)
        self.assertEqual("not_acquired", value["cleanup"]["status"])

    def test_export_preserves_failed_result_and_redacts_path(self):
        ci.write_json(self.root / "ci-run.json", {"status": "check_failed", "input": str(ci.ROOT)})
        with contextlib.redirect_stdout(io.StringIO()) as stream:
            ci.finish(self.root)
        value = json.loads(stream.getvalue().splitlines()[1])
        self.assertEqual("check_failed", value["records"]["ci-run.json"]["status"])
        self.assertEqual("$SOURCE_ROOT", value["records"]["ci-run.json"]["input"])

    def test_export_bounds_and_links(self):
        with self.assertRaises(ValueError):
            ci.write_json(self.root / "big.json", {"data": "x" * 65536})
        (self.root / "real.json").write_text("{}")
        (self.root / "alias.json").symlink_to(self.root / "real.json")
        with self.assertRaises(ValueError):
            ci.read_json(self.root / "alias.json")

    def test_mocked_prerequisite_blocked_never_starts_runtime(self):
        wheel = self.root / "test.whl"
        with zipfile.ZipFile(wheel, "w") as archive:
            for name in ci.MODULES:
                archive.writestr(name, b"reviewed")
                (self.root / name).write_bytes(b"reviewed")
        def git(*args):
            if args == ("rev-parse", "HEAD"):
                return "a" * 40
            if args == ("rev-parse", "HEAD^{tree}"):
                return "b" * 40
            return ""
        docker = Mock()
        docker.preflight.return_value = {"status": "blocked", "reason": "required_control_missing"}
        with patch.object(ci, "ROOT", self.root), patch.object(ci, "git", side_effect=git), \
                patch.object(ci, "Docker", return_value=docker), patch.object(ci, "bounded_command") as command, \
                patch.dict(os.environ, {"GITHUB_SHA": "a" * 40}):
            self.assertEqual(2, ci.run(wheel, self.root))
            command.assert_not_called()
        report = ci.read_json(self.root / "ci-run.json")
        self.assertFalse(report["runtime_started"])
        self.assertEqual("prerequisite_blocked", report["status"])
        self.assertFalse((self.root / "cleanup-scope.json").exists())

    def test_mocked_stale_checkout_fails_before_docker(self):
        with patch.object(ci, "git", return_value="wrong-sha"), patch.object(ci, "Docker") as docker:
            self.assertEqual(2, ci.run(self.root / "absent.whl", self.root))
            docker.assert_not_called()
        self.assertEqual("operational_failure", ci.read_json(self.root / "ci-run.json")["status"])

    def test_workflow_is_single_public_branch_push_without_storage_upload(self):
        text = (ci.ROOT / ".github/workflows/safety-fs001.yml").read_text()
        for required in ("branches: [fix/trusted-intake-evidence]", "runs-on: ubuntu-24.04",
                         "persist-credentials: false", "github.run_attempt == 1", "[azt-fs001-once]",
                         "github.event.repository.private == false", "if: always()", "timeout-minutes: 12"):
            self.assertIn(required, text)
        for forbidden in ("pull_request_target:", "workflow_dispatch:", "uses: actions/upload-artifact", "secrets.", "sudo "):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
