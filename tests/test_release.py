"""Publication plumbing tests. No uploads, credentials or runtime trials."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("release_candidate", ROOT / "scripts/release_candidate.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


def verifier():
    workflow = (ROOT / ".github/workflows/publish.yml").read_text()
    blocks = workflow.split("          # BEGIN FIXED TRANSFER VERIFIER\n")[1:]
    scripts = []
    for block in blocks:
        body = block.split("          # END FIXED TRANSFER VERIFIER", 1)[0]
        scripts.append("\n".join(line[10:] for line in body.splitlines()[1:-1]))
    if len(scripts) != 2 or scripts[0] != scripts[1]:
        raise AssertionError("low-privilege and publishing byte verifiers must be identical")
    return scripts[0]


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="azt release test ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle = self.root / "release-candidate"
        self.dist = self.bundle / "dist"
        self.dist.mkdir(parents=True)
        self.version = "0.1.9"
        self.names = ["agent_zero_trust-0.1.9-py3-none-any.whl", "agent_zero_trust-0.1.9.tar.gz"]
        for name in self.names:
            (self.dist / name).write_bytes(b"synthetic transferred bytes, not executed")
        self.manifest = {
            "schema": "azt.release-manifest.v1", "status": "verified",
            "source": {"sha": "a" * 40, "version": self.version, "tag": ""},
            "run_id": "123", "run_attempt": "1", "repository": "example/test",
            "event": "pull_request", "build": {"exit_code": 0},
            "tests": [{"name": name, "exit_code": 0} for name in release.TESTS],
            "distributions": release.distributions(self.dist, self.version)}
        self.env = dict(os.environ, GITHUB_WORKSPACE=str(self.root), GITHUB_SHA="a" * 40,
                        GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="1",
                        GITHUB_REPOSITORY="example/test", GITHUB_EVENT_NAME="pull_request", AZT_RELEASE_TAG="")

    def check_transfer(self, expected=0, manifest=None, **env):
        (self.bundle / "release-manifest.json").write_text(json.dumps(self.manifest if manifest is None else manifest))
        result = subprocess.run([sys.executable, "-I", "-c", verifier()],
                                env=dict(self.env, **env), capture_output=True, text=True, timeout=10)
        if expected == 0:
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("TRANSFER VERIFIED", result.stdout)
        else:
            self.assertNotEqual(0, result.returncode, result.stdout)
            self.assertNotIn("TRANSFER VERIFIED", result.stdout)

    def test_exact_transfer_and_paths_with_spaces(self):
        self.check_transfer()
        m = copy.deepcopy(self.manifest)
        m["event"], m["source"]["tag"] = "release", "v0.1.9"
        self.check_transfer(manifest=m, GITHUB_EVENT_NAME="release", AZT_RELEASE_TAG="v0.1.9")

    def test_tampered_missing_extra_and_linked_distribution_rejected(self):
        path = self.dist / self.names[0]
        original = path.read_bytes()
        path.write_bytes(b"changed")
        self.check_transfer(1)
        path.unlink()
        self.check_transfer(1)
        path.symlink_to(self.dist / self.names[1])
        self.check_transfer(1)
        path.unlink()
        path.write_bytes(original)
        (self.dist / "private.txt").write_text("synthetic unselected data")
        self.check_transfer(1)

    def test_manifest_identity_and_failed_tests_rejected(self):
        for field, value in (("status", "failed"), ("schema", "unknown"), ("run_id", "other"),
                             ("run_attempt", "2"), ("repository", "other"), ("event", "release")):
            m = copy.deepcopy(self.manifest)
            m[field] = value
            self.check_transfer(1, m)
        for change in ("sha", "tag", "version"):
            m = copy.deepcopy(self.manifest)
            m["source"][change] = "../unsupported"
            self.check_transfer(1, m)
        for change in ("failed", "missing", "duplicate", "build"):
            m = copy.deepcopy(self.manifest)
            if change == "failed":
                m["tests"][1]["exit_code"] = 1
            elif change == "missing":
                m["tests"].pop()
            elif change == "duplicate":
                m["tests"][1] = m["tests"][0]
            else:
                m["build"]["exit_code"] = 1
            self.check_transfer(1, m)

    def test_unsafe_manifest_directory_and_filename_rejected(self):
        m = copy.deepcopy(self.manifest)
        m["distributions"]["../escape"] = m["distributions"].pop(self.names[0])
        self.check_transfer(1, m)
        (self.bundle / "release-manifest.json").unlink()
        (self.root / "other.json").write_text("{}")
        (self.bundle / "release-manifest.json").symlink_to(self.root / "other.json")
        self.check_transfer(1)
        (self.bundle / "release-manifest.json").unlink()
        (self.bundle / "private").write_text("not an approved upload")
        self.check_transfer(1)

    def test_source_tag_and_version_binding(self):
        (self.root / "pyproject.toml").write_text('version = "0.1.9"\n')
        def git(*args):
            if args[0] == "status":
                return ""
            return "a" * 40
        with patch.object(release, "ROOT", self.root), patch.object(release, "git", side_effect=git):
            self.assertEqual("v0.1.9", release.source_identity("release", "a" * 40, "v0.1.9")["tag"])
            for event, sha, tag in (("release", "a" * 40, "v0.1.8"), ("release", "b" * 40, "v0.1.9"),
                                    ("pull_request", "a" * 40, "v0.1.9"), ("unknown", "", "")):
                with self.assertRaises(ValueError):
                    release.source_identity(event, sha, tag)
        with patch.object(release, "ROOT", self.root), patch.object(release, "git", side_effect=["a" * 40, "M changed"]):
            with self.assertRaises(ValueError):
                release.source_identity("local", "", "")

    def test_failed_command_cannot_issue_verified_result(self):
        with self.assertRaisesRegex(ValueError, "failed"):
            release.execute("negative-control", [sys.executable, "-c", "raise SystemExit(7)"], self.root)
        self.assertFalse((self.root / "release-manifest.json").exists())

    def test_artifact_inventory_rejects_extra_files_and_empty_bytes(self):
        (self.dist / self.names[0]).write_bytes(b"")
        with self.assertRaises(ValueError):
            release.distributions(self.dist, self.version)

    def test_publisher_has_no_checkout_tests_or_build_and_pr_cannot_route_there(self):
        workflow = (ROOT / ".github/workflows/publish.yml").read_text()
        publisher = workflow.split("\n  publish:\n", 1)[1]
        self.assertIn("if: github.event_name == 'release' && github.event.action == 'published'", publisher)
        self.assertIn("needs: [build, verify-transfer]", publisher)
        self.assertNotIn("actions/checkout@", publisher)
        self.assertNotIn("scripts/", publisher)
        self.assertNotIn("pip install", publisher)
        self.assertEqual(1, workflow.count("id-token: write"))
        self.assertEqual(1, workflow.count("name: pypi"))
        self.assertIn("persist-credentials: false", workflow)
        verifier()


if __name__ == "__main__":
    unittest.main()
