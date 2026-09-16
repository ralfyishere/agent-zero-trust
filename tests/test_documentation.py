"""Offline checks for active onboarding, not historical version rewriting.

After verifying a new public package release, update RELEASED_VERSION and the
README's install pin/release link together. Do not copy the candidate package
version here or infer PyPI availability from this test. Historical examples and
captured output deliberately retain their original versions.
"""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent
RELEASED_VERSION = "0.1.13"


class DocumentationTests(unittest.TestCase):
    def test_active_install_pin_has_matching_reviewed_release_link(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        quickstart = readme.split("## Scan your project\n", 1)[1].split("<details>", 1)[0]
        self.assertEqual([RELEASED_VERSION],
                         re.findall(r"agent-zero-trust==([0-9]+\.[0-9]+\.[0-9]+)", quickstart))
        self.assertIn("https://github.com/ralfyishere/agent-zero-trust/releases/tag/v" + RELEASED_VERSION,
                      quickstart)
        self.assertNotIn("unreleased", quickstart.lower())

    def test_quickstart_keeps_startup_environment_and_reports_external(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        quickstart = readme.split("## Scan your project\n", 1)[1].split("<details>", 1)[0]
        script = re.search(r"```sh\n(.*?)\n```", quickstart, re.S).group(1)
        # These are intentionally reviewed example commands, not an arbitrary
        # shell interpreter. The complete installed lab tests exercise behavior.
        self.assertLess(script.index('AZT_PROJECT=$(pwd -P)'), script.index('cd "$AZT_REVIEW"'))
        self.assertLess(script.index('cd "$AZT_REVIEW"'), script.index("python3 -m venv"))
        self.assertIn('AZT_REVIEW=$(mktemp -d)', script)
        self.assertIn('AZT_REVIEW=$(cd "$AZT_REVIEW" && pwd -P)', script)
        self.assertIn('python3 -m venv "$AZT_REVIEW/venv"', script)
        self.assertIn('. "$AZT_REVIEW/venv/bin/activate"', script)
        self.assertIn('azt scan "$AZT_PROJECT"', script)
        self.assertIn('> "$AZT_REVIEW/before.json"', readme)
        self.assertIn('--output "$AZT_REVIEW/review.html"', readme)

    def test_current_demo_continues_quickstart_not_a_different_environment(self):
        demo = (ROOT / "docs/demo.md").read_text(encoding="utf-8")
        active = demo.split("<details>", 1)[0]
        self.assertIn("[README quickstart](../README.md)", active)
        self.assertIn("activated terminal and external review directory", active)
        self.assertNotIn(".venv-azt", active)
        self.assertIn("(github-action.md)", active)
        self.assertNotRegex(active, r"uses:\s+ralfyishere/agent-zero-trust@(?:main|v[0-9])")


if __name__ == "__main__":
    unittest.main()
