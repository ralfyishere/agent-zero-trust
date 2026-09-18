"""Exercise the maintainer selection guard, not a substitute Actions validator."""
import os
from pathlib import Path
import subprocess
import unittest


class ResearchWorkflowTests(unittest.TestCase):
    def test_selection_guard_handles_identity_as_data_before_checkout(self):
        text=(Path(__file__).resolve().parents[1]/'.github/workflows/research.yml').read_text()
        block=text.split("          python3 -I - <<'PY'\n",1)[1].split('\n          PY',1)[0]
        script='\n'.join(line[10:] for line in block.splitlines())
        env=dict(os.environ, EXPECTED_SOURCE='a'*40,GITHUB_SHA='a'*40,
                 GITHUB_REPOSITORY='ralfyishere/agent-zero-trust',
                 GITHUB_ACTOR='ralfyishere',GITHUB_TRIGGERING_ACTOR='ralfyishere')
        for changes,expected in (({},0),({'EXPECTED_SOURCE':'b'*40},1),
                ({'EXPECTED_SOURCE':'$(touch NEVER_EXECUTE)'},1),
                ({'GITHUB_REPOSITORY':'other/repository'},1),
                ({'GITHUB_ACTOR':'other'},1),({'GITHUB_TRIGGERING_ACTOR':'other'},1)):
            with self.subTest(changes=changes):
                result=subprocess.run(['python3','-I','-c',script],env=dict(env,**changes),
                                      capture_output=True,timeout=5)
                self.assertEqual(result.returncode,expected)
        self.assertLess(text.index('Verify explicit selection'),text.index('uses: actions/checkout@'))
        self.assertIn('workflow_dispatch:',text)
        self.assertIn('inputs.source_sha == github.sha',text)
        self.assertNotIn('pull_request_target:',text)
        self.assertNotIn('id-token:',text)
        self.assertNotIn('upload-artifact',text)


if __name__=='__main__': unittest.main()
