"""Assert expected findings in AZT's own explicit PR snapshots.

Maintainer-only candidate test, not a consumer bypass. The bundled attack corpus
requires exit 1. Installation errors/invalid reports/exit 2 do not pass this test.
"""
import os
from pathlib import Path
import subprocess
import sys


def main():
    root=Path(__file__).resolve().parent.parent
    env=dict(os.environ, GITHUB_ACTION_PATH=str(root), AZT_FAIL_ON='high',
             AZT_ACTION_VERSION='', AZT_JOB_SUMMARY='true')
    result=subprocess.run([sys.executable,'-I',str(root/'scripts/action_review.py')],
                          env=env,cwd=os.environ['RUNNER_TEMP'],capture_output=True,
                          text=True,timeout=480)
    # Only the helper's already-bounded, sanitized derivative is printed.
    assert len(result.stdout.encode())<64*1024 and len(result.stderr.encode())<4096
    print(result.stdout)
    assert result.returncode==1, 'expected validated candidate HIGH findings, not setup/scan failure'
    assert 'Threshold: HIGH; met/exceeded; scanner exit 1.' in result.stdout
    assert '### Comparison' in result.stdout and 'Action exit: 1.' in result.stdout
    print('EXPLICIT PR SNAPSHOTS PASS: actual head threshold failure preserved and asserted; comparison and summary completed')


if __name__=='__main__':
    main()
