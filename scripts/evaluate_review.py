"""Measure the frozen saved-report regression pack, using an installed Python.

Not a detection-accuracy estimate or runtime benchmark. No fixture execution.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess
import time


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--python',required=True,help='Python in an environment containing the installed candidate')
    parser.add_argument('--output',required=True,type=Path,help='new result file')
    args=parser.parse_args()
    root=Path(__file__).resolve().parent.parent
    frozen=(root/'examples/change-review/evaluation-cases.json').read_bytes()
    cases=json.loads(frozen)['cases']
    start=time.monotonic()
    command=[args.python,'-I','-m','unittest','discover','-s',str(root/'tests'),'-p','test_review.py','-v']
    result=subprocess.run(command,capture_output=True,text=True,timeout=90,cwd=args.output.absolute().parent)
    assert len(result.stdout)+len(result.stderr)<512*1024, 'bounded test output exceeded'
    observed=dict(re.findall(r'^(test_\w+) \([^\n]+\) \.\.\. (ok|FAIL|ERROR|skipped[^\n]*)$',result.stderr,re.M))
    assert set(observed)==set(cases), 'frozen case list and measured suite differ'
    record={'schema':'azt.review-evaluation.v1','cases_sha256':hashlib.sha256(frozen).hexdigest(),
            'test_source_sha256':hashlib.sha256((root/'tests/test_review.py').read_bytes()).hexdigest(),
            'cases':[{ 'name':name,'category':cases[name],'outcome':observed[name]} for name in sorted(cases)],
            'total':len(cases),'passed':sum(v=='ok' for v in observed.values()),
            'failed':sum(v in ('FAIL','ERROR') for v in observed.values()),
            'skipped':sum(v.startswith('skipped') for v in observed.values()),
            'benign_context_cases':sum(v=='benign/context' for v in cases.values()),
            'seconds':round(time.monotonic()-start,3),'platform':platform.system()+' '+platform.release(),
            'runtime_trials':0,'scope':'Assertion-based synthetic comparison/report regressions, not real-world detection accuracy. See lab for benign finding counts.'}
    identity=subprocess.check_output([args.python,'-I','-c','import azt,platform; print(azt.__version__+"; Python "+platform.python_version())'],text=True,timeout=10)
    record['installed_version']=identity.strip()
    with args.output.open('x',encoding='utf-8') as stream:json.dump(record,stream,indent=2,sort_keys=True);stream.write('\n')
    print(json.dumps(record,indent=2,sort_keys=True))
    return 0 if result.returncode==0 and record['failed']==0 else 1


if __name__=='__main__':raise SystemExit(main())
