"""Measure six frozen inert requests through an installed component and CLI.

No fixture instruction executes. Run from reviewed source, with an installed
interpreter: --python /external/venv/bin/python --output /new/external/result.json.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
PACK = ROOT / 'examples/sensitive-request/associations-v1.json'
RULE = 'request.sensitive_disclosure'
COMPONENT = '''import hashlib,json,sys
from pathlib import Path
import azt,azt_sensitive,azt_review
assert Path(sys.prefix).resolve() in Path(azt.__file__).resolve().parents
rows=[]
for case in json.load(sys.stdin):
 text=case['text']; findings,errors=azt_sensitive.analyze({'README.md':{'text':text,'sha256':hashlib.sha256(text.encode()).hexdigest()}},{})
 rows.append({'id':case['id'],'classes':sorted({c for f in findings for c in f['sensitive_request']['information_classes']}),'findings':len(findings),'errors':errors})
print(json.dumps({'version':azt.__version__,'engine':azt_review.engine_identity(azt),'python':sys.version.split()[0],'cases':rows}))
'''


def evaluate(python, output):
    raw = PACK.read_bytes()
    pack = json.loads(raw)
    assert pack['schema'] == 'azt.sensitive-associations.v1'
    output = output.absolute()
    if output.exists() or output.is_symlink() or output.parent.resolve() != output.parent:
        raise ValueError('use a new output file in an existing canonical external directory')
    if ROOT == output.parent or ROOT in output.parents:
        raise ValueError('keep generated evidence outside the source checkout')
    env = {'PATH': os.defpath, 'PYTHONNOUSERSITE': '1', 'PIP_CONFIG_FILE': os.devnull}
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='azt associations ') as temporary:
        work = Path(temporary).resolve()
        def invoke(args, data=None):
            result = subprocess.run([str(python), '-I']+args, cwd=work, env=env,
                                    input=data, capture_output=True, text=True, timeout=30)
            if len(result.stdout)>8*1024*1024 or len(result.stderr)>65536:
                raise ValueError('reviewed measurement output limit exceeded')
            return result.returncode, json.loads(result.stdout)
        code, component = invoke(['-c', COMPONENT], json.dumps(pack['cases']))
        assert code == 0
        rows = []
        for case, observed in zip(pack['cases'], component['cases']):
            target = work / (case['id']+' project')
            target.mkdir()
            (target/'README.md').write_text(case['text'], encoding='utf-8')
            scans = []
            for threshold in ('high','medium'):
                code, report = invoke(['-m','azt','scan','--json','--fail-on',threshold,'--',str(target)])
                matches = [f for f in report['findings'] if f['rule']==RULE]
                classes = sorted({c for f in matches for c in f['sensitive_request']['information_classes']})
                scans.append({'threshold':threshold,'exit':code,'complete':report['scope']['complete'],
                              'exit_matches_decision':code=={'pass':0,'deny':1,'incomplete':2}[report['decision']],
                              'classes':classes,'sensitive_findings':len(matches),
                              'all_rules':[f['rule'] for f in report['findings']], 'input_digest':report['input_digest']})
            passed = observed['classes']==case['classes'] and not observed['errors'] and all(s['classes']==case['classes'] and s['complete'] and s['exit_matches_decision'] for s in scans)
            rows.append({'id':case['id'],'expected_classes':case['classes'],'component':observed,'scans':scans,'passed':passed})
    result = {'schema':'azt.association-evaluation.v1','pack_sha256':hashlib.sha256(raw).hexdigest(),
              'runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'version':component['version'],'engine':component['engine'],'python':component['python'],
              'platform':platform.system()+' '+platform.release(),'seconds':round(time.monotonic()-started,6),
              'peak_child_rss_bytes':resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss*(1 if platform.system()=='Darwin' else 1024),
              'cases':rows,'counts':{'total':len(rows),'passed':sum(r['passed'] for r in rows),'failed':sum(not r['passed'] for r in rows)},
              'limitations':['selected known regression inputs, not held-out','component and installed CLI; no target execution or network','single timing includes process startup; RSS is child high-water']}
    with output.open('x',encoding='utf-8') as stream:
        json.dump(result,stream,indent=2,sort_keys=True); stream.write('\n')
    print(json.dumps(result,indent=2))
    return int(result['counts']['failed']>0)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--python',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    return evaluate(args.python,args.output)


if __name__=='__main__':
    raise SystemExit(main())
