"""Four frozen, inert change-review examples through an explicit installed CLI.

No target command is executed. Output must be a new directory outside fixtures.
This helper constructs synthetic files, scans them and captures actual output.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import time


def run_lab(cli, output):
    cli = Path(cli).resolve(strict=True)
    output = Path(output).absolute()
    output.mkdir(mode=0o700)  # create only; never overwrite a previous run
    fixture = Path(__file__).resolve().parent.parent / 'examples/change-review/fixtures.json'
    raw = fixture.read_bytes()
    spec = json.loads(raw)
    records, transcript = [], []
    start = time.monotonic()

    def invoke(args, expected=0):
        result = subprocess.run([str(cli), *map(str, args)], capture_output=True, text=True, timeout=30)
        assert len(result.stdout.encode()) < 8*1024*1024 and len(result.stderr) < 65536
        assert result.returncode == expected, (args, result.returncode, result.stderr)
        return result.stdout

    for name, files in spec['cases'].items():
        root = output / 'fixtures' / name
        root.mkdir(parents=True)
        for rel, text in files.items():
            assert rel in ('README.md', 'AGENTS.md', '.claude/settings.json')
            path = root / rel
            path.parent.mkdir(exist_ok=True)
            path.write_text(text, encoding='utf-8')
        code = 1 if name == 'concerning' else 2 if name == 'incomplete' else 0
        scan = invoke(['scan', root, '--json'], code)
        (output / (name+'.json')).write_text(scan, encoding='utf-8')
    for name, expected in spec['expectations'].items():
        args = ['changes', '--before', output/(expected['before']+'.json'), '--after', output/(expected['after']+'.json')]
        report = json.loads(invoke(args+['--json']))
        assert report['meaningful_delta'] == expected['delta']
        assert report['comparability']['status'] == expected['comparability']
        assert len(report['findings']['new']) == expected['new']
        assert len(report['findings']['unresolved']) == expected['unresolved']
        assert not report['findings']['no_longer_observed']
        invoke(args+['--json', '--output', output/(name+'-changes.json')])
        text = invoke(args)
        transcript.append('CASE: '+name+'\n'+text)
        invoke(args+['--format', 'html', '--output', output/(name+'.html')])
        records.append({'case':name, 'status':'passed', 'meaningful_delta':report['meaningful_delta'],
                        'comparability':report['comparability']['status'],
                        'new':len(report['findings']['new']), 'unresolved':len(report['findings']['unresolved'])})
    transcript.append(invoke(['explain', 'net.pipe_shell']))
    invoke(['report', '--input', output/'concerning.json', '--format', 'html', '--output', output/'scan.html'])
    (output/'transcript.txt').write_text('\n'.join(transcript), encoding='utf-8')
    result = {'schema':'azt.change-review-lab-results.v1', 'version':invoke(['--version']).strip(),
              'platform':platform.system()+' '+platform.release(), 'fixture_sha256':hashlib.sha256(raw).hexdigest(),
              'cases':records, 'passed':len(records), 'planned':len(spec['expectations']), 'failed':0,
              'seconds':round(time.monotonic()-start,3),
              'limits':'Synthetic offline scan/review; no target execution, model or runtime-containment trial.'}
    (output/'results.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps(result,indent=2,sort_keys=True))
    return result


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli',required=True)
    parser.add_argument('--output',required=True)
    args=parser.parse_args()
    run_lab(args.cli,args.output)
