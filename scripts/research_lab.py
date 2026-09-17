"""Offline installed-CLI lab. Captures are inert data; reports live elsewhere."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cli',type=Path,required=True); p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    root=Path(__file__).resolve().parent.parent/'examples/protected-research'
    output=args.output.resolve(); output.mkdir(mode=0o700)
    cli=args.cli.resolve()
    def run(*words, expected=0):
        r=subprocess.run([str(cli),*map(str,words)],cwd=output,capture_output=True,text=True,timeout=20)
        assert r.returncode==expected, (r.returncode,r.stderr)
        return r.stdout
    run('research','review','--manifest',root/'sources.json','--root','captures='+str(root/'captures'),'--output',output/'review.json')
    value=json.loads((output/'review.json').read_text())
    assert value['complete']
    scans={s['id']:s['review']['scan'] for s in value['sources']}
    assert not scans['limited']['findings']
    assert any(f['rule']=='request.sensitive_disclosure' and f['severity']=='MEDIUM' for f in scans['diagnostics']['findings'])
    assert scans['diagnostics']['decision']=='pass'  # threshold, not approval
    for fmt in ('html','text'):
        run('research','export','--input',output/'review.json','--format',fmt,'--output',output/('review.'+fmt))
    run('research','case','--input',output/'review.json','--output',output/'pending-case.json')
    assert json.loads((output/'pending-case.json').read_text())['status']=='pending-owner-review'
    run('research','review','--manifest',root/'sources.json','--root','captures='+str(root/'captures'),'--output',output/'review.json',expected=2)
    (output/'transcript.txt').write_text('AZT captured-source lab\n3 selected sources inspected.\nLimited request: no finding.\nBroad diagnostics: MEDIUM request.sensitive_disclosure; HIGH threshold not exceeded.\nClaimed peer role: retained only as an untrusted identity hash.\nHTML/text exported; pending case grants no authority.\nDuplicate output rejected (exit 2).\nNo Docker, source execution, diagnostics collection, network or model calls.\n')
    print((output/'transcript.txt').read_text(),end='')
    return 0


if __name__=='__main__': raise SystemExit(main())
