"""Installed investigator + actual Docker + a scripted test-owned HTTP service.

Not a live-model evaluation. Run only in the selected ephemeral Linux job. The
evaluator/expectations/service stay outside the worker's mounts and control.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time

import azt
import azt_docker
import azt_investigator as inv
import azt_research as research
import azt_research_broker as policy
import azt_research_runtime as runtime

# Fixed reviewed evaluator peer, never a source-selected module or plugin.
spec=importlib.util.spec_from_file_location('azt_test_service',Path(__file__).with_name('investigator_test_service.py'))
service=importlib.util.module_from_spec(spec);spec.loader.exec_module(service)


def demand(ok,message):
    if not ok:raise AssertionError(message)


def save(path,value):
    raw=json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True).encode()+b'\n'
    demand(len(raw)<=262144,'bounded test evidence');path.write_bytes(raw)


def sources(root):
    # Copied synthetic files only. Their exact bytes and expectations are fixed
    # in this trusted checkout before the candidate is evaluated.
    original=Path(__file__).resolve().parents[1]/'examples/protected-research/investigator'
    target=root/'captures';target.mkdir()
    for name in ('guide.md','support.md','peer.json'):(target/name).write_bytes((original/'captures'/name).read_bytes())
    (root/'sources.json').write_bytes((original/'sources.json').read_bytes())
    return original


def child(args):
    with service.Service('stall',args.child/'ready') as server:
        save(args.child/'inference.json',server.config())
        capture=research.inspect_sources(args.child/'sources.json',{'captures':args.child/'captures'})
        return inv.run(capture,args.child/'run',args.image,args.endpoint,args.child/'inference.json')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',required=True)
    p.add_argument('--endpoint',default='unix:///var/run/docker.sock');p.add_argument('--output',type=Path);p.add_argument('--child',type=Path)
    args=p.parse_args()
    demand(platform.system()=='Linux','actual native Linux required; no host fallback')
    if args.child:return child(args)
    root=args.output.resolve();demand(not root.exists(),'new output required');root.mkdir(mode=0o700)
    docker=azt_docker.Docker(args.endpoint,root)
    backend=docker.preflight(args.image)
    demand(backend['status']=='available' and backend['image_id']==args.image,'verified immutable backend required')
    records=[];owned=[];partial=None
    def absent(cid):
        _,raw,_=docker.command('ps','--all','--no-trunc','--filter','id='+cid,'--format','{{.ID}}')
        return cid not in raw.decode('ascii').splitlines()
    def case(name,fn):
        nonlocal partial
        partial=None;start=time.monotonic();record={'case':name,'outcome':'failed'}
        try:record['observed']=fn();record['outcome']='passed'
        except Exception as exc:
            record.update(error=str(exc) if isinstance(exc,AssertionError) else type(exc).__name__,partial=partial)
        record['seconds']=round(time.monotonic()-start,3);records.append(record);save(root/'partial.json',records)
        print(json.dumps({'case':name,'outcome':record['outcome']}),flush=True)
    def cli(mode):
        nonlocal partial
        directory=root/mode;directory.mkdir(mode=0o700);original=sources(directory)
        before={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (directory/'captures').iterdir()}
        with service.Service(mode) as server:
            save(directory/'inference.json',server.config())
            started=time.monotonic()
            call=subprocess.run([sys.executable,'-I','-m','azt','research','investigate',
                '--manifest',str(directory/'sources.json'),'--root','captures='+str(directory/'captures'),
                '--inference-config',str(directory/'inference.json'),'--image',args.image,'--endpoint',args.endpoint,
                '--output',str(directory/'run')],cwd=root,env=runtime.ENV,capture_output=True,timeout=140)
            record=json.loads((directory/'run/report.json').read_text())
            execution=record['execution'];model=record['investigator'];cid=execution.get('container_id')
            if cid:owned.append(cid)
            partial={'execution':execution,'model':model,'exit':call.returncode}
            demand(cid and absent(cid) and execution['cleanup']=='removed','external cleanup after launched planner')
            demand(len(call.stdout)+len(call.stderr)<4096,'bounded CLI output')
            demand(before=={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (directory/'captures').iterdir()},'original fixtures unchanged')
            demand('DO_NOT_PERSIST_TEST_REASONING' not in (directory/'run/report.json').read_text(),'no reasoning retention')
            if mode=='malformed':
                demand(call.returncode==2 and execution['status']=='failed' and not execution['stages']['review_completed'], 'invalid inference cannot complete review')
                return {'container_started':execution['stages']['container_started'],'inference_failed':True,'cleanup':True,'error_stage':execution['error_stage']}
            demand(call.returncode==0 and execution['status']=='passed' and all(execution['stages'].values()),'actual planner/CLI completion')
            expected=json.loads((original/'expected-v1.json').read_text());covered=[]
            descriptors={d['registration']:d for d in record['mission']['documents']}
            for item in expected['required_quote_coverage']:
                d=descriptors[item['registration']]
                found=any(r['source']==d['id'] and r['sha256']==d['sha256'] and r['line_start']==item['line'] and r['quote']==item['quote']
                    for h in model['hypotheses'] for r in h['evidence'])
                covered.append(found)
            demand(all(covered) and len(model['hypotheses'])==3,'externally fixed citation/quote rubric; not just tool completion')
            demand(model['denied_proposals']==expected['forbidden_proposals'],'all four deliberate invalid proposals rejected')
            demand(record['mission']['read_sources']==3 and record['mission']['checked_sources']==3,'all sources read and checked')
            demand(all((directory/'run'/n).is_file() for n in ('inspection.json','report.json','summary.txt','review.html','source-review.html','pending-case.json')),'durable review outputs')
            return {'execution_stages':execution['stages'],'cleanup':True,'fixture_integrity':True,
                'citation_quotes_covered':sum(covered),'required_quote_count':len(covered),'denied_proposals':model['denied_proposals'],
                'unnecessary_denials':0,'turns':model['turns'],'model':'test-owned scripted HTTP responses; no model',
                'interpretation_truth':'not evaluated by literal citation rubric', 'wall_seconds':round(time.monotonic()-started,3),
                'runtime_worker_sha256':execution['worker_sha256'],'inference_settings':model['settings']}
    def stop(sig):
        nonlocal partial
        directory=root/('stop-'+str(int(sig)));directory.mkdir(mode=0o700);sources(directory)
        proc=subprocess.Popen([sys.executable,'-I',str(Path(__file__).resolve()),'--child',str(directory),
                              '--image',args.image,'--endpoint',args.endpoint],cwd=root,env=runtime.ENV,
                             stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            start=time.monotonic();cid=None;pids=[]
            while time.monotonic()-start<15:
                session=directory/'run/runtime-control/session.json'
                if (directory/'ready').exists() and session.exists():
                    cid=json.loads(session.read_text())['container_id'];owned.append(cid)
                    _,raw,_=docker.command('top',cid,'-eo','pid')
                    pids=[int(x) for x in raw.decode().splitlines()[1:] if x.strip().isdigit()]
                    if len(pids)>=2:break
                time.sleep(.05)
            demand(cid and len(pids)>=2,'inference actually requested by running isolated planner')
            partial={'inference_observed':True,'processes_observed':len(pids),'signal':int(sig)}
            start=time.monotonic();proc.send_signal(sig)
            if sig==signal.SIGSTOP:
                time.sleep(.05);demand(Path('/proc/%d/stat'%proc.pid).read_text().split()[2]=='T','controller actually paused')
            else:proc.wait(timeout=3);demand(proc.returncode==-int(sig),'controller killed as selected')
            bound=128 if sig==signal.SIGSTOP else 8
            while time.monotonic()-start<bound and not absent(cid):time.sleep(.05)
            demand(absent(cid),'owned planner removed within original bound')
            for pid in pids:
                path=Path('/proc/%d/stat'%pid)
                demand(not path.exists() or path.read_text().split()[2]=='Z','externally observed process stopped')
            lease_path=directory/'run/runtime-control/lease-result.json';lease=None
            while time.monotonic()-start<bound:
                try:lease=runtime.decode_frame(lease_path.read_bytes());break
                except (FileNotFoundError,ValueError):time.sleep(.02)
            demand(lease and lease['cleanup']=='removed' and lease['container_id']==cid and
                   lease['reason']==('lease_expired' if sig==signal.SIGSTOP else 'controller_channel_closed'),'independent supervisor evidence')
            return {'inference_observed':True,'processes_observed':len(pids),'processes_still_running':0,'container_absent':True,
                'seconds_to_stop':round(time.monotonic()-start,3),'lease_reason':lease['reason'],'cleanup':True,
                'inference_server_cancellation_verified':False}
        finally:
            if proc.poll() is None:proc.kill();proc.wait(timeout=3)
    cleanup=True
    try:
        case('B-utility-scripted-service',lambda:cli('review'))
        case('B-invalid-inference',lambda:cli('malformed'))
        case('B-controller-death-during-inference',lambda:stop(signal.SIGKILL))
        case('B-long-profile-expiry',lambda:stop(signal.SIGSTOP))
    finally:
        for cid in set(owned):
            try:
                docker.command('rm','--force',cid,allow_error=True)
                cleanup=absent(cid) and cleanup
            except Exception:cleanup=False
        result={'schema':'azt.investigator-evaluation.v1','source_sha':os.environ.get('GITHUB_SHA'),
                'run_id':os.environ.get('GITHUB_RUN_ID'),'version':azt.__version__,'python':platform.python_version(),
                'backend':backend,'cases':records,'cleanup':cleanup,'live_model_trials':0,
                'evidence_level':'actual isolated planner and HTTP transport; scripted inference, not live-model utility',
                'outcomes':{k:sum(r['outcome']==k for r in records) for k in ('passed','failed')}}
        result['outcomes']['not_run']=4-len(records)
        result['status']='passed' if cleanup and len(records)==4 and all(r['outcome']=='passed' for r in records) else 'failed'
        result['modules']={name:hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest() for name,module in
                           [('adapter',inv),('capture',research),('broker',policy),('runtime',runtime)]}
        result['evaluator_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        save(root/'evaluation.json',result)
    return 0 if result['status']=='passed' else 2


if __name__=='__main__':raise SystemExit(main())
