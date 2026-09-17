"""Export only selected bounded synthetic evaluation and exact artifact identities."""
import argparse
import hashlib
import json
from pathlib import Path


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evidence',type=Path,required=True); p.add_argument('--dist',type=Path,required=True)
    a=p.parse_args()
    value={'schema':'azt.research-ci.v1','evaluation':None,'artifacts':[], 'status':'missing-evaluation'}
    if a.evidence.is_file():
        raw=a.evidence.read_bytes()
        if len(raw)>262144: raise SystemExit('bounded evidence limit')
        value['evaluation']=json.loads(raw); value['status']=value['evaluation']['status']
    for path in sorted(a.dist.glob('agent_zero_trust-*')):
        if path.is_file() and path.suffix in ('.whl','.gz'):
            value['artifacts'].append({'filename':path.name,'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'bytes':path.stat().st_size})
    text=json.dumps(value,sort_keys=True,ensure_ascii=True)
    if len(text)>300000: raise SystemExit('bounded export limit')
    print('AZT_RESEARCH_EVIDENCE_BEGIN\n'+text+'\nAZT_RESEARCH_EVIDENCE_END')
    return 0 if value['status']=='passed' else 2


if __name__=='__main__': raise SystemExit(main())
