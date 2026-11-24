#!/usr/bin/env python3
"""Distributed synthetic lab; no real GitHub or agent calls."""
import argparse,json,subprocess,sys,tempfile,time,socket
from pathlib import Path
from intent_merge.control_plane import CONTROL_NAMES,CASES,PROFILE,init,serve,read_key,collect,replay,LabRevocations,render,require,lab_http
from intent_merge.core import digest

def study(out,keys,urls):
    out.mkdir(parents=True,exist_ok=False);trust=json.loads((keys/'trust.json').read_text());key=read_key(keys/'aggregate/key.pem');rows=[]
    for c in CONTROL_NAMES:
        health=lab_http(c,urls[c],'/health',timeout=3)
        require(health=={'control':c,'profile':PROFILE,'key':trust[c]},'service identity mismatch')
    (out/'trust.json').write_text(json.dumps(trust,indent=2));print('trust_digest',digest(trust),flush=True)
    for case,expected in CASES.items():
        r=collect(case,urls,trust,key);replay(r,trust,now=r['statement']['evaluated_at']);rows.append(r)
        print(case,r['statement']['decision'],flush=True)
        with (out/'runs.jsonl').open('a') as f:f.write(json.dumps(r)+'\n')
    a=collect('happy',urls,trust,key);b=collect('happy',urls,trust,key);now=int(time.time());j=LabRevocations(out/'lifecycle.sqlite');i=j.register(a,trust,now);k=j.register(b,trust,now);before=j.state(i);after=j.revoke(i,'synthetic_review_withdrawn');j.register(a,trust,now);no_restore=j.state(i);j.close();j=LabRevocations(out/'lifecycle.sqlite');j.sweep(b['statement']['expires_at']);expiry=j.state(k);restart=j.state(i);j.close()
    life={'before':before,'after':after,'no_restore':no_restore,'expired':expiry,'after_restart':restart,'reports':[a,b]}
    passed=sum(r['statement']['decision']==CASES[r['statement']['case']] for r in rows);ok=passed==len(CASES) and before['state']=='CURRENT' and all(x['state']=='REVOKED' for x in (after,no_restore,expiry,restart));report={'profile':PROFILE,'status':'PASS' if ok else 'FAIL','production_ready':False,'merge_authority':False,'expected_matches':passed,'total':len(CASES),'runs':rows,'lifecycle':life,'limitations':['Built-in AUTH-201 fixture only','Synthetic approval and autonomy','Private lab HTTP only, no TLS/authentication','Availability fault simulated by skipping a request; delayed response is real timeout','Same-host processes are not organizational independence or hostile isolation','Local revocation journal only']};(out/'report.json').write_text(json.dumps(report,indent=2));(out/'report.html').write_text(render(report));print(json.dumps({k:report[k] for k in ('status','expected_matches','total','merge_authority')},indent=2));return ok

def demo(out):
    with tempfile.TemporaryDirectory(prefix='itm-control-lab-') as tmp:
        keys=Path(tmp)/'keys';init(keys);procs=[];urls={}
        try:
            for c in CONTROL_NAMES:
                with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
                urls[c]=f'http://127.0.0.1:{port}';procs.append(subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'serve','--control',c,'--key',str(keys/c/'key.pem'),'--port',str(port)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
            deadline=time.monotonic()+10
            for c in CONTROL_NAMES:
                while True:
                    try:
                        lab_http(c,urls[c],'/health',timeout=.5)
                        break
                    except OSError:
                        if time.monotonic()>=deadline:raise RuntimeError('service startup failed')
                        time.sleep(.05)
            return study(out,keys,urls)
        finally:
            for p in procs:p.terminate()
            for p in procs:
                try:p.wait(timeout=3)
                except subprocess.TimeoutExpired:p.kill();p.wait()

def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='cmd',required=True)
    a=sub.add_parser('init');a.add_argument('--keys',type=Path,required=True)
    a=sub.add_parser('serve');a.add_argument('--control',choices=CONTROL_NAMES,required=True);a.add_argument('--key',type=Path,required=True);a.add_argument('--host',default='127.0.0.1');a.add_argument('--port',type=int,default=8080)
    a=sub.add_parser('demo');a.add_argument('--out',type=Path,required=True)
    a=sub.add_parser('run');a.add_argument('--keys',type=Path,required=True);a.add_argument('--out',type=Path,required=True)
    a=sub.add_parser('verify');a.add_argument('--report',type=Path,required=True);a.add_argument('--trust',type=Path,required=True);a.add_argument('--expected-trust-digest',required=True)
    args=p.parse_args()
    if args.cmd=='init':print(json.dumps({'trust_digest':digest(init(args.keys))},indent=2))
    elif args.cmd=='serve':serve(args.control,args.key,args.host,args.port)
    elif args.cmd=='demo':return 0 if demo(args.out) else 2
    elif args.cmd=='run':return 0 if study(args.out,args.keys,{c:'http://'+c.replace('_','-')+':8080' for c in CONTROL_NAMES}) else 2
    else:
        trust=json.loads(args.trust.read_text());require(digest(trust)==args.expected_trust_digest,'untrusted key inventory');report=json.loads(args.report.read_text());rows=report['runs'];require(len(rows)==len(CASES) and {r['statement']['case'] for r in rows}==set(CASES),'incomplete inventory');results=[replay(r,trust) for r in rows];require(all(r['statement']['decision']==CASES[r['statement']['case']] for r in rows),'unexpected historical result');print(json.dumps({'verified':len(results),'current_allows':sum(r['current_decision']=='ALLOW' for r in results),'merge_authority':False},indent=2))
    return 0
if __name__=='__main__':raise SystemExit(main())
