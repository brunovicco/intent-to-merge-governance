"""Operational CLI entrypoints; webhook ingress and privileged worker are separate."""
import argparse,json,os,sys,uuid
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from cryptography.hazmat.primitives import serialization
from .github import policy_from,REPO
from .operational import Journal,delivery,installation_client,work_once,reconcile,MAX_BODY
from .capture import run_agent,hook
from .core import digest, load_user_config
from .hardening import strict_gate, sweep, DurableChangeSet, verify_payment_candidate
from functools import partial
from .policy_schema import InvalidConfiguration
from .cli_errors import emit_failure, telemetry_provider

def serve(db,repo,installation,secret,port):
    if len(secret)<32 or not REPO.fullmatch(repo) or installation<=0:raise ValueError('invalid ingress configuration')
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def do_POST(self):
            try:
                if self.path!='/webhook':self.send_error(404);return
                if self.headers.get('Transfer-Encoding'):raise ValueError('unsupported transfer encoding')
                n=int(self.headers.get('Content-Length','-1'))
                if not 0<=n<=MAX_BODY:raise ValueError('invalid body size')
                raw=self.rfile.read(n)
                if len(raw)!=n:raise ValueError('incomplete body')
                j=delivery(raw,self.headers.get('X-Hub-Signature-256'),self.headers.get('X-GitHub-Event'),self.headers.get('X-GitHub-Delivery'),secret,repo,installation)
                if j:
                    store=Journal(db)
                    try:store.enqueue(j)
                    finally:store.close()
                self.send_response(202);self.end_headers()
            except (ValueError,KeyError,TypeError):self.send_error(400,'invalid delivery')
            except Exception:self.send_error(503,'unable to queue delivery')
        def setup(self):
            self.request.settimeout(10);super().setup()
    ThreadingHTTPServer(('127.0.0.1',port),Handler).serve_forever()

def main():
    p=argparse.ArgumentParser(description='ITM operational integration'); s=p.add_subparsers(dest='cmd',required=True)
    w=s.add_parser('serve'); w.add_argument('--db',type=Path,required=True);w.add_argument('--repo',required=True);w.add_argument('--installation',type=int,required=True);w.add_argument('--port',type=int,default=8765)
    for name in ('worker','reconcile','sweep'):
        a=s.add_parser(name);a.add_argument('--db',type=Path,required=True);a.add_argument('--policy',type=Path,required=True);a.add_argument('--app-id',type=int,required=True);a.add_argument('--installation',type=int,required=True);a.add_argument('--app-key',type=Path,required=True)
        if name in ('worker','sweep'):
            a.add_argument('--receipts',type=Path,required=True);a.add_argument('--control-trust',type=Path,required=True)
            a.add_argument('--assertions',type=Path,required=True);a.add_argument('--verifier-key',type=Path,required=True);a.add_argument('--publish',action='store_true');a.add_argument('--trace-console',action='store_true')
        else:a.add_argument('--delivery',required=True)
    a=s.add_parser('journal');a.add_argument('--db',type=Path,required=True)
    a=s.add_parser('refresh');a.add_argument('--db',type=Path,required=True);a.add_argument('--repo',required=True);a.add_argument('--pr',type=int,required=True)
    a=s.add_parser('agent-run');a.add_argument('--provider',choices=['claude','codex'],required=True);a.add_argument('--repo',type=Path,required=True);a.add_argument('--prompt-file',type=Path,required=True);a.add_argument('--output',type=Path,required=True);a.add_argument('--timeout',type=int,default=300)
    a=s.add_parser('hook');a.add_argument('--provider',choices=['claude','codex'],required=True);a.add_argument('--repo',type=Path,required=True);a.add_argument('--output',type=Path,required=True)
    a=s.add_parser('verify-candidate');a.add_argument('--repo',type=Path,required=True);a.add_argument('--base',required=True);a.add_argument('--head',required=True);a.add_argument('--spec',type=Path,required=True);a.add_argument('--backend',choices=['docker','local'],default='docker');a.add_argument('--trusted-fixture',action='store_true');a.add_argument('--image',default='python:3.11-slim')
    a=s.add_parser('changeset-recover');a.add_argument('--db',type=Path,required=True);a.add_argument('--config',type=Path,required=True);a.add_argument('--plan',type=Path,required=True);a.add_argument('--approvals',type=Path,required=True);a.add_argument('--repos',type=Path,required=True);a.add_argument('--executor-key',type=Path,required=True);a.add_argument('--compensate',action='store_true')
    args=p.parse_args()
    try:
        if args.cmd=='serve':return serve(args.db,args.repo,args.installation,os.environ['ITM_WEBHOOK_SECRET'].encode(),args.port)
        if args.cmd=='verify-candidate':result=verify_payment_candidate(args.repo,args.base,args.head,load_user_config(args.spec),backend=args.backend,trusted_fixture=args.trusted_fixture,image=args.image)
        elif args.cmd=='changeset-recover':
            d=DurableChangeSet(args.db)
            try:result=d.run(json.loads(args.config.read_text()),json.loads(args.plan.read_text()),json.loads(args.approvals.read_text()),json.loads(args.repos.read_text()),serialization.load_pem_private_key(args.executor_key.read_bytes(),password=None),compensate=args.compensate)
            finally:d.close()
        elif args.cmd=='agent-run':result=run_agent(args.provider,args.repo,args.prompt_file,args.output,args.timeout)
        elif args.cmd=='hook':
            if args.output.resolve().is_relative_to(args.repo.resolve()):raise ValueError('hook output must be outside workspace')
            raw=sys.stdin.buffer.read(65537)
            if len(raw)>65536:raise ValueError('hook input too large')
            result=hook(args.provider,json.loads(raw),args.repo)
            with args.output.open('x') as f:json.dump(result,f,indent=2)
            return # no hook stdout, do not inject agent context
        else:
            j=Journal(args.db)
            try:
                if args.cmd=='journal':result=j.list()
                elif args.cmd=='refresh':
                    if not REPO.fullmatch(args.repo) or args.pr<=0:raise ValueError('invalid repository/PR')
                    job={'id':'manual-'+uuid.uuid4().hex,'repo':args.repo,'pr':args.pr};job['body_sha256']=digest(job);result={'delivery':job['id'],'state':j.enqueue(job)}
                else:
                    policy=policy_from(args.policy);client=installation_client(args.app_id,args.installation,args.app_key,policy['repository'])
                    if args.cmd=='reconcile':result=reconcile(j,client,args.delivery,args.app_id)
                    elif args.cmd=='sweep':
                        result=sweep(j,client,policy,args.assertions,serialization.load_pem_public_key(args.verifier_key.read_bytes()),args.receipts,json.loads(args.control_trust.read_text()),args.app_id,apply=args.publish)
                    else:
                        provider=None;tracer=None
                        if args.trace_console:
                            provider = telemetry_provider(sys.stderr)
                            tracer = provider.get_tracer('intent-merge.operational')
                        try:result=work_once(j,client,policy,args.assertions,serialization.load_pem_public_key(args.verifier_key.read_bytes()),app_id=args.app_id,tracer=tracer,publish=args.publish,gate_fn=partial(strict_gate,receipt_dir=args.receipts,control_trust=json.loads(args.control_trust.read_text())))
                        finally:
                            if provider:provider.shutdown()
            finally:j.close()
        print(json.dumps(result,indent=2))
        if args.cmd=='sweep' and any(r['status'] in ('REMOTE_STATE_UNKNOWN','REVOCATION_UNCERTAIN') for r in result):p.exit(2)
        if args.cmd=='verify-candidate' and not result['passed']:p.exit(2)
        if args.cmd=='changeset-recover' and result['status']=='MANUAL_INTERVENTION':p.exit(2)
    except Exception as exc:
        emit_failure(args.cmd, exc, remote_write_possible=getattr(args, 'publish', False))
        p.exit(2 if isinstance(exc, InvalidConfiguration) else 1)
if __name__=='__main__':main()
