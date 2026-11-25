"""Live GitHub preflight. Separate from synthetic evidence and merge authority."""
from __future__ import annotations
import json, os, re, tomllib
from .path_policy import matches, validate_patterns, SEGMENT_V2
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from .core import digest

SHA = re.compile(r'[0-9a-f]{40}')
REPO = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+')
CHECK_NAME = 'ITM / PR preflight'

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

class GitHub:
    def __init__(self, token=None):
        self.token = token or os.environ.get('ITM_GITHUB_TOKEN')
        if not self.token: raise ValueError('ITM_GITHUB_TOKEN is required')
        self.opener = build_opener(NoRedirect())
    def request(self, path, payload=None, *, method=None):
        if not path.startswith('/repos/'): raise ValueError('invalid API route')
        req = Request('https://api.github.com'+path, method=method, data=None if payload is None else json.dumps(payload).encode(), headers={'Authorization':'Bearer '+self.token,'Accept':'application/vnd.github+json','Content-Type':'application/json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'intent-to-merge/0.5'})
        try:
            with self.opener.open(req, timeout=30) as response:
                raw=response.read(16*1024*1024+1)
                if len(raw)>16*1024*1024: raise ValueError('API response too large')
                return json.loads(raw)
        except HTTPError as e: raise ValueError(f'GitHub HTTP {e.code}') from None
        except URLError: raise ValueError('GitHub transport failure') from None
    def pages(self,path,key=None):
        for page in range(1,31):
            data=self.request(path+('&' if '?' in path else '?')+f'per_page=100&page={page}')
            rows=data[key] if key else data
            if not isinstance(rows,list): raise ValueError('invalid GitHub collection')
            yield from rows
            if len(rows)<100: return
        raise ValueError('pagination limit reached; refusing incomplete evidence')

def policy_from(path):
    p=tomllib.loads(path.read_text())
    if 'path_semantics' not in p:
        p['path_semantics'] = SEGMENT_V2
    return validate_policy(p)

def validate_policy(p):
    if not isinstance(p,dict) or type(p.get('version')) is not int or p.get('version')!=1: raise ValueError('unsupported PR policy')
    for k in ('repository','base_ref','allowed_paths','protected_paths','required_checks','required_roles'):
        if k not in p: raise ValueError('missing policy field: '+k)
    if set(p) != {'version','path_semantics','repository','base_ref','allowed_paths','protected_paths','required_checks','required_roles'} or p.get('path_semantics') != SEGMENT_V2: raise ValueError('invalid policy fields or path semantics')
    if not isinstance(p['repository'],str) or not REPO.fullmatch(p['repository']): raise ValueError('invalid repository')
    if not isinstance(p['base_ref'],str) or not p['base_ref']: raise ValueError('invalid base ref')
    for k in ('allowed_paths','protected_paths'):
        validate_patterns(p[k], nonempty=k=='allowed_paths')
    if not p['allowed_paths']: raise ValueError('empty allowlist')
    if not isinstance(p['required_checks'],list) or not p['required_checks']: raise ValueError('required checks must be nonempty')
    names=set()
    for check in p['required_checks']:
        if not isinstance(check,dict) or set(check)!={'name','app_id'}: raise ValueError('invalid required check fields')
        if not isinstance(check['name'],str) or not check['name'] or check['name']==CHECK_NAME or type(check['app_id']) is not int or check['app_id']<=0: raise ValueError('invalid required check')
        if check['name'] in names: raise ValueError('duplicate check name')
        names.add(check['name'])
    roles=p['required_roles']
    if not isinstance(roles,dict) or not roles: raise ValueError('required roles must be nonempty')
    ids=set()
    for role, members in roles.items():
        if not isinstance(role,str) or not role.strip() or not isinstance(members,list) or not members or any(type(m) is not int or m<=0 for m in members) or ids.intersection(members): raise ValueError('invalid or overlapping approver IDs')
        ids.update(members)
    return p

def identity(pr):
    return (pr['head']['sha'],pr['base']['sha'],pr['base']['ref'],pr['state'],pr['draft'],pr['head']['repo']['full_name'],pr['base']['repo']['full_name'],pr['changed_files'],pr['user']['id'])

def preflight(client, repo, number, policy, *, publish=False):
    validate_policy(policy)
    if not REPO.fullmatch(repo) or type(number) is not int or number<=0 or policy['repository'].lower()!=repo.lower(): raise ValueError('repository/PR does not match policy')
    prefix='/repos/'+repo; route=prefix+f'/pulls/{number}'
    pr=client.request(route); before=identity(pr); head,base,ref,state,draft,head_repo,base_repo,count,author=before
    if not SHA.fullmatch(head) or not SHA.fullmatch(base): raise ValueError('invalid Git SHA')
    if base_repo.lower()!=repo.lower(): raise ValueError('base repository mismatch')
    if head_repo.lower()!=repo.lower(): raise ValueError('fork PRs unsupported in v0.5')
    if count<=0 or count>=3000: raise ValueError('unsupported file count')
    files=list(client.pages(route+'/files'))
    if len(files)!=count or any(not isinstance(f.get('filename'),str) or not f['filename'] for f in files) or len({f['filename'] for f in files})!=count: raise ValueError('incomplete file inventory')
    paths=sorted({p for f in files for p in [f['filename'],f.get('previous_filename')] if p})
    if any(f['status']=='renamed' and not f.get('previous_filename') for f in files): raise ValueError('rename missing source path')
    reviews=list(client.pages(route+'/reviews'))
    checks=list(client.pages(prefix+f'/commits/{head}/check-runs?filter=all','check_runs'))
    reasons=[]; gates=[]
    def gate(name, passed):
        gates.append({'name':name,'passed':bool(passed)})
        if not passed: reasons.append(name)
    gate('open_non_draft_target',state=='open' and not draft and ref==policy['base_ref'])
    for path in paths:
        gate('scope:'+path,matches(path,policy['allowed_paths']) and not matches(path,policy['protected_paths']))
    for rule in policy['required_checks']:
        matching=[c for c in checks if c['name']==rule['name'] and (c.get('app') or {}).get('id')==rule['app_id'] and c.get('head_sha')==head]
        latest=max(matching,key=lambda c:c['id'],default={})
        gate('check:'+rule['name'],latest.get('status')=='completed' and latest.get('conclusion')=='success')
    latest_reviews={}
    for r in sorted(reviews,key=lambda x:x['id']):
        uid=r['user']['id']; status=r['state']
        if status in ('APPROVED','CHANGES_REQUESTED','DISMISSED'): latest_reviews[uid]=r
    approved={uid for uid,r in latest_reviews.items() if uid!=author and r['state']=='APPROVED' and r.get('commit_id')==head and r['user'].get('type')=='User'}
    for role, members in policy['required_roles'].items(): gate('approval:'+role,bool(approved.intersection(members)))
    if identity(client.request(route))!=before: raise ValueError('PR changed during collection; retry')
    report={'schema_version':'1.0','profile':'github-live-preflight','repository':repo,'pr':number,'head':head,'base':base,'base_ref':ref,'policy_digest':digest(policy),'paths':paths,'gates':gates,'reasons':reasons,'decision':'PASS' if not reasons else 'BLOCK','full_itm_authorization':False,'note':'PR preflight only; no verification of agent observations or full evidence bundle. GitHub enforces merge rules.'}
    if publish:
        if identity(client.request(route))!=before: raise ValueError('PR changed before publication')
        payload={'name':CHECK_NAME,'head_sha':head,'status':'completed','conclusion':'failure' if reasons else 'success','external_id':digest(report),'output':{'title':'ITM preflight '+report['decision'],'summary':f'{sum(g["passed"] for g in gates)}/{len(gates)} gates passed. Base {base}. This is not full ITM merge authorization.'}}
        result=client.request(prefix+'/check-runs',payload); report['published_check_id']=result['id']
    return report
