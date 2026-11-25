"""Live GitHub preflight. Separate from synthetic evidence and merge authority."""
from __future__ import annotations
import json, os, re
from .path_policy import matches, validate_patterns, SEGMENT_V2
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from .core import digest, load_user_config, unique_json_members
from .policy_schema import InvalidConfiguration

SHA = re.compile(r'[0-9a-f]{40}')
REPO = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+')
CHECK_NAME = 'ITM / PR preflight'
CHECK_STATUSES = {'queued', 'in_progress', 'completed', 'requested', 'waiting', 'pending'}
CHECK_CONCLUSIONS = {'action_required', 'cancelled', 'failure', 'neutral', 'skipped',
                     'stale', 'startup_failure', 'success', 'timed_out'}

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

def valid_token(token):
    # Treat tokens as opaque; do not hard-code an evolving GitHub prefix.
    return isinstance(token, str) and 0 < len(token) <= 16384 and all(
        33 <= ord(c) <= 126 for c in token
    )


def positive_id(value):
    return type(value) is int and value > 0


def check_observation(row):
    """Validate the identity and lifecycle fields returned by GitHub."""
    if not isinstance(row, dict):
        raise ValueError('invalid check observation')
    app, status, conclusion = row.get('app'), row.get('status'), row.get('conclusion')
    if (not positive_id(row.get('id')) or not isinstance(app, dict) or not positive_id(app.get('id'))
            or not isinstance(row.get('name'), str) or not row['name']
            or not isinstance(row.get('head_sha'), str) or not SHA.fullmatch(row['head_sha'])
            or not isinstance(status, str) or status not in CHECK_STATUSES
            or 'conclusion' not in row
            or (status == 'completed' and
                (not isinstance(conclusion, str) or conclusion not in CHECK_CONCLUSIONS))
            or (status != 'completed' and conclusion is not None)):
        raise ValueError('invalid check observation')
    return row['id']


def validate_check_response(response, expected, app_id, *, check_id=None, conclusions=None):
    """Validate an observation against trusted correlation and lifecycle expectations."""
    observed_id = check_observation(response)
    fields = ('name', 'head_sha', 'external_id', 'status')
    if conclusions is None:
        conclusions = (expected['conclusion'],)
    if (not positive_id(app_id) or response['app']['id'] != app_id
            or any(field not in response or response[field] != expected[field] for field in fields)
            or response['conclusion'] not in conclusions
            or (check_id is not None and (not positive_id(check_id) or observed_id != check_id))):
        raise ValueError('unexpected check response')
    return observed_id


class CheckPublicationUnconfirmed(ValueError):
    """A check creation POST may have taken effect."""
    def __init__(self, repo, app_id, payload, *, installation_id=None):
        super().__init__('check publication not confirmed')
        self.correlation = {'repository': repo, 'app_id': app_id,
                            **{k: payload[k] for k in ('name', 'head_sha', 'external_id', 'conclusion')}}
        if installation_id is not None:
            self.correlation['installation_id'] = installation_id


class GitHub:
    def __init__(self, token=None, *, installation_app_id=None, installation_id=None, repository=None):
        if installation_app_id is not None:
            if not positive_id(installation_app_id) or not valid_token(token):
                raise ValueError('invalid installation credentials')
        if installation_id is not None and (not positive_id(installation_id)
                or not positive_id(installation_app_id) or not isinstance(repository, str)
                or not REPO.fullmatch(repository)):
            raise ValueError('invalid installation scope')
        self.installation_app_id = installation_app_id
        self.installation_id = installation_id
        self.installation_repository = repository
        self.token = os.environ.get('ITM_GITHUB_TOKEN') if token is None else token
        if not valid_token(self.token): raise ValueError('valid GitHub token required')
        self.opener = build_opener(NoRedirect())
    def request(self, path, payload=None, *, method=None):
        if not path.startswith('/repos/'): raise ValueError('invalid API route')
        req = Request('https://api.github.com'+path, method=method, data=None if payload is None else json.dumps(payload).encode(), headers={'Authorization':'Bearer '+self.token,'Accept':'application/vnd.github+json','Content-Type':'application/json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'intent-to-merge/0.5'})
        try:
            with self.opener.open(req, timeout=30) as response:
                raw=response.read(16*1024*1024+1)
                if len(raw)>16*1024*1024: raise ValueError('API response too large')
                return json.loads(raw, object_pairs_hook=unique_json_members)
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
    p = load_user_config(path)
    if 'path_semantics' not in p:
        p['path_semantics'] = SEGMENT_V2
    try:
        return validate_policy(p)
    except ValueError as exc:
        raise InvalidConfiguration(str(exc)) from None

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
        if not isinstance(check['name'],str) or not check['name'] or check['name']==CHECK_NAME or not positive_id(check['app_id']): raise ValueError('invalid required check')
        if check['name'] in names: raise ValueError('duplicate check name')
        names.add(check['name'])
    roles=p['required_roles']
    if not isinstance(roles,dict) or not roles: raise ValueError('required roles must be nonempty')
    ids=set()
    for role, members in roles.items():
        if not isinstance(role,str) or not role.strip() or not isinstance(members,list) or not members or any(not positive_id(m) for m in members) or len(members) != len(set(members)) or ids.intersection(members): raise ValueError('invalid or overlapping approver IDs')
        ids.update(members)
    return p

def identity(pr, number):
    head, base = pr['head'], pr['base']
    author, count, draft = pr['user']['id'], pr['changed_files'], pr['draft']
    if (not positive_id(author) or type(count) is not int or type(draft) is not bool
            or ('number' in pr and (not positive_id(pr['number']) or pr['number'] != number))
            or pr['state'] not in ('open', 'closed')):
        raise ValueError('invalid PR observation')
    return (head['sha'], base['sha'], base['ref'], pr['state'], draft,
            head['repo']['full_name'], base['repo']['full_name'], count, author)


def latest_prerequisite(checks, rule, head):
    matching = []
    try:
        for row in checks:
            if not isinstance(row, dict):
                raise ValueError('invalid check collection')
            if row.get('name') == rule['name']:
                check_observation(row)
                if row['app']['id'] == rule['app_id'] and row['head_sha'] == head:
                    matching.append(row)
        if len({row['id'] for row in matching}) != len(matching):
            raise ValueError('ambiguous prerequisite checks')
    except ValueError:
        return {}
    return max(matching, key=lambda row: row['id'], default={})

def preflight(client, repo, number, policy, *, publish=False):
    validate_policy(policy)
    app_id = getattr(client, 'installation_app_id', None)
    if publish and not positive_id(app_id):
        raise ValueError('publication requires expected installation App identity')
    if not REPO.fullmatch(repo) or not positive_id(number) or policy['repository'].lower()!=repo.lower(): raise ValueError('repository/PR does not match policy')
    scoped_repo = getattr(client, 'installation_repository', None)
    scoped_installation = getattr(client, 'installation_id', None)
    if publish and scoped_installation is not None and not positive_id(scoped_installation):
        raise ValueError('invalid publication installation identity')
    if publish and scoped_repo is not None and (not isinstance(scoped_repo, str)
                                               or scoped_repo.lower() != repo.lower()):
        raise ValueError('installation repository mismatch')
    prefix='/repos/'+repo; route=prefix+f'/pulls/{number}'
    pr=client.request(route); before=identity(pr, number); head,base,ref,state,draft,head_repo,base_repo,count,author=before
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
        latest = latest_prerequisite(checks, rule, head)
        gate('check:'+rule['name'],latest.get('status')=='completed' and latest.get('conclusion')=='success')
    review_ids = set()
    for review in reviews:
        if (not positive_id(review.get('id')) or review['id'] in review_ids
                or not positive_id(review['user'].get('id'))
                or review.get('state') not in ('APPROVED', 'CHANGES_REQUESTED', 'DISMISSED',
                                                'COMMENTED', 'PENDING')):
            raise ValueError('invalid review observation')
        review_ids.add(review['id'])
    latest_reviews={}
    for r in sorted(reviews,key=lambda x:x['id']):
        uid=r['user']['id']; status=r['state']
        if status in ('APPROVED','CHANGES_REQUESTED','DISMISSED'): latest_reviews[uid]=r
    approved={uid for uid,r in latest_reviews.items() if uid!=author and r['state']=='APPROVED' and r.get('commit_id')==head and r['user'].get('type')=='User'}
    for role, members in policy['required_roles'].items(): gate('approval:'+role,bool(approved.intersection(members)))
    if identity(client.request(route), number)!=before: raise ValueError('PR changed during collection; retry')
    report={'schema_version':'1.0','profile':'github-live-preflight','repository':repo,'pr':number,'head':head,'base':base,'base_ref':ref,'policy_digest':digest(policy),'paths':paths,'gates':gates,'reasons':reasons,'decision':'PASS' if not reasons else 'BLOCK','full_itm_authorization':False,'note':'PR preflight only; no verification of agent observations or full evidence bundle. GitHub enforces merge rules.'}
    if publish:
        if identity(client.request(route), number)!=before: raise ValueError('PR changed before publication')
        payload={'name':CHECK_NAME,'head_sha':head,'status':'completed','conclusion':'failure' if reasons else 'success','external_id':digest(report),'output':{'title':'ITM preflight '+report['decision'],'summary':f'{sum(g["passed"] for g in gates)}/{len(gates)} gates passed. Base {base}. This is not full ITM merge authorization.'}}
        try:
            result = client.request(prefix+'/check-runs', payload)
            check_id = validate_check_response(result, payload, app_id)
        except Exception:
            raise CheckPublicationUnconfirmed(repo, app_id, payload, installation_id=scoped_installation) from None
        report['published_check_id'] = check_id
        report['publication_confirmation'] = 'RESPONSE_MATCHED'
        report['published_external_id'] = payload['external_id']
    return report
