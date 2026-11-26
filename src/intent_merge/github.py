"""Live GitHub preflight. Separate from synthetic evidence and merge authority."""
from __future__ import annotations
import json, os, re
from .path_policy import matches, validate_patterns, SEGMENT_V2
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError, URLError
from http.client import HTTPException
from urllib.parse import quote
from .core import digest, load_user_config, unique_json_members
from .policy_schema import InvalidConfiguration

SHA = re.compile(r'[0-9a-f]{40}')
REPO = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+')
CHECK_NAME = 'ITM / PR preflight'
FILE_STATUSES = ('added', 'removed', 'modified', 'renamed', 'copied', 'changed', 'unchanged')
CHECK_STATUSES = {'queued', 'in_progress', 'completed', 'requested', 'waiting', 'pending'}
PAGE_SIZE = 100
PAGE_LIMIT = 30
CHECK_SUITE_LIMIT = 1000
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


class GitHubObservationError(ValueError):
    """An unavailable or invalid GitHub observation with a redacted message."""


def check_observation(row, *, allow_null_app=False):
    """Validate the identity and lifecycle fields returned by GitHub."""
    if not isinstance(row, dict):
        raise GitHubObservationError('invalid check observation')
    app, status, conclusion = row.get('app'), row.get('status'), row.get('conclusion')
    has_app = isinstance(app, dict) and positive_id(app.get('id'))
    null_app = allow_null_app and 'app' in row and app is None
    external_id = row.get('external_id')
    if (not positive_id(row.get('id')) or not (has_app or null_app)
            or 'external_id' not in row
            or (external_id is not None and not isinstance(external_id, str))
            or not isinstance(row.get('name'), str) or not row['name']
            or not isinstance(row.get('head_sha'), str) or not SHA.fullmatch(row['head_sha'])
            or not isinstance(status, str) or status not in CHECK_STATUSES
            or 'conclusion' not in row
            or (status == 'completed' and
                (not isinstance(conclusion, str) or conclusion not in CHECK_CONCLUSIONS))
            or (status != 'completed' and conclusion is not None)):
        raise GitHubObservationError('invalid check observation')
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
        raise GitHubObservationError('unexpected check response')
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
        except HTTPError as e:
            raise GitHubObservationError(f'GitHub HTTP {e.code}') from None
        except (URLError, OSError, HTTPException):
            raise GitHubObservationError('GitHub transport failure') from None
        if len(raw) > 16*1024*1024:
            raise GitHubObservationError('GitHub response too large')
        try:
            return json.loads(raw, object_pairs_hook=unique_json_members)
        except (ValueError, RecursionError):
            raise GitHubObservationError('invalid GitHub response JSON') from None

    def pages(self, path):
        for page in range(1, PAGE_LIMIT + 1):
            separator = '&' if '?' in path else '?'
            rows = self.request(f'{path}{separator}per_page={PAGE_SIZE}&page={page}')
            if not isinstance(rows, list):
                raise GitHubObservationError('invalid GitHub collection')
            yield from rows
            if len(rows) < PAGE_SIZE:
                return
        raise GitHubObservationError('pagination limit reached; refusing incomplete evidence')


def _counted_page(data, key):
    if not isinstance(data, dict) or not isinstance(data.get(key), list):
        raise GitHubObservationError('invalid GitHub collection')
    count = data.get('total_count')
    if type(count) is not int or count < 0:
        raise GitHubObservationError('invalid GitHub collection count')
    return count, data[key]


def check_runs(client, repo, head):
    """Collect distinct check runs for a validated repository and commit SHA."""
    route = f'/repos/{repo}/commits/{head}'
    # The ref-level runs endpoint can silently omit older suites at its cap.
    suite_count, suites = _counted_page(
        client.request(route + '/check-suites?per_page=1&page=1'), 'check_suites')
    if len(suites) != min(1, suite_count) or any(
            not isinstance(row, dict) or not positive_id(row.get('id')) for row in suites):
        raise GitHubObservationError('invalid check suite observation')
    if suite_count >= CHECK_SUITE_LIMIT:
        raise GitHubObservationError('unsupported GitHub check suite count')

    expected = None
    runs = {}
    for page in range(1, PAGE_LIMIT + 1):
        path = f'{route}/check-runs?filter=all&per_page={PAGE_SIZE}&page={page}'
        count, rows = _counted_page(client.request(path), 'check_runs')
        if expected is None:
            expected = count
            if expected > PAGE_SIZE * PAGE_LIMIT:
                raise GitHubObservationError('unsupported GitHub check run count')
        elif count != expected:
            raise GitHubObservationError('GitHub check run count changed; retry')
        if len(rows) != min(PAGE_SIZE, expected - len(runs)):
            raise GitHubObservationError('incomplete or excess GitHub check runs; retry')
        for row in rows:
            check_id = check_observation(row, allow_null_app=True)
            if check_id in runs:
                raise GitHubObservationError('duplicate GitHub check run identity; retry')
            runs[check_id] = row
        if len(runs) == expected:
            return list(runs.values())
    raise GitHubObservationError('pagination limit reached; refusing incomplete evidence')


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

def pr_side(side):
    if isinstance(side, dict) and isinstance(side.get('repo'), dict):
        sha = side.get('sha')
        name = side['repo'].get('full_name')
        if isinstance(sha, str) and SHA.fullmatch(sha) and isinstance(name, str) and REPO.fullmatch(name):
            return sha, name
    raise GitHubObservationError('invalid PR observation')


def identity(pr, number):
    if not isinstance(pr, dict) or not isinstance(pr.get('user'), dict):
        raise GitHubObservationError('invalid PR observation')
    author, count, draft = pr['user'].get('id'), pr.get('changed_files'), pr.get('draft')
    state = pr.get('state')
    if (not positive_id(author) or type(count) is not int or type(draft) is not bool
            or ('number' in pr and (not positive_id(pr['number']) or pr['number'] != number))
            or state not in ('open', 'closed')):
        raise GitHubObservationError('invalid PR observation')
    head, head_repo = pr_side(pr.get('head'))
    base, base_repo = pr_side(pr.get('base'))
    ref = pr['base'].get('ref')
    if not isinstance(ref, str) or not ref:
        raise GitHubObservationError('invalid PR observation')
    return head, base, ref, state, draft, head_repo, base_repo, count, author


def changed_paths(files, count):
    names = set()
    paths = set()
    for item in files:
        if not isinstance(item, dict):
            raise GitHubObservationError('invalid PR file observation')
        name, status, previous = item.get('filename'), item.get('status'), item.get('previous_filename')
        if (not isinstance(name, str) or not name or status not in FILE_STATUSES
                or (previous is not None and (not isinstance(previous, str) or not previous))):
            raise GitHubObservationError('invalid PR file observation')
        if status == 'renamed' and previous is None:
            raise GitHubObservationError('rename missing source path')
        names.add(name)
        paths.add(name)
        if previous is not None:
            paths.add(previous)
    if len(files) != count or len(names) != count:
        raise GitHubObservationError('incomplete file inventory')
    return sorted(paths)


def latest_prerequisite(checks, rule, head):
    matching = (row for row in checks
                if row['name'] == rule['name'] and row['app'] is not None
                and row['app']['id'] == rule['app_id'] and row['head_sha'] == head)
    return max(matching, key=lambda row: row['id'], default={})


def validate_reviews(reviews):
    review_ids = set()
    for review in reviews:
        if not isinstance(review, dict) or not isinstance(review.get('user'), dict):
            raise GitHubObservationError('invalid review observation')
        user, review_id = review['user'], review.get('id')
        state, user_type, commit = review.get('state'), user.get('type'), review.get('commit_id')
        if (not positive_id(review_id) or review_id in review_ids or not positive_id(user.get('id'))
                or not isinstance(user_type, str) or not user_type
                or state not in ('APPROVED', 'CHANGES_REQUESTED', 'DISMISSED', 'COMMENTED', 'PENDING')
                or (state != 'PENDING' and 'commit_id' not in review)
                or (commit is not None and (not isinstance(commit, str) or not SHA.fullmatch(commit)))):
            raise GitHubObservationError('invalid review observation')
        review_ids.add(review_id)


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
    if base_repo.lower()!=repo.lower(): raise GitHubObservationError('base repository mismatch')
    if head_repo.lower()!=repo.lower(): raise GitHubObservationError('fork PRs unsupported in v0.5')
    if count<=0 or count>=3000: raise GitHubObservationError('unsupported file count')
    paths = changed_paths(list(client.pages(route+'/files')), count)
    reviews=list(client.pages(route+'/reviews'))
    validate_reviews(reviews)
    checks = check_runs(client, repo, head)
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
    latest_reviews={}
    for r in sorted(reviews,key=lambda x:x['id']):
        uid=r['user']['id']; status=r['state']
        if status in ('APPROVED','CHANGES_REQUESTED','DISMISSED'): latest_reviews[uid]=r
    approved={uid for uid,r in latest_reviews.items() if uid!=author and r['state']=='APPROVED' and r.get('commit_id')==head and r['user'].get('type')=='User'}
    for role, members in policy['required_roles'].items(): gate('approval:'+role,bool(approved.intersection(members)))
    if identity(client.request(route), number)!=before: raise GitHubObservationError('PR changed during collection; retry')
    report={'schema_version':'1.0','profile':'github-live-preflight','repository':repo,'pr':number,'head':head,'base':base,'base_ref':ref,'policy_digest':digest(policy),'paths':paths,'gates':gates,'reasons':reasons,'decision':'PASS' if not reasons else 'BLOCK','full_itm_authorization':False,'note':'PR preflight only; no verification of agent observations or full evidence bundle. GitHub enforces merge rules.'}
    if publish:
        if identity(client.request(route), number)!=before: raise GitHubObservationError('PR changed before publication')
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
