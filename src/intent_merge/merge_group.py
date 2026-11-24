"""Strict standalone merge_group webhook parser; no queue authorization or checks.
Not wired into the existing PR worker. Payload is a claim, not a fresh API snapshot.
"""
import hashlib,hmac,json,re
from .operational import require,MAX_BODY
from .github import SHA,REPO

def parse_merge_group(raw,signature,event,delivery_id,secret,repo,installation,base_ref='main'):
    require(isinstance(raw,bytes) and len(raw)<=MAX_BODY and isinstance(secret,bytes) and len(secret)>=32,'invalid webhook inputs');expected='sha256='+hmac.new(secret,raw,hashlib.sha256).hexdigest();require(isinstance(signature,str) and hmac.compare_digest(expected,signature),'invalid webhook signature');require(isinstance(delivery_id,str) and re.fullmatch(r'[A-Za-z0-9-]{1,80}',delivery_id),'invalid delivery ID')
    if event!='merge_group':return None
    require(REPO.fullmatch(repo) and type(installation) is int and installation>0,'invalid trust configuration');d=json.loads(raw);require(d['repository']['full_name'].lower()==repo.lower() and d['installation']['id']==installation,'untrusted repository or installation')
    if d.get('action')!='checks_requested':return None
    g=d['merge_group'];head=g['head_sha'];base=g['base_sha'];ref=g['head_ref'];target='refs/heads/'+base_ref;require(SHA.fullmatch(head) and SHA.fullmatch(base) and head!=base and g['base_ref']==target,'invalid queue binding');require(isinstance(ref,str) and ref.startswith('refs/heads/gh-readonly-queue/'+base_ref+'/') and len(ref)<=512,'invalid queue ref')
    return {'profile':'merge-group-observation-only','delivery_id':delivery_id,'repository':repo,'installation':installation,'head':head,'base':base,'head_ref':ref,'base_ref':target,'body_sha256':hashlib.sha256(raw).hexdigest(),'decision':'BLOCK_PENDING_FRESH_GROUP_VERIFICATION','merge_authority':False}
