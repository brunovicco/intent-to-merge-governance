"""Portable evidence bundles: signed in-toto Statement v1 in a DSSE envelope.
External signer trust is mandatory. No candidate execution or private approval keys.
"""
from __future__ import annotations
import base64, hashlib, json, os, shutil, tempfile
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from .core import canonical, file_hash
from .evidence_inventory import evidence_files, regular_file
from .evidence_profile import CURRENT
from .runner import audit, write_json

PAYLOAD_TYPE = 'application/vnd.in-toto+json'
PREDICATE = 'https://intent-to-merge.dev/predicates/change-evidence/v1'
STATEMENT = 'https://in-toto.io/Statement/v1'


def pae(kind, payload):
    t=kind.encode('utf-8')
    return b'DSSEv1 %d %s %d %s' % (len(t),t,len(payload),payload)


def keygen(private_path, public_path):
    private_path,public_path=Path(private_path),Path(public_path)
    if private_path.resolve()==public_path.resolve() or private_path.exists() or public_path.exists(): raise ValueError('key paths must be distinct and new')
    key=Ed25519PrivateKey.generate()
    raw=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    with os.fdopen(os.open(private_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as f: f.write(raw)
    with public_path.open('xb') as f: f.write(key.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
    return {'key_id':key_id(key.public_key()),'private_key':str(private_path),'public_key':str(public_path)}


def key_id(key):
    return hashlib.sha256(key.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).hexdigest()


def inventory(root):
    """Strict flat evidence directory; no links, nested files or special files."""
    root=Path(root)
    if root.is_symlink() or not root.is_dir(): raise ValueError('invalid bundle directory')
    if {p.name for p in root.iterdir()} != {'evidence','manifest.json','anchor.json','approval-trust.json','attestation.json'}: raise ValueError('unexpected bundle layout')
    files = list(evidence_files(root).values())
    for name in ('manifest.json', 'anchor.json', 'approval-trust.json', 'attestation.json'):
        path = regular_file(root / name)
        if name != 'attestation.json':
            files.append(path)
    return {p.relative_to(root).as_posix():file_hash(p) for p in sorted(files)}


def public_approval_trust(path):
    keys=json.loads(Path(path).read_text())
    if not isinstance(keys,dict) or not keys: raise ValueError('invalid approval trust')
    for actor,key in keys.items():
        if not isinstance(key,str) or not key.startswith('ed25519-public:'): raise ValueError('public Ed25519 approval keys required; legacy HMAC runs cannot be exported')
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key.split(':',1)[1]))
    return keys


def pack(run, output, private_key):
    run,output=Path(run),Path(output).resolve()
    if output.exists() or output.is_relative_to(run.resolve()): raise ValueError('bundle output must be new and outside run')
    key=serialization.load_pem_private_key(Path(private_key).read_bytes(),password=None)
    if not isinstance(key,Ed25519PrivateKey): raise ValueError('Ed25519 signer required')
    audit(run,run/'anchor.json',run/'demo-trust.json')
    public_approval_trust(run/'demo-trust.json')
    output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output.parent) as tmp:
        stage=Path(tmp)/'bundle'; stage.mkdir(); (stage/'evidence').mkdir()
        for p in (run/'evidence').iterdir():
            if p.is_symlink() or not p.is_file(): raise ValueError('non-regular evidence file')
            shutil.copyfile(p,stage/'evidence'/p.name)
        for src,dst in [('manifest.json','manifest.json'),('anchor.json','anchor.json'),('demo-trust.json','approval-trust.json')]:
            if (run/src).is_symlink(): raise ValueError('symlinks not allowed')
            shutil.copyfile(run/src,stage/dst)
        (stage/'attestation.json').write_text('{}')
        report=json.loads((stage/'evidence/report.json').read_text())
        audit(stage,stage/'anchor.json',stage/'approval-trust.json')
        statement={'_type':STATEMENT,'subject':[{'name':name,'digest':{'sha256':sha}} for name,sha in inventory(stage).items()], 'predicateType':PREDICATE,'predicate':{'candidate':report['candidate'],'base':report['base'],'ledger_root':report['ledger_root'],'merged':report['merged'],'profile':'synthetic-demo','approval_trust':'signer-endorsed public keys','evidence_version':'0.4'}}
        payload=canonical(statement)
        envelope={'payloadType':PAYLOAD_TYPE,'payload':base64.b64encode(payload).decode(),'signatures':[{'keyid':key_id(key.public_key()),'sig':base64.b64encode(key.sign(pae(PAYLOAD_TYPE,payload))).decode()}]}
        write_json(stage/'attestation.json',envelope)
        stage.rename(output)
    return {'bundle':str(output),'key_id':key_id(key.public_key()),'subjects':len(statement['subject']),'candidate':report['candidate']}


def verify(bundle, public_key, *, profile=CURRENT):
    bundle=Path(bundle); files=inventory(bundle)
    key=serialization.load_pem_public_key(Path(public_key).read_bytes())
    if not isinstance(key,Ed25519PublicKey): raise ValueError('Ed25519 public key required')
    envelope=json.loads((bundle/'attestation.json').read_text())
    try:
        if envelope['payloadType']!=PAYLOAD_TYPE or len(envelope['signatures'])!=1: raise ValueError('invalid DSSE envelope')
        sig=envelope['signatures'][0]
        if sig['keyid']!=key_id(key): raise ValueError('untrusted signer')
        payload=base64.b64decode(envelope['payload'],validate=True)
        key.verify(base64.b64decode(sig['sig'],validate=True),pae(PAYLOAD_TYPE,payload))
    except (InvalidSignature, KeyError, TypeError) as e: raise ValueError('invalid attestation signature or envelope') from e
    statement=json.loads(payload)
    if statement.get('_type')!=STATEMENT or statement.get('predicateType')!=PREDICATE: raise ValueError('unsupported attestation type')
    expected=[{'name':name,'digest':{'sha256':sha}} for name,sha in files.items()]
    if statement['subject']!=expected: raise ValueError('signed subject inventory mismatch')
    report=json.loads((bundle/'evidence/report.json').read_text()); pred=statement['predicate']
    expected_pred={'candidate':report['candidate'],'base':report['base'],'ledger_root':report['ledger_root'],'merged':report['merged'],'profile':'synthetic-demo','approval_trust':'signer-endorsed public keys','evidence_version':'0.4'}
    if pred!=expected_pred: raise ValueError('attestation predicate mismatch')
    public_approval_trust(bundle/'approval-trust.json')
    result=audit(bundle,bundle/'anchor.json',bundle/'approval-trust.json',profile=profile)
    return {**result,'signature':'verified','key_id':key_id(key),'subjects':len(files),'candidate':report['candidate'],'profile':pred['profile']}
