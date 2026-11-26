import base64, hashlib, hmac, json, tempfile, unittest, subprocess, os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519,rsa,padding
from cryptography.hazmat.primitives import hashes
from intent_merge.operational import (app_jwt,delivery,Journal,verify_assertion,gate,work_once,reconcile,DOMAIN,CONTROLS,NAME)
from intent_merge.core import canonical,digest
from intent_merge.github import GitHubObservationError, policy_from
from intent_merge.capture import hook,run_agent
from test_integration_v05 import FixtureAPI,HEAD,BASE,ROOT
NOW=1900000000; APP=789; SECRET=b'x'*32
class API(FixtureAPI):
    def __init__(self):super().__init__();self.lost=False
    def request(self,path,payload=None):
        if payload is None:return super().request(path)
        self.posts.append((path,payload)); result={**payload,'id':43+len(self.posts),'app':{'id':APP}};self.checks.append(result)
        if self.lost:raise ValueError('simulated response loss')
        return result
class OpsTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.j=Journal(self.root/'queue.sqlite');self.addCleanup(self.j.close)
        self.api=API();self.policy=policy_from(ROOT/'examples/github-policy.toml');self.key=ed25519.Ed25519PrivateKey.generate()
        self.job={'id':'d1','repo':'OWNER/REPO','pr':1,'body_sha256':'a'*64};self.j.enqueue(self.job)
        self.body={'schema_version':1,'profile':'live-external-verifier','repository':'OWNER/REPO','pr':1,'head':HEAD,'base':BASE,'policy_digest':digest(self.policy),'issued_at':NOW-10,'expires_at':NOW+60,'controls':dict.fromkeys(CONTROLS,True),'evidence_digest':'c'*64}
    def assertion(self,**kw):
        body={**self.body,**kw};env={'statement':body,'signature':base64.b64encode(self.key.sign(DOMAIN+canonical(body))).decode()};(self.root/f'1-{HEAD}.json').write_text(json.dumps(env));return env
    def work(self,**kw):return work_once(self.j,self.api,self.policy,self.root,self.key.public_key(),app_id=APP,now=NOW,publication_clock=lambda: NOW,**kw)
    def check(self):return gate(self.api,self.job,self.policy,self.root,self.key.public_key(),NOW)
    def test_valid_snapshot(self):
        self.assertion();r=self.work(publish=True);self.assertEqual(r['decision'],'PASS');self.assertFalse(r['merge_authority']);self.assertEqual(self.j.get('d1')['state'],'DONE');self.assertEqual(self.api.posts[0][1]['conclusion'],'success')
    def test_missing_assertion(self):
        self.assertEqual(self.work(publish=True)['decision'],'BLOCK');self.assertEqual(self.api.posts[0][1]['conclusion'],'failure')
    def test_synthetic_profile(self):self.assertion(profile='synthetic-demo');self.assertEqual(self.check()['decision'],'BLOCK')
    def test_expired(self):self.assertion(expires_at=NOW);self.assertEqual(self.check()['decision'],'BLOCK')
    def test_wrong_base(self):self.assertion(base='d'*40);self.assertEqual(self.check()['decision'],'BLOCK')
    def test_wrong_policy(self):self.assertion(policy_digest='d'*64);self.assertEqual(self.check()['decision'],'BLOCK')
    def test_control_false(self):self.assertion(controls={**self.body['controls'],'operational_autonomy':False});self.assertEqual(self.check()['decision'],'BLOCK')
    def test_signature_tamper(self):
        e=self.assertion();e['statement']['evidence_digest']='b'*64;(self.root/f'1-{HEAD}.json').write_text(json.dumps(e));self.assertEqual(self.check()['decision'],'BLOCK')
    def test_missing_review(self):self.assertion();self.api.reviews.pop();self.assertIn('approval:security',self.check()['reasons'])
    def test_dry_run(self):self.assertion();self.work();self.assertEqual(self.j.get('d1')['state'],'DRY_RUN');self.assertFalse(self.api.posts)
    def test_duplicate(self):self.assertEqual(self.j.enqueue(self.job),'QUEUED');self.assertEqual(len(self.j.list()),1)
    def test_collision(self):
        with self.assertRaises(ValueError):self.j.enqueue({**self.job,'body_sha256':'b'*64})
    def test_running_recovery(self):self.j.claim();self.j.recover();self.assertEqual(self.j.get('d1')['state'],'QUEUED')
    def test_lost_response(self):
        self.assertion();self.api.lost=True
        with self.assertRaises(ValueError):self.work(publish=True)
        self.assertEqual(self.j.get('d1')['state'],'UNCERTAIN');self.assertIsNone(self.work(publish=True));self.assertEqual(len(self.api.posts),1)
        self.assertEqual(reconcile(self.j,self.api,'d1',APP)['state'],'DONE');self.assertEqual(len(self.api.posts),1)
    def test_crash_before_response(self):
        self.j.claim()
        with self.j.db:
            self.j.db.execute("UPDATE jobs SET state='PUBLISHING', report=?, external_id='missing' WHERE id='d1'", (json.dumps({'head':HEAD,'decision':'PASS'}),))
        self.j.recover();self.assertEqual(self.j.get('d1')['state'],'UNCERTAIN');self.assertEqual(reconcile(self.j,self.api,'d1',APP)['state'],'UNCERTAIN');self.assertFalse(self.api.posts)
    def test_jwt(self):
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048);a,b,c=app_jwt(APP,key,NOW).split('.');decode=lambda s:base64.urlsafe_b64decode(s+'='*(-len(s)%4));key.public_key().verify(decode(c),(a+'.'+b).encode(),padding.PKCS1v15(),hashes.SHA256());self.assertEqual(json.loads(decode(b))['iss'],str(APP))
    def test_delivery(self):
        raw=json.dumps({'action':'opened','repository':{'full_name':'OWNER/REPO'},'installation':{'id':1},'pull_request':{'number':1}}).encode();sig='sha256='+hmac.new(SECRET,raw,hashlib.sha256).hexdigest();self.assertEqual(delivery(raw,sig,'pull_request','d1',SECRET,'OWNER/REPO',1)['pr'],1)
        for bad,install in [('bad',1),(sig,2)]:
            with self.assertRaises(ValueError):delivery(raw,bad,'pull_request','d1',SECRET,'OWNER/REPO',install)
    def test_hook(self):
        repo=self.root/'repo';repo.mkdir();subprocess.run(['git','init','-q',str(repo)],check=True);subprocess.run(['git','-C',str(repo),'-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','--allow-empty','-qm','initial'],check=True)
        r=hook('claude',{'hook_event_name':'SessionStart','session_id':'secret-session','transcript_path':'secret-path','prompt':'private'},repo);self.assertTrue(r['git']['clean']);self.assertNotIn('secret',json.dumps(r));self.assertFalse(r['merge_authority'])
    def test_worker_rechecks(self):
        self.assertion();original=self.api.pages;counter=[0]
        def pages(path,key=None):
            if path.endswith('/reviews'):
                counter[0]+=1
                if counter[0]==2:self.api.reviews.pop()
            return original(path,key)
        self.api.pages=pages
        with self.assertRaises(ValueError):self.work(publish=True)
        self.assertFalse(self.api.posts);self.assertEqual(self.j.get('d1')['state'],'QUEUED')
    def test_telemetry(self):
        try:
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import SimpleSpanProcessor
            from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
        except ModuleNotFoundError as exc:
            if os.environ.get('ITM_REQUIRE_TELEMETRY') == '1' or not (exc.name or '').startswith('opentelemetry'):
                raise
            self.skipTest('optional telemetry extra is not installed')
        provider=TracerProvider();exp=InMemorySpanExporter();provider.add_span_processor(SimpleSpanProcessor(exp));self.assertion();self.work(tracer=provider.get_tracer('test'),publish=True);self.assertEqual({s.name for s in exp.get_finished_spans()},{'itm.worker','itm.evaluate','itm.publish'});provider.shutdown()
    def test_local_runner_fixture(self):
        from unittest.mock import patch
        repo=self.root/'repo';repo.mkdir();subprocess.run(['git','init','-q',str(repo)],check=True);subprocess.run(['git','-C',str(repo),'-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','--allow-empty','-qm','initial'],check=True)
        bin_dir=self.root/'bin';bin_dir.mkdir();prompt=self.root/'prompt.txt';prompt.write_text('non-sensitive fixture')
        for agent,exe in [('claude','claude'),('codex','codex')]:
            executable=bin_dir/exe;native=(ROOT/f'examples/native-sessions/{agent}.jsonl').read_text()
            executable.write_text('#!/usr/bin/env python3\nimport os\nfrom pathlib import Path\nassert "ITM_FIXTURE_SECRET" not in os.environ\nPath("new.txt").write_text("fixture change")\nprint('+repr(native)+')\n');executable.chmod(0o700)
            with patch.dict(os.environ,{'PATH':str(bin_dir)+os.pathsep+os.environ['PATH'],'ITM_FIXTURE_SECRET':'private'}):
                result=run_agent(agent,repo,prompt,self.root/(agent+'.json'),timeout=5)
            self.assertTrue(result['before']['clean']);self.assertFalse(result['after']['clean']);self.assertFalse(result['merge_authority']);self.assertNotIn('fixture change',json.dumps(result));(repo/'new.txt').unlink()
    def test_self_required_gate(self):
        self.policy['required_checks'].append({'name':NAME,'app_id':APP});self.assertion()
        with self.assertRaisesRegex(ValueError,'itself'):self.check()

    def test_installation_identity_mismatch_never_posts(self):
        self.api.installation_app_id = APP + 1
        self.assertion()
        with self.assertRaisesRegex(ValueError, 'App identity mismatch'):
            self.work(publish=True)
        self.assertEqual(self.j.get('d1')['state'], 'QUEUED')
        self.assertFalse(self.api.posts)

    def test_malformed_acknowledgement_after_remote_creation(self):
        from unittest.mock import patch
        self.assertion()
        request = self.api.request
        for n, fields in enumerate(({'id': -1}, {'id': 0}, {'id': True}, {'id': 44.0},
                                    {'app': {'id': 789.0}}, {'app': None}, {'head_sha': 'f'*40},
                                    {'name': 'incorrect'}, {'status': 'queued'},
                                    {'conclusion': 'failure'}, {'external_id': 'incorrect'},
                                    {'app': {'id': -1}}, {'app': {'id': True}},
                                    {'app': {'id': 0}}, {'app': {}})):
            with self.subTest(fields=fields):
                job_id = self.job['id'] if n == 0 else f'd{n+1}'
                self.j.enqueue({**self.job, 'id': job_id})
                def create(path, payload=None):
                    result = request(path, payload)
                    return {**result, **fields} if payload else result
                with patch.object(self.api, 'request', side_effect=create), self.assertRaises(ValueError):
                    self.work(publish=True)
                job = self.j.get(job_id)
                self.assertEqual(job['state'], 'UNCERTAIN')
                self.assertIsNotNone(job['external_id'])
                self.assertIsNone(job['check_id'])
                self.assertEqual(reconcile(self.j, self.api, job_id, APP)['state'], 'DONE')
                self.assertEqual(len(self.api.posts), n+1)

    def test_reconcile_malformed_or_duplicate_correlated_acknowledgement(self):
        from unittest.mock import patch
        self.assertion()
        self.api.lost = True
        with self.assertRaises(ValueError):
            self.work(publish=True)
        good = self.api.checks[-1]
        missing = {k: v for k, v in good.items() if k != 'id'}
        for rows in ([missing], [{**good, 'id': -1}], [good, missing],
                     [good, {**good, 'head_sha': 'f'*40}], [good, good],
                     [good, None], [good, {}], [good, {**good, 'external_id': 'other'}],
                     [good, {**good, 'app': {'id': 789.0}}]):
            with self.subTest(rows=len(rows)), patch.object(self.api, 'checks', rows):
                result = reconcile(self.j, self.api, 'd1', APP)
                self.assertEqual(result['state'], 'UNCERTAIN')
                self.assertEqual(self.j.get('d1')['external_id'], good['external_id'])
        with patch.object(self.api, 'checks', [{**good, 'id': 99, 'external_id': 'other'}, good]):
            self.assertEqual(reconcile(self.j, self.api, 'd1', APP)['state'], 'DONE')
        self.assertEqual(len(self.api.posts), 1)

    def test_default_worker_refuses_incomplete_refresh(self):
        from unittest.mock import patch
        self.assertion()
        request = self.api.request
        reads = 0

        def observe(path, payload=None):
            nonlocal reads
            response = request(path, payload)
            if '/check-runs?' in path:
                reads += 1
                if reads == 2:
                    response['total_count'] += 1
            return response

        with patch.object(self.api, 'request', side_effect=observe), self.assertRaises(GitHubObservationError):
            self.work(publish=True)
        self.assertEqual(reads, 2)
        self.assertEqual(self.j.get('d1')['state'], 'QUEUED')
        self.assertFalse(self.api.posts)

    def test_default_gate_expiry_after_publishing_commit(self):
        from unittest.mock import patch
        self.assertion(expires_at=NOW+1)
        clock = [NOW]
        transition = self.j.transition
        def commit(*args, **kwargs):
            transition(*args, **kwargs)
            if args[2] == 'PUBLISHING':
                clock[0] = NOW+1
        with patch('intent_merge.operational.time.time', side_effect=lambda: clock[0]), \
                patch.object(self.j, 'transition', side_effect=commit):
            report = work_once(self.j, self.api, self.policy, self.root, self.key.public_key(),
                               app_id=APP, now=NOW, publish=True)
        self.assertEqual(report['decision'], 'BLOCK')
        self.assertEqual(self.j.get('d1')['state'], 'BLOCKED_BEFORE_PUBLICATION')
        self.assertFalse(self.api.posts)

    def test_default_gate_last_valid_second_and_clock_regression(self):
        self.assertion(expires_at=NOW+2)
        def run(clock):
            return work_once(self.j, self.api, self.policy, self.root, self.key.public_key(),
                             app_id=APP, now=NOW, publish=True, publication_clock=lambda: clock)
        self.assertEqual(run(NOW-1)['decision'], 'BLOCK')
        self.assertEqual(self.j.get('d1')['state'], 'BLOCKED_BEFORE_PUBLICATION')
        self.assertFalse(self.api.posts)
        self.j.enqueue({**self.job, 'id': 'last-second'})
        self.assertEqual(run(NOW+1)['decision'], 'PASS')
        self.assertEqual(self.j.get('last-second')['state'], 'DONE')
        self.assertEqual(len(self.api.posts), 1)

    def test_success_returned_without_valid_verified_expiry(self):
        self.assertion()
        for i, invalid in enumerate((None, True, float(NOW+60), 'unknown', 0)):
            with self.subTest(invalid=invalid):
                job_id = 'd1' if not i else 'invalid-' + str(i)
                self.j.enqueue({**self.job, 'id': job_id})
                def invalid_gate(*args):
                    report = gate(*args)
                    return {**report, 'expires_at': invalid}
                report = self.work(publish=True, gate_fn=invalid_gate)
                self.assertEqual(report['decision'], 'BLOCK')
                self.assertEqual(self.j.get(job_id)['state'], 'BLOCKED_BEFORE_PUBLICATION')
                self.assertIsNone(self.j.get(job_id)['external_id'])
        self.assertFalse(self.api.posts)

    def test_acknowledgement_missing_identifier_or_invalid_object(self):
        from unittest.mock import patch
        self.assertion()
        request = self.api.request
        for i, field in enumerate(('id', 'app', None)):
            with self.subTest(field=field):
                job_id = 'd1' if not i else 'missing-' + str(i)
                self.j.enqueue({**self.job, 'id': job_id})
                def create(path, payload=None):
                    result = request(path, payload)
                    if not payload:
                        return result
                    if field is None:
                        return []
                    return {k: v for k, v in result.items() if k != field}
                with patch.object(self.api, 'request', side_effect=create), self.assertRaises(ValueError):
                    self.work(publish=True)
                self.assertEqual(self.j.get(job_id)['state'], 'UNCERTAIN')
                self.assertEqual(reconcile(self.j, self.api, job_id, APP)['state'], 'DONE')
        self.assertEqual(len(self.api.posts), 3)
