"""RC6 regression probes; all use harmless fixtures and no external credentials."""
import hashlib,hmac,json,os,sqlite3,subprocess,sys,tempfile,unittest,threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from intent_merge.integrated import Lifecycle,run,attest,candidate,git,text_git,SCENARIO,TARGET
from intent_merge.control_plane import public
from intent_merge.core import canonical
from intent_merge.budget import Limits
from intent_merge.secure_executor import bounded_capture,Executor

class OutputLimits(unittest.TestCase):
    def execute(self,code,**kwargs):
        with tempfile.TemporaryDirectory() as d:
            return bounded_capture([sys.executable,'-I','-c',code],b'[]',cwd=d,timeout=kwargs.pop('timeout',3),**kwargs)
    def test_normal_output(self):self.assertEqual(self.execute('print("ok")'),('ok',b'ok\n'))
    def test_stdout_cap(self):self.assertEqual(self.execute('print("a"*1000000)',stdout_limit=4096),('output_limit',None))
    def test_stderr_cap(self):self.assertEqual(self.execute('import sys;sys.stderr.write("x"*1000000)',stderr_limit=4096),('output_limit',None))
    def test_timeout(self):
        with self.assertRaises(subprocess.TimeoutExpired):self.execute('import time;time.sleep(10)',timeout=.15)
    def test_nonzero(self):self.assertEqual(self.execute('raise SystemExit(1)'),('execution_failed',None))

class JournalSecurity(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.p=Path(self.tmp.name);self.out=self.p/'run';self.r=run(self.out,'claude',Limits(),fixture='first');self.key=Ed25519PrivateKey.generate();self.pub=public(self.key);self.rec=attest(self.out/'repo',self.r,Executor('local'),self.key,100);self.j=Lifecycle(self.p/'journal.db');self.addCleanup(self.j.close)
    def event(self,kind='review_withdrawn',head=None,at=101):
        raw=canonical({'id':'delivery','kind':kind,'head':head or self.r['head'],'base':self.r['base'],'at':at});key=b'k'*32;return self.j.event(raw,hmac.new(key,raw,hashlib.sha256).hexdigest(),key)
    def register(self,rec=None,now=102):return self.j.register(rec or self.rec,self.pub,self.r,now)
    def test_event_before_registration(self):
        self.event();self.assertEqual(self.j.state(self.register())['state'],'REVOKED')
    def test_fresh_receipt_cannot_restore_revoked_binding(self):
        self.register();self.event();fresh=attest(self.out/'repo',self.r,Executor('local'),self.key,103);self.assertNotEqual(fresh['statement']['issued_at'],self.rec['statement']['issued_at']);self.assertEqual(self.j.state(self.register(fresh,104))['state'],'REVOKED')
    def test_binding_event_before_registration(self):
        self.event('binding_changed',head='f'*40);self.assertEqual(self.j.state(self.register())['state'],'REVOKED')
    def test_stale_snapshot_rejected(self):
        self.j.reconcile('f'*40,self.r['base'],105)
        with self.assertRaises(ValueError):self.j.reconcile(self.r['head'],self.r['base'],104)
        with self.assertRaises(ValueError):self.j.reconcile(self.r['head'],self.r['base'],105)
        self.assertEqual(self.j.state(self.register(now=106))['state'],'REVOKED')
    def test_checkpoint_tamper(self):
        i=self.register();self.event();pin=self.j.checkpoint();self.assertTrue(self.j.verify_checkpoint(pin));
        with self.j.db:self.j.db.execute("UPDATE readiness SET state='CURRENT' WHERE id=?",(i,))
        with self.assertRaises(ValueError):self.j.verify_checkpoint(pin)
    def test_checkpoint_replay(self):
        self.register();old=self.j.checkpoint();self.event();new=self.j.checkpoint();self.assertNotEqual(old,new)
        with self.assertRaises(ValueError):self.j.verify_checkpoint(old)
        self.assertTrue(self.j.verify_checkpoint(new))
    def test_actual_database_rollback_detected(self):
        self.register();backup=self.p/'old.db'
        with closing(sqlite3.connect(backup)) as dest:self.j.db.backup(dest)
        self.event();latest=self.j.checkpoint();old=Lifecycle(backup)
        try:
            with self.assertRaises(ValueError):old.verify_checkpoint(latest)
        finally:old.close()
    def test_concurrent_register_and_withdraw(self):
        barrier=threading.Barrier(2);path=self.p/'journal.db'
        def register():
            j=Lifecycle(path)
            try:barrier.wait(5);return j.register(self.rec,self.pub,self.r,102)
            finally:j.close()
        def withdraw():
            j=Lifecycle(path)
            try:
                raw=canonical({'id':'race','kind':'review_withdrawn','head':self.r['head'],'base':self.r['base'],'at':101});key=b'k'*32
                barrier.wait(5);return j.event(raw,hmac.new(key,raw,hashlib.sha256).hexdigest(),key)
            finally:j.close()
        with ThreadPoolExecutor(max_workers=2) as pool:
            x=pool.submit(register);y=pool.submit(withdraw);i=x.result(10);self.assertEqual(y.result(10),'APPLIED')
        self.assertEqual(self.j.state(i)['state'],'REVOKED')
    def test_legacy_journal_rejected(self):
        p=self.p/'legacy.db'
        with closing(sqlite3.connect(p)) as conn, conn:conn.execute('CREATE TABLE readiness(id TEXT)')
        with self.assertRaises(ValueError):Lifecycle(p)
    def test_duplicate_json_keys(self):
        raw=b'{"id":"one","id":"two"}';key=b'k'*32
        with self.assertRaises(ValueError):self.j.event(raw,hmac.new(key,raw,hashlib.sha256).hexdigest(),key)
    def test_candidate_report_mismatch(self):
        self.r['attempts'][-1]['verification']['source_digest']='f'*64
        with self.assertRaises(ValueError):attest(self.out/'repo',self.r,Executor('local'),self.key,100)
    def test_git_replace_ref_ignored(self):
        repo=self.out/'repo';head=self.r['head'];base=self.r['base'];git(repo,'replace',head,base)
        self.assertEqual(candidate(repo,base,head)[0],SCENARIO['fixed'])
    def test_git_environment_ignored(self):
        with patch.dict(os.environ,{'GIT_DIR':'/nonexistent','GIT_WORK_TREE':'/nonexistent'}):self.assertEqual(candidate(self.out/'repo',self.r['base'],self.r['head'])[0],SCENARIO['fixed'])

if __name__=='__main__':unittest.main()
