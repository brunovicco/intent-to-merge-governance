"""Bounded execution for RC6 integrated profile. Legacy verifier is retained for historical signed bundle replay."""
from __future__ import annotations
import json, os, selectors, signal, subprocess, tempfile, time, uuid
from pathlib import Path
from .verification import Executor as LegacyExecutor

def bounded_capture(command, payload, *, timeout, cwd, env=None, stdout_limit=2_000_000, stderr_limit=131072):
    """POSIX bounded pipe capture; no unbounded communicate() allocation.

    Docker container cleanup is the caller's responsibility. A process group
    is not a sandbox; descendants that escape it are outside this guarantee.
    """
    deadline=time.monotonic()+timeout
    with tempfile.TemporaryFile() as stdin:
        stdin.write(payload); stdin.seek(0)
        with subprocess.Popen(command,stdin=stdin,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=cwd,env=env,start_new_session=True) as p:
            completed=False
            try:
                with selectors.DefaultSelector() as sel:
                    buffers={'stdout':bytearray(),'stderr':bytearray()}
                    for stream,label in ((p.stdout,'stdout'),(p.stderr,'stderr')):sel.register(stream,selectors.EVENT_READ,label)
                    while sel.get_map():
                        remaining=deadline-time.monotonic()
                        if remaining<=0:raise subprocess.TimeoutExpired(command,timeout)
                        for k,_ in sel.select(remaining):
                            chunk=os.read(k.fileobj.fileno(),65536)
                            if not chunk:sel.unregister(k.fileobj);continue
                            buf=buffers[k.data];limit=stdout_limit if k.data=='stdout' else stderr_limit
                            if len(buf)+len(chunk)>limit:return 'output_limit',None
                            buf.extend(chunk)
                    remaining=deadline-time.monotonic()
                    if remaining<=0:raise subprocess.TimeoutExpired(command,timeout)
                    rc=p.wait(timeout=remaining);completed=True
                    if rc:return 'execution_failed',None
                    return 'ok',bytes(buffers['stdout'])
            finally:
                # Kill the group even if the leader exited but a descendant
                # retained a pipe. Only invoked for this newly created session.
                if not completed:
                    try:os.killpg(p.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                p.wait()


class Executor(LegacyExecutor):
    def execute(self, source, worker, plan_data):
        with tempfile.TemporaryDirectory(prefix='itm-worker-') as tmp:
            d=Path(tmp); d.chmod(0o755)
            for n,content in [('candidate.py',source),('worker.py',worker)]:
                f=d/n; f.write_text(content); f.chmod(0o444)
            name='itm-'+uuid.uuid4().hex
            try:
                status,output=bounded_capture(self.command(d,name),json.dumps(plan_data['cases']).encode(),timeout=self.timeout,cwd=d,env={'PATH':os.environ.get('PATH','')} if self.backend=='local' else None)
                if status!='ok':return {'status':status,'observations':None}
                try:
                    obs=json.loads(output,parse_constant=lambda s: (_ for _ in ()).throw(ValueError(s)))
                    return {'status':'ok','observations':obs}
                except (ValueError,RecursionError): return {'status':'invalid_output','observations':None}
            except subprocess.TimeoutExpired:
                return {'status':'timeout','observations':None}
            except OSError:
                return {'status':'execution_failed','observations':None}
            finally:
                if self.backend=='docker':
                    try: subprocess.run(['docker','rm','-f',name],capture_output=True,timeout=5)
                    except (OSError,subprocess.SubprocessError): pass

