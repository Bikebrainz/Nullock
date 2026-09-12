#!/usr/bin/env python3
"""Crash recovery and atomic save failures against an isolated real application."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from outbound_scope_regression import free_port


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('app', type=Path)
    app = parser.parse_args().app.resolve(); checks = 0; hits = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_GET(self):
            hits.append(self.path)
            self.send_response(200); self.send_header('Content-Length', '0')
            self.send_header('X-Token', 'token-' + str(len(hits))); self.end_headers()
    fixture = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    worker = Thread(target=fixture.serve_forever, daemon=True); worker.start()
    with tempfile.TemporaryDirectory(prefix='nullock-recovery-') as tmp:
        root = Path(tmp); control = free_port(); process = None
        log = (root/'app.log').open('wb')
        def api(endpoint, data=None, status=200):
            req = urllib.request.Request(f'http://127.0.0.1:{control}'+endpoint,
                data=None if data is None else json.dumps(data).encode(),
                headers={'Content-Type':'application/json', 'X-Nullock-UI':'1'})
            try:
                with urllib.request.urlopen(req, timeout=15) as r: code, body = r.status, r.read()
            except urllib.error.HTTPError as e: code, body = e.code, e.read()
            assert code == status, (endpoint, code, body)
            return json.loads(body)
        def wait_for(fn, timeout=12):
            deadline = time.monotonic()+timeout
            while time.monotonic()<deadline:
                if fn(): return
                time.sleep(.08)
            raise AssertionError('condition timed out')
        def start():
            nonlocal process
            process = subprocess.Popen([str(app), '--headless', '--no-update-check',
                f'--project={root / "projects/recovery-a"}', f'--control-port={control}',
                f'--proxy-port={free_port()}', f'--oast-port={free_port()}', f'--dns-port={free_port()}'],
                env={**os.environ, 'NULLOCK_DATA_DIR':str(root)}, stdout=log, stderr=log,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
            for _ in range(150):
                try: api('/api/snapshot'); return
                except OSError: assert process.poll() is None; time.sleep(.1)
            raise AssertionError('startup timeout')
        def check(name, condition):
            nonlocal checks
            assert condition, name; checks += 1; print('PASS', name, flush=True)
        def workspace(): return api('/api/sequencer/workspace')
        def patch(fields, revision=None):
            return api('/api/sequencer/workspace/patch', {'patch':fields,
                'textRevision':workspace()['textRevision'] if revision is None else revision})
        def saved():
            f = root/'projects/recovery-a/sequencer.json'
            return json.loads(f.read_text()) if f.exists() else {}
        try:
            start()
            raw = 'GET /capture HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n'
            patch({'text':'manual-one\nmanual-two', 'sigLevel':.05, 'capHost':'127.0.0.1',
                   'capPort':fixture.server_port, 'capTls':False, 'capRequest':raw,
                   'capExtractFrom':'header', 'capExtractKey':'X-Token', 'capCount':100, 'capThrottleMs':100})
            api('/api/repeater/set', {'host':'recovery.test', 'port':8080, 'tls':False, 'request':'GET /staged HTTP/1.1\r\nHost: recovery.test\r\n\r\n'})
            api('/api/intruder/set', {'host':'intruder-recovery.test', 'template':'GET /?q=§x§ HTTP/1.1\r\nHost: intruder-recovery.test\r\n\r\n', 'payloads':['one','two']})
            api('/api/sessions/setCookie', {'host':'recovery.test','name':'session','value':'saved-secret','path':'/'})
            wait_for(lambda: saved().get('draft',{}).get('text')=='manual-one\nmanual-two')
            check('draft and settings autosave without quitting', saved()['draft']['sigLevel']==.05)
            api('/api/scope/in/add', {'glob':'127.0.0.1'})
            api('/api/sequencer/capture/start', {'host':'127.0.0.1', 'port':fixture.server_port,'tls':False,
                'request':raw,'count':100,'throttleMs':100,'extract':{'from':'header','key':'X-Token'}})
            wait_for(lambda: len(saved().get('tokens',[]))>=2)
            persisted = saved(); process.kill(); process.wait(10); hits_before = len(hits)
            start(); restored = workspace()
            check('crash restores captured tokens and manually supplied corpus', restored['tokens']==persisted['tokens'] and restored['draft']['text']==persisted['draft']['text'])
            time.sleep(.3)
            check('recovery is idle and does not resume traffic', not restored['capture']['running'] and len(hits)==hits_before and 'interrupted' in restored['capture']['error'])
            snap = api('/api/snapshot')
            check('Repeater draft survives forced termination', snap['repeater']['host']=='recovery.test' and '/staged' in snap['repeater']['request'])
            check('Intruder draft survives forced termination', snap['intruder']['host']=='intruder-recovery.test')
            metadata = json.loads((root/'projects/recovery-a/project.json').read_text())
            check('cookie jar is saved before clean shutdown', 'saved-secret' in json.dumps(metadata['cookieJar']))
            revision = restored['textRevision']
            api('/api/sequencer/workspace/append', {'text':'peer-token'})
            conflict = api('/api/sequencer/workspace/patch', {'patch':{'text':'stale'}, 'textRevision':revision}, 409)
            check('stale corpus edit cannot erase another client’s append', 'changed' in conflict['error'] and workspace()['draft']['text'].endswith('peer-token'))
            patch({'capHost':'edited.test'})
            check('field patches preserve unrelated corpus and settings', workspace()['draft']['sigLevel']==.05 and workspace()['draft']['text'].endswith('peer-token'))
            before = workspace()['draft']; generation = api('/api/snapshot')['bootInfo']['historyGeneration']
            api('/api/project/create', {'name':'recovery-b'})
            check('new project has no old tokens or credentials in Sequencer', workspace()['draft']=={} and workspace()['tokens']==[])
            api('/api/sequencer/workspace/append', {'text':'old','historyGeneration':generation}, 409)
            check('delayed old-project write is rejected', workspace()['draft']=={})
            api('/api/project/open', {'name':'recovery-a'})
            check('project reopening restores its own Sequencer draft', workspace()['draft']==before)
            for filename in ['sequencer.json','project.json']:
                file = root/'projects/recovery-a'/filename; backup = file.with_suffix('.backup')
                wait_for(lambda: file.exists())
                file.rename(backup); file.mkdir()
                try:
                    if filename=='sequencer.json': patch({'capHost':'pending.test'})
                    else: api('/api/repeater/set', {'host':'pending-repeater.test'})
                    wait_for(lambda: bool(api('/api/snapshot')['bootInfo']['workspaceSaveError']))
                    failed = api('/api/project/open', {'name':'recovery-b'})
                    check(filename+' save failure retains current project', not failed['ok'] and api('/api/snapshot')['bootInfo']['project']=='recovery-a')
                    check(filename+' failure keeps previous valid file', bool(json.loads(backup.read_text())))
                finally: file.rmdir(); backup.rename(file)
                wait_for(lambda: not api('/api/snapshot')['bootInfo']['workspaceSaveError'])
                check(filename+' autosave retries after storage recovers', True)
            invalid = root/'projects/recovery-b/sequencer.json'; invalid.write_text('{bad')
            check('corrupt incoming Sequencer file is rejected before switching', not api('/api/project/open', {'name':'recovery-b'})['ok'] and api('/api/snapshot')['bootInfo']['project']=='recovery-a')
            invalid.write_text(json.dumps({'version':1,'draft':{'text':5},'tokens':[],'capture':{}}))
            check('wrong saved draft types are rejected', not api('/api/project/open', {'name':'recovery-b'})['ok'])
            api('/api/app/quit', {}); process.wait(15)
            check('clean exit reports successful workspace saves', process.returncode==0)
            print(f'{checks} workspace recovery checks passed', flush=True)
        except Exception:
            log.flush(); print((root/'app.log').read_text(encoding='utf-8',errors='replace')[-3000:]); raise
        finally:
            if process and process.poll() is None: process.kill(); process.wait(10)
            log.close(); fixture.shutdown(); fixture.server_close(); worker.join()


if __name__=='__main__': main()
