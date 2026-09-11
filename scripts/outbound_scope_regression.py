#!/usr/bin/env python3
"""Exercise active-tool scope against owned loopback servers; denied traffic is counted."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread, Event


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('app', type=Path)
    app = parser.parse_args().app.resolve()
    checked = 0
    held, release = Event(), Event()

    class Server(ThreadingHTTPServer):
        daemon_threads = True
        def __init__(self):
            self.paths, self.connections = [], 0
            super().__init__(('127.0.0.1', 0), Handler)
        def get_request(self):
            conn, addr = super().get_request()
            self.connections += 1
            conn.settimeout(2)
            return conn, addr

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_GET(self):
            self.server.paths.append(self.path)
            if self.path == '/allowed/hold':
                held.set()
                release.wait(10)
            body = b'<a href="/allowed/child">yes</a><a href="/blocked">no</a>' if self.path == '/allowed/crawl' else b'fixture'
            redirects = {'/allowed/redirect-path':'/blocked', '/allowed/redirect-port':f'http://127.0.0.1:{denied.server_port}/allowed/ok', '/allowed/redirect-ok':'/allowed/ok'}
            self.send_response(302 if self.path in redirects else 200)
            if self.path in redirects: self.send_header('Location', redirects[self.path])
            self.send_header('X-Token', 'local-token')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        do_HEAD = do_GET

    allowed, denied = Server(), Server()
    servers = [allowed, denied]
    threads = [Thread(target=s.serve_forever, daemon=True) for s in servers]
    for t in threads: t.start()
    with tempfile.TemporaryDirectory(prefix='nullock-scope-') as tmp:
        root, control = Path(tmp), free_port()
        log = (root/'app.log').open('wb')
        process = subprocess.Popen([str(app), '--headless', '--no-update-check',
            f'--control-port={control}', f'--proxy-port={free_port()}',
            f'--oast-port={free_port()}', f'--dns-port={free_port()}'],
            env={**os.environ, 'NULLOCK_DATA_DIR':str(root)}, stdout=log, stderr=log,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        def api(path, data=None, status=200):
            request = urllib.request.Request(f'http://127.0.0.1:{control}'+path,
                data=None if data is None else json.dumps(data).encode(),
                headers={'Content-Type':'application/json', 'X-Nullock-UI':'1'})
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    code, body = response.status, response.read()
            except urllib.error.HTTPError as error:
                code, body = error.code, error.read()
            assert code == status, (path, code, body)
            return json.loads(body)
        def wait_for(predicate, timeout=15):
            deadline = time.monotonic()+timeout
            while time.monotonic()<deadline:
                if predicate(): return
                time.sleep(.04)
            raise AssertionError('condition timed out')
        def check(name, condition):
            nonlocal checked
            assert condition, name
            checked += 1
            print('PASS', name, flush=True)
        def rule(include=True, port=None, path='/allowed/.*', protocol=1):
            return {'enabled':True, 'include':include, 'host':r'127\.0\.0\.1',
                'portFrom':port or allowed.server_port, 'file':path, 'protocol':protocol}
        def scope(rules):
            assert api('/api/scope/advanced', {'rules':rules})['ok']
        def raw(path): return f'GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n'
        def repeat(path, port=None, tls=False, follow=0):
            assert api('/api/repeater/set', {'host':'127.0.0.1', 'port':port or allowed.server_port,
                'tls':tls, 'request':raw(path), 'followRedirects':follow})['ok']
            result = api('/api/repeater/send', {})
            # The send event is queued before the next snapshot connection.
            return result, api('/api/snapshot')['repeater']
        def intrude(template, payloads):
            api('/api/intruder/load', {})
            api('/api/intruder/set', {'host':'127.0.0.1', 'port':allowed.server_port, 'tls':False,
                'template':raw(template), 'payloads':payloads, 'concurrency':1, 'retries':0})
            assert api('/api/intruder/start', {})['ok']
        try:
            for _ in range(180):
                try:
                    api('/api/snapshot'); break
                except OSError:
                    assert process.poll() is None, 'app exited'
                    time.sleep(.1)
            else: raise AssertionError('startup timeout')
            api('/api/scope/in/add', {'glob':'127.0.0.1'})
            scope([rule(), rule(False, path='/allowed/private.*')])
            before = api('/api/snapshot')['scope']['advanced']
            for invalid in [[{**rule(), 'file':'['}], [rule(), {'include':False,'host':'['}],
                            [rule(port=70000)], [rule(protocol=99)], [rule()]*257,
                            [42], [{'host':True}], [{'portFrom':1.5}], 'not an array']:
                result = api('/api/scope/advanced', {'rules':invalid}, status=400)
                check('invalid scope edit rejected and previous rules preserved', not result['ok'] and api('/api/snapshot')['scope']['advanced']==before)
            repeat('/allowed/ok?query=/blocked')
            check('allowed sibling path survives partial host exclusion', allowed.paths == ['/allowed/ok?query=/blocked'])
            before = allowed.connections
            for path in ['/blocked', '/allowed/private', '/allowed/%70rivate', '/allowed/../blocked', '/allowed/%2e%2e/blocked']:
                _, result = repeat(path)
                check('Repeater blocks '+path, 'scope' in json.dumps(result).lower() and allowed.connections == before)
            repeat('/allowed/ok', port=denied.server_port)
            check('wrong port receives no connection', denied.connections == 0)
            repeat('/allowed/ok', tls=True)
            check('wrong scheme receives no TLS connection', allowed.connections == before)
            for policy in [1,2,3]:
                for suffix in ['path','port']:
                    seen = len(allowed.paths)
                    repeat('/allowed/redirect-'+suffix, follow=policy)
                    check(f'redirect policy {policy} respects {suffix} boundary', allowed.paths[seen:] == ['/allowed/redirect-'+suffix] and denied.connections == 0)
            seen = len(allowed.paths)
            repeat('/allowed/redirect-ok', follow=2)
            check('in-scope redirect reaches allowed destination', allowed.paths[seen:] == ['/allowed/redirect-ok','/allowed/ok'])
            seen = len(allowed.paths)
            intrude('/§item§', ['allowed/one','blocked','allowed/private','allowed/two'])
            wait_for(lambda: not api('/api/snapshot')['intruder']['running'])
            rows = api('/api/intruder/export')['rows']
            check('Intruder checks each generated payload URL', allowed.paths[seen:] == ['/allowed/one','/allowed/two'] and sum('scope' in row['err'].lower() for row in rows)==2)
            seen = len(allowed.paths)
            intrude('/allowed/§item§', ['hold','after'])
            assert held.wait(10)
            scope([rule(False, path='/allowed/.*')])
            release.set()
            wait_for(lambda: not api('/api/snapshot')['intruder']['running'])
            check('scope edits affect the next queued send', allowed.paths[seen:] == ['/allowed/hold'])
            scope([rule(), rule(False, path='/allowed/private.*')])
            seen = len(allowed.paths)
            assert api('/api/crawler/start', {'seed':f'http://127.0.0.1:{allowed.server_port}/allowed/crawl','maxPages':5,'maxDepth':1,'throttleMs':0})['ok']
            wait_for(lambda: not api('/api/snapshot')['crawler']['running'])
            check('crawler visits only allowed seed and links', allowed.paths[seen:] == ['/allowed/crawl','/allowed/child'])
            before = allowed.connections
            result = api('/api/crawler/start', {'seed':f'http://127.0.0.1:{allowed.server_port}/blocked'})
            check('crawler refuses excluded seed', not result['ok'] and allowed.connections==before)
            for endpoint, body in [('/api/fingerprint',{'url':f'http://127.0.0.1:{allowed.server_port}/blocked'}),
                ('/api/cswsh/test',{'url':f'ws://127.0.0.1:{allowed.server_port}/blocked'}),
                ('/api/tls/inspect',{'host':'127.0.0.1','port':allowed.server_port,'timeoutMs':100}),
                ('/api/servicevulns/scan',{'host':'127.0.0.1','ports':[allowed.server_port],'timeoutMs':100})]:
                result = api(endpoint, body)
                check(endpoint+' checks before connecting', allowed.connections==before and 'scope' in json.dumps(result).lower())
            assert api('/api/portscan/start', {'host':'127.0.0.1','ports':[allowed.server_port,denied.server_port],'timeoutMs':100,'banner':False})['ok']
            wait_for(lambda: not api('/api/snapshot')['portScan']['running'])
            check('raw port scans cannot use path-limited grant', allowed.connections==before and denied.connections==0)
            seq = {'host':'127.0.0.1','port':allowed.server_port,'tls':False,'request':raw('/blocked'),
                'count':1,'extract':{'from':'header','key':'X-Token'}}
            result = api('/api/sequencer/capture/start', seq)
            check('Sequencer rejects excluded URL', not result['ok'] and allowed.connections==before)
            seq['request']=raw('/allowed/seq')
            assert api('/api/sequencer/capture/start', seq)['ok']
            wait_for(lambda: not api('/api/snapshot')['sequencerCapture']['running'])
            check('Sequencer can capture allowed sibling', '/allowed/seq' in allowed.paths)
            before=allowed.connections
            result=api('/api/chain/run', {'steps':[{'host':'127.0.0.1','port':allowed.server_port,'tls':False,'request':raw('/blocked')}]})
            check('chain checks actual request target', allowed.connections==before and 'scope' in json.dumps(result).lower())
            scope([rule(path='',protocol=0)])
            before=allowed.connections
            api('/api/portscan/start', {'host':'127.0.0.1','ports':[allowed.server_port,denied.server_port],'timeoutMs':100,'banner':False})
            wait_for(lambda: not api('/api/snapshot')['portScan']['running'])
            check('whole endpoint grant permits correct raw port only', allowed.connections==before+1 and denied.connections==0)
            check('no excluded HTTP path reached either server', all(p.startswith('/allowed/') for p in allowed.paths) and not denied.paths)
            # A malformed imported project must deny rather than drop its rules.
            invalid_dir = root/'projects'/'invalid-scope'
            invalid_dir.mkdir(parents=True)
            (invalid_dir/'project.json').write_text(json.dumps({'name':'invalid-scope',
                'inScope':['127.0.0.1'], 'advancedScope':[{'host':'[','include':False}]}))
            assert api('/api/project/open', {'name':'invalid-scope'})['ok']
            check('crawler state clears across projects', api('/api/snapshot')['crawler']['seed']=='' and api('/api/snapshot')['crawler']['visited']==0)
            check('stale scope edit is rejected', not api('/api/scope/advanced', {'rules':[], 'historyGeneration':'stale'}, status=409)['ok'])
            before = allowed.connections
            denied_send, _ = repeat('/allowed/ok')
            check('invalid saved scope blocks active requests visibly', not denied_send['ok']
                and allowed.connections==before and api('/api/snapshot')['scope']['validationError'])
            api('/api/app/quit', {})
            process.wait(15)
            assert process.returncode==0
            print(f'{checked} outbound scope checks passed', flush=True)
        except Exception:
            log.flush()
            print((root/'app.log').read_text(encoding='utf-8',errors='replace')[-2500:])
            raise
        finally:
            release.set()
            if process.poll() is None: process.terminate(); process.wait(15)
            log.close()
            for s in servers: s.shutdown(); s.server_close()
            for t in threads: t.join()

if __name__=='__main__': main()
