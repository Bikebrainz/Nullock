#!/usr/bin/env python3
"""Verify project-scoped Intruder workspaces using temporary local profiles."""
import argparse
import copy
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
from threading import Event, Thread, Timer


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('app', type=Path)
    args = parser.parse_args()
    app = args.app.resolve()
    checks = 0
    with tempfile.TemporaryDirectory(prefix='nullock-intruder-workspace-') as temporary:
        root = Path(temporary)
        control = free_port()
        process = None
        log = (root / 'app.log').open('wb')

        def api(path, data=None, status=200):
            request = urllib.request.Request(f'http://127.0.0.1:{control}' + path,
                data=None if data is None else json.dumps(data).encode(),
                headers={'Content-Type':'application/json', 'X-Nullock-UI':'1'})
            try:
                with urllib.request.urlopen(request, timeout=15) as response:
                    code, body = response.status, response.read()
            except urllib.error.HTTPError as error:
                code, body = error.code, error.read()
            assert code == status, (path, code, body)
            return json.loads(body)

        def start(project=None):
            nonlocal process
            arguments = [str(app), '--headless', '--no-update-check',
                f'--control-port={control}', f'--proxy-port={free_port()}',
                f'--oast-port={free_port()}', f'--dns-port={free_port()}']
            if project:
                arguments.append('--project=' + str(root / 'projects' / project))
            process = subprocess.Popen(arguments, env={**os.environ, 'NULLOCK_DATA_DIR':str(root)},
                stdout=log, stderr=log, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            for _ in range(150):
                if process.poll() is not None:
                    raise RuntimeError('App exited during startup')
                try:
                    api('/api/snapshot')
                    return
                except OSError:
                    time.sleep(.1)
            raise RuntimeError('App did not start')

        def stop():
            api('/api/app/quit', {})
            process.wait(timeout=15)
            assert process.returncode == 0

        def check(name, condition):
            nonlocal checks
            assert condition, name
            checks += 1
            print('PASS', name, flush=True)

        def exported():
            return api('/api/intruder/export')

        try:
            start()
            defaults = exported()
            assert api('/api/project/create', {'name':'workspace-a'})['ok']
            draft = copy.deepcopy(defaults)
            draft['config'].update({
                'host':'workspace.test', 'port':8080, 'tls':False,
                'template':'POST /review?q=§seed§ HTTP/1.1\r\nHost: workspace.test\r\n\r\n\x00\xff',
                'requestLatin1':True, 'attackType':2, 'payloadSets':['first\nsecond', 'A\nB'],
                'rules':[{'op':'prefix', 'arg':'project-a-prefix'}],
                'grepMatch':['project-a-match'], 'grepPayloadReflection':True,
                'grepExtract':{'regex':'token=(.+)', 'start':'start', 'end':'end'},
                'concurrency':2, 'throttleMs':37, 'retries':1, 'globalEncodeChars':'&=',
                'recursiveGrep':True, 'recursiveGrepSeed':'project-a-seed', 'recursiveGrepCount':7,
                'followPolicy':2, 'followCookies':False,
            })
            draft['rows'] = [{'id':1, 'payloads':['first', 'A'], 'combo':['first', None],
                'status':200, 'size':17, 'ms':4, 'err':'', 'complete':True,
                'matched':True, 'reflected':False, 'extracted':'fixture-token'},
                {'id':2, 'payloads':['second', 'B'], 'combo':['second', 'B'],
                'status':0, 'size':0, 'ms':0, 'err':'', 'complete':False,
                'matched':False, 'reflected':False, 'extracted':''}]
            assert api('/api/intruder/load', draft)['ok']
            expected = exported()
            check('all staged configuration fields loaded', expected['config'] == draft['config'])
            assert api('/api/project/create', {'name':'workspace-b'})['ok']
            check('new project resets every Intruder field', exported() == defaults)
            assert api('/api/project/open', {'name':'workspace-a'})['ok']
            check('project reopen restores complete configuration and binary template', exported() == expected)
            check('completed and pending rows retain results and null payload combinations', exported()['rows'] == draft['rows'])
            check('restoring a workspace does not start traffic', not api('/api/snapshot')['intruder']['running'])
            assert api('/api/intruder/set', {'host':'changed.workspace.test'})['ok']
            expected = exported()
            assert api('/api/project/open', {'name':'workspace-a'})['ok']
            check('reopening the active project preserves its latest draft', exported() == expected)
            stop()
            start('workspace-a')
            check('startup restores the explicitly selected project', exported() == expected)
            check('startup leaves the restored attack idle', not api('/api/snapshot')['intruder']['running'])

            saved_path = root / 'projects/workspace-a/intruder.json'
            backup = saved_path.with_suffix('.saved')
            saved_path.rename(backup)
            saved_path.mkdir()
            generation = api('/api/snapshot')['bootInfo']['historyGeneration']
            try:
                response = api('/api/project/open', {'name':'workspace-b'})
                check('failed workspace save refuses project switch', not response['ok'])
                check('failed switch retains draft and history generation', exported() == expected
                    and api('/api/snapshot')['bootInfo']['historyGeneration'] == generation)
            finally:
                saved_path.rmdir()
                backup.rename(saved_path)

            corrupt = root / 'projects/workspace-b/intruder.json'
            original = corrupt.read_bytes() if corrupt.exists() else None
            corrupt.write_text('{invalid', encoding='utf-8')
            try:
                check('malformed incoming workspace is rejected before clearing the current draft',
                    not api('/api/project/open', {'name':'workspace-b'})['ok'] and exported() == expected)
            finally:
                if original is None:
                    corrupt.unlink()
                else:
                    corrupt.write_bytes(original)
            assert api('/api/project/open', {'name':'workspace-b'})['ok']
            check('other project remains independently blank after restart', exported() == defaults)
            assert api('/api/project/open', {'name':'workspace-a'})['ok']
            assert api('/api/clear-history', {})['ok']
            check('clearing captured history retains the independently staged workspace', exported() == expected)
            assert api('/api/intruder/load', {})['ok']
            stop()
            start('workspace-a')
            check('explicitly reset workspace stays clear after clean restart', exported() == defaults)
            entered, release = Event(), Event()
            class Fixture(BaseHTTPRequestHandler):
                def log_message(self, *_):
                    pass
                def do_GET(self):
                    entered.set()
                    release.wait(timeout=10)
                    self.send_response(200)
                    self.send_header('Content-Length', '7')
                    self.end_headers()
                    self.wfile.write(b'fixture')
            fixture = ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
            thread = Thread(target=fixture.serve_forever, daemon=True)
            thread.start()
            try:
                assert api('/api/scope/in/add', {'glob':'127.0.0.1'})['ok']
                assert api('/api/intruder/set', {'host':'127.0.0.1', 'port':fixture.server_port,
                    'tls':False, 'template':'GET /§one§ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n',
                    'payloads':['one'], 'concurrency':1})['ok']
                assert api('/api/intruder/start', {})['ok']
                assert entered.wait(timeout=10), 'Local request did not start'
                check('active Intruder request still blocks project changes',
                    not api('/api/project/open', {'name':'workspace-b'})['ok'])
                timer = Timer(.3, release.set)
                timer.start()
                stop()
                timer.join()
                last = json.loads(saved_path.read_text(encoding='utf-8'))
                check('shutdown saves results after the last worker response is drained',
                    len(last['rows']) == 1 and last['rows'][0]['complete'] and last['rows'][0]['status'] == 200)
            finally:
                release.set()
                fixture.shutdown()
                fixture.server_close()
                thread.join()
            start('workspace-a')
            check('completed shutdown workspace restores idle with its final result',
                exported() == last and not api('/api/snapshot')['intruder']['running'])
            stop()
            print(f'{checks} Intruder workspace checks passed', flush=True)
        except Exception:
            log.flush()
            print((root / 'app.log').read_text(encoding='utf-8', errors='replace')[-4000:])
            raise
        finally:
            if process and process.poll() is None:
                process.terminate()
                process.wait(timeout=15)
            log.close()


if __name__ == '__main__':
    main()
