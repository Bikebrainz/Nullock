#!/usr/bin/env python3
"""Repeater CLI contract checks against an owned loopback API fixture."""
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

ROOT = Path(__file__).resolve().parents[1]
received = []
state = {'polls': 0, 'refuse': False, 'hold': False}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def reply(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        state['polls'] += 1
        busy = state['hold'] or state['polls'] < 3
        self.reply({'repeater': {'busy': busy, 'statusLine': 'pending' if busy else 'HTTP/1.1 200 OK',
                                  'response': 'old response' if busy else 'completed fixture'}})
    def do_POST(self):
        data = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        received.append((self.path, data, self.headers.get('X-Nullock-UI')))
        if self.path == '/api/repeater/send':
            state['polls'] = 0
            self.reply({'ok': not state['refuse'], 'error': 'Repeater busy'} if state['refuse'] else {'ok': True},
                       409 if state['refuse'] else 200)
        elif self.path == '/api/repeater/tab/addFromHistoryId':
            self.reply({'ok': False, 'error': 'History row not found'} if data['id'] == 999 else {'ok': True, 'index': 2})
        elif self.path == '/api/repeater/stop': self.reply({'ok': True})
        else: self.reply({'ok': True, 'index': 1})

def main():
    bash = os.environ.get('BASH_EXE') or shutil.which('bash')
    assert bash, 'bash is required'
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    env = {**os.environ, 'NULLOCK_API': f'http://127.0.0.1:{server.server_port}'}
    def run(*args, success=True, timeout=30, input_bytes=None):
        result = subprocess.run([bash, 'bin/nullock', 'repeater', *args], cwd=ROOT, env=env,
                                capture_output=True, input=input_bytes, timeout=timeout)
        result.stdout = result.stdout.decode('utf-8')
        result.stderr = result.stderr.decode('utf-8')
        assert (result.returncode == 0) == success, (args, result.returncode, result.stdout, result.stderr)
        return result
    try:
        raw = b'POST /bytes HTTP/1.1\r\nHost: fixture.test\r\n\r\n' + bytes(range(256)) + b'\n\n'
        with tempfile.TemporaryDirectory(prefix='nullock-cli-bytes-') as temporary:
            request = Path(temporary) / 'request bytes.bin'
            for content in [raw, b'']:
                request.write_bytes(content)
                for source in [request.as_posix(), '-']:
                    run('set', 'fixture.test', '80', 'false', source,
                        input_bytes=content if source == '-' else None)
                    path, payload, guard = received[-1]
                    assert path == '/api/repeater/set' and guard == '1'
                    assert base64.b64decode(payload['requestBase64'], validate=True) == content
                    assert 'request' not in payload and 'requestEncoding' not in payload
            count = len(received)
            run('set', 'fixture.test', '80', 'false', (Path(temporary) / 'missing').as_posix(), success=False)
            assert len(received) == count, 'unreadable input must not change the draft'
        run('set', 'fixture.test', '80', 'false')
        assert 'requestBase64' not in received[-1][1], 'omitting a file must preserve the current draft'
        print('PASS: files and stdin preserve all bytes, empty input and trailing newlines', flush=True)
        run('load', '17')
        assert received[-1] == ('/api/repeater/tab/addFromHistoryId', {'id': 17}, '1'), received[-1]
        assert 'History row not found' in run('load', '999', success=False).stderr
        count = len(received)
        for value in ['0', '-1', '1.5', '1, "host":"other.test"', 'one']:
            run('load', value, success=False)
        assert len(received) == count, 'invalid IDs must not make API requests'
        print('PASS: stable history IDs, missing rows and invalid CLI input', flush=True)
        response = json.loads(run('send').stdout)
        assert response['status'] == 'HTTP/1.1 200 OK' and response['response'] == 'completed fixture'
        assert state['polls'] >= 3
        print('PASS: asynchronous send survives multiple busy polls', flush=True)
        state['refuse'] = True
        assert 'Repeater busy' in run('send', success=False).stderr
        assert state['polls'] == 0, 'a refused send must not print a stale response'
        state['refuse'] = False
        state['hold'] = True
        result = run('send', success=False)
        assert 'still running' in result.stderr and not result.stdout.strip()
        print('PASS: rejected sends and wait exhaustion report failure', flush=True)
        run('stop')
        assert received[-1] == ('/api/repeater/stop', {}, '1')
        print('PASS: stop reaches the current Repeater cancellation API', flush=True)
    finally:
        server.shutdown(); server.server_close(); worker.join()

if __name__ == '__main__': main()
