#!/usr/bin/env python3
"""Verify Repeater response bytes, history and persistence against an owned fixture."""
import argparse
import base64
import gzip
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from annotations_regression import free_port


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('app', type=Path)
    app = parser.parse_args().app.resolve()
    binary = bytes(range(256)) * 300 + b'\x00\xff\x80A\n\n'
    fixtures = {}
    for name, body, encoding in [('binary', binary, ''), ('empty', b'', ''),
                                 ('gzip', binary, 'gzip'), ('gzip-empty', b'', 'gzip'),
                                 ('invalid-gzip', binary, 'invalid')]:
        wire_body = gzip.compress(body, mtime=0) if encoding == 'gzip' else body
        header = (f'HTTP/1.1 200 OK\r\nContent-Length: {len(wire_body)}\r\n'
                  'Content-Type: application/octet-stream\r\nConnection: close\r\n')
        if encoding:
            header += 'Content-Encoding: gzip\r\n'
        fixtures['/' + name] = ((header + '\r\n').encode() + wire_body, body, encoding == 'gzip')
    chunks = b''.join(f'{len(chunk):x}\r\n'.encode() + chunk + b'\r\n'
                      for chunk in [binary[:200], binary[200:]]) + b'0\r\nX-Trailer: done\r\n\r\n'
    fixtures['/chunked'] = (b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n'
                            b'Connection: close\r\n\r\n' + chunks, binary, False)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_GET(self):
            self.wfile.write(fixtures[self.path][0])
            self.close_connection = True

    fixture = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    Thread(target=fixture.serve_forever, daemon=True).start()
    with tempfile.TemporaryDirectory(prefix='nullock-repeater-bytes-') as temporary:
        root = Path(temporary)
        control = free_port()
        process = None
        log = (root / 'app.log').open('wb')

        def api(path, data=None):
            request = urllib.request.Request(f'http://127.0.0.1:{control}' + path,
                data=None if data is None else json.dumps(data).encode(),
                headers={'Content-Type': 'application/json', 'X-Nullock-UI': '1'})
            with urllib.request.urlopen(request, timeout=15) as response:
                return json.load(response)

        def snapshot(): return api('/api/snapshot')['repeater']

        def start():
            nonlocal process
            process = subprocess.Popen([str(app), '--headless', '--no-update-check',
                f'--project={root / "projects/bytes-a"}', f'--control-port={control}',
                f'--proxy-port={free_port()}', f'--oast-port={free_port()}', f'--dns-port={free_port()}'],
                env={**os.environ, 'NULLOCK_DATA_DIR': str(root)}, stdout=log, stderr=log,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            for _ in range(150):
                assert process.poll() is None, 'app exited during startup'
                try: snapshot(); return
                except OSError: time.sleep(.1)
            raise AssertionError('app did not start')

        def stop():
            api('/api/app/quit', {})
            process.wait(timeout=15)

        def verify(path):
            rep = snapshot()
            wire, body, decoded = fixtures[path]
            assert base64.b64decode(rep['responseWireBase64'], validate=True) == wire, path + ' wire bytes'
            assert base64.b64decode(rep['responseBodyBase64'], validate=True) == body, path + ' body bytes'
            assert rep['responseBodyDecoded'] == decoded, path + ' decoding flag'
            assert rep['responseBytes'] == len(wire), path + ' wire byte count'
            assert rep['response'].split('\r\n\r\n', 1)[1] == body.decode('utf-8', errors='replace'), path + ' text view'

        def empty():
            rep = snapshot()
            assert rep['responseWireBase64'] == rep['responseBodyBase64'] == rep['response'] == ''
            assert not rep['responseBodyDecoded'] and rep['responseBytes'] == -1

        try:
            start()
            empty()
            for path in fixtures:
                api('/api/repeater/set', {'host': '127.0.0.1', 'port': fixture.server_port, 'tls': False,
                    'request': f'GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n'})
                api('/api/repeater/send', {})
                deadline = time.monotonic() + 15
                while snapshot()['busy']:
                    assert time.monotonic() < deadline, 'send timed out'
                    time.sleep(.05)
                verify(path)
            print('PASS: all 256 byte values, large/NUL/invalid UTF-8, empty, gzip and chunked responses retain exact bytes', flush=True)
            for index, path in enumerate(fixtures):
                api('/api/repeater/history/load', {'index': index})
                verify(path)
            print('PASS: every history entry restores its wire bytes, body and decoding state', flush=True)
            api('/api/repeater/history/load', {'index': 2})
            verify('/gzip')
            api('/api/repeater/tab/duplicate', {'index': 0})
            empty()
            api('/api/repeater/tab/activate', {'index': 0})
            verify('/gzip')
            assert api('/api/project/create', {'name': 'bytes-b'})['ok']
            empty()
            assert api('/api/project/open', {'name': 'bytes-a'})['ok']
            verify('/gzip')
            assert snapshot()['tabs'][0]['historyCount'] == 0, 'past sends stay session-only'
            stop()
            start()
            verify('/gzip')
            print('PASS: project switching and app restart preserve the current response without resending; duplicate starts empty', flush=True)
            # Failed encoding must not expose bytes from the previous successful send.
            api('/api/repeater/set', {'request': 'GET /\u20ac HTTP/1.1\r\n\r\n', 'requestEncoding': 'latin1'})
            api('/api/repeater/send', {})
            deadline = time.monotonic() + 15
            while snapshot()['busy']:
                assert time.monotonic() < deadline
                time.sleep(.05)
            rep = snapshot()
            assert 'outside Latin-1' in rep['response']
            assert rep['responseWireBase64'] == rep['responseBodyBase64'] == ''
            assert not rep['responseBodyDecoded']
            api('/api/repeater/clear', {})
            empty()
            stop()
            start()
            empty()
            print('PASS: encoding failures and clear discard stale bytes, including after reload', flush=True)
            stop()
        finally:
            if process and process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            log.close()
            fixture.shutdown()
            fixture.server_close()


if __name__ == '__main__':
    main()
