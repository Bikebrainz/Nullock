#!/usr/bin/env python3
"""Run the Repeater CLI against an isolated app and loopback HTTP fixture."""
import argparse
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from annotations_regression import free_port

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('app', type=Path)
    app = parser.parse_args().app.resolve()
    bash = os.environ.get('BASH_EXE') or shutil.which('bash')
    assert bash, 'bash is required'
    received = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            received.append((self.path, body))
            # The CLI must survive more than one busy snapshot.
            time.sleep(.8)
            self.send_response(200)
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b'OK')

    fixture = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    worker = Thread(target=fixture.serve_forever, daemon=True)
    worker.start()
    with tempfile.TemporaryDirectory(prefix='nullock-cli-repeater-') as temporary:
        root = Path(temporary)
        control = free_port()
        base = f'http://127.0.0.1:{control}'
        env = {**os.environ, 'NULLOCK_DATA_DIR': str(root), 'NULLOCK_API': base, 'NULLOCK_NO_UPDATE': '1'}
        process = None
        log = (root/'app.log').open('wb')

        def api(path, data=None):
            request = urllib.request.Request(base + path,
                data=None if data is None else json.dumps(data).encode(),
                headers={'Content-Type': 'application/json', 'X-Nullock-UI': '1'})
            with urllib.request.urlopen(request, timeout=10) as response:
                return json.load(response)

        def cli(*args, success=True, input_bytes=None):
            result = subprocess.run([bash, 'bin/nullock', 'repeater', *args], cwd=ROOT, env=env,
                capture_output=True, input=input_bytes, timeout=25)
            result.stdout = result.stdout.decode('utf-8')
            result.stderr = result.stderr.decode('utf-8')
            assert (result.returncode == 0) == success, (args, result.stdout, result.stderr)
            return result

        def entry(path, body):
            return {
                'startedDateTime': '2026-09-29T00:00:00.000Z',
                'request': {'method': 'POST', 'url': f'http://127.0.0.1:{fixture.server_port}{path}',
                    'httpVersion': 'HTTP/1.1',
                    'headers': [{'name': 'Content-Type', 'value': 'application/octet-stream'}],
                    'postData': {'mimeType': 'application/octet-stream', '_encoding': 'base64',
                                 'text': base64.b64encode(body).decode()}},
                'response': {'status': 200, 'statusText': 'OK', 'httpVersion': 'HTTP/1.1',
                             'headers': [], 'content': {'mimeType': 'text/plain', 'text': 'OK'}},
            }

        try:
            process = subprocess.Popen([str(app), '--headless', '--no-update-check',
                f'--control-port={control}', f'--proxy-port={free_port()}',
                f'--oast-port={free_port()}', f'--dns-port={free_port()}'],
                env=env, stdout=log, stderr=log,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            for _ in range(150):
                assert process.poll() is None, 'app exited during startup'
                try: api('/api/snapshot'); break
                except OSError: time.sleep(.1)
            else: raise AssertionError('app did not start')
            first = b'\x00\xff\x80\n\r\n' + b'A' * 70000
            second = b'second captured request'
            assert api('/api/har/import', {'har': {'log': {'version': '1.2',
                'entries': [entry('/first', first), entry('/second', second)]}}})['ok']
            rows = api('/api/snapshot')['rows']
            assert [row['id'] for row in rows] == [1, 2]
            cli('load', '1')
            repeater = api('/api/snapshot')['repeater']
            assert repeater['request'].startswith('POST /first ')
            assert repeater['requestEncoding'] == 'latin1'
            result = json.loads(cli('send').stdout)
            assert '200' in result['status'] and result['response'].endswith('OK')
            assert received == [('/first', first)], 'history ID must select the exact full binary request'
            print('PASS: CLI loads the stable history ID and sends all binary bytes after async polling', flush=True)
            cli('load', '2')
            before = api('/api/snapshot')['repeater']
            assert before['request'].startswith('POST /second ')
            assert 'History row not found' in cli('load', '999', success=False).stderr
            after = api('/api/snapshot')['repeater']
            assert after['request'] == before['request'] and after['activeTab'] == before['activeTab']
            cli('stop')
            print('PASS: another ID selects its request; missing IDs fail without replacing the draft', flush=True)
            binary = bytes(range(256)) * 300 + b'\x00\xff\n\n'
            request = (f'POST /file HTTP/1.1\r\nHost: 127.0.0.1:{fixture.server_port}\r\n'
                       f'Content-Length: {len(binary)}\r\n\r\n').encode() + binary
            request_file = root / 'request bytes.bin'
            request_file.write_bytes(request)
            for source in [request_file.as_posix(), '-']:
                cli('set', '127.0.0.1', str(fixture.server_port), 'false', source,
                    input_bytes=request if source == '-' else None)
                loaded = api('/api/snapshot')['repeater']
                assert loaded['request'].encode('latin1') == request
                assert loaded['requestEncoding'] == 'latin1'
                cli('send')
                assert received[-1] == ('/file', binary), 'file and stdin must send every original body byte'
            print('PASS: file and stdin send 76,804 bytes including NUL, invalid UTF-8 and trailing newlines', flush=True)
            before = api('/api/snapshot')['repeater']
            for invalid in [None, 123, '!!!', 'YQ=', 'YQ===', '\u00e9', {'nested': 'bad'}]:
                try:
                    api('/api/repeater/set', {'host': 'changed.invalid', 'requestBase64': invalid})
                    raise AssertionError(f'invalid base64 accepted: {invalid!r}')
                except urllib.error.HTTPError as error:
                    assert error.code == 400
                after = api('/api/snapshot')['repeater']
                assert after['request'] == before['request'] and after['host'] == before['host']
            for extra in [{'request': 'ambiguous'}, {'requestEncoding': 'utf8'}]:
                try:
                    api('/api/repeater/set', {'requestBase64': 'YQ==', **extra})
                    raise AssertionError('ambiguous encoding accepted')
                except urllib.error.HTTPError as error:
                    assert error.code == 400
            cli('set', '127.0.0.1', str(fixture.server_port), 'false')
            assert api('/api/snapshot')['repeater']['request'] == before['request']
            request_file.write_bytes(b'')
            cli('set', '127.0.0.1', str(fixture.server_port), 'false', request_file.as_posix())
            assert api('/api/snapshot')['repeater']['request'] == ''
            unicode_body = 'caf\u00e9 \u2603\n\n'
            unicode_request = (f'POST /utf8 HTTP/1.1\r\nHost: 127.0.0.1:{fixture.server_port}\r\n'
                               f'Content-Length: {len(unicode_body.encode())}\r\n\r\n' + unicode_body)
            cli('set', '127.0.0.1', str(fixture.server_port), 'false', '-', input_bytes=unicode_request.encode())
            loaded = api('/api/snapshot')['repeater']
            assert loaded['request'] == unicode_request and loaded['requestEncoding'] == 'utf8'
            cli('send')
            assert received[-1] == ('/utf8', unicode_body.encode())
            assert api('/api/repeater/set', {'request': unicode_request, 'requestEncoding': 'utf8'})['ok']
            assert api('/api/snapshot')['repeater']['request'] == unicode_request
            print('PASS: invalid or ambiguous base64 preserves the draft; an empty file explicitly clears it', flush=True)
            print('PASS: valid UTF-8 stays readable and legacy text input remains supported', flush=True)
            api('/api/app/quit', {})
            assert process.wait(timeout=15) == 0
        except Exception:
            log.flush()
            print((root/'app.log').read_text(errors='replace')[-3500:])
            raise
        finally:
            if process and process.poll() is None:
                process.terminate(); process.wait(timeout=10)
            log.close()
            fixture.shutdown(); fixture.server_close(); worker.join()


if __name__ == '__main__': main()
