#!/usr/bin/env python3
"""Exercise CLI JSON escaping, patch semantics and failure exit codes locally."""
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
workspace = {'version':1, 'config':{'host':'fixture.test', 'template':'quoted "request"\n雪'}, 'rows':[]}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == '/api/snapshot':
            self.reply({'bootInfo': {'historyGeneration': 'project-generation'}})
        elif self.path == '/api/history/annotations':
            self.reply({'ok': True, 'annotations': {'1': {'comment': 'saved'}}})
        elif self.path == '/api/intruder/export':
            self.reply(workspace)
        else:
            self.reply({'ok': False}, 404)

    def do_POST(self):
        data = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        received.append((self.path, data, self.headers.get('X-Nullock-UI')))
        if self.path == '/api/intruder/load':
            self.reply({'ok':data.get('config', {}).get('host') != 'refused.test'})
            return
        if data['id'] == 2:
            self.reply({'ok': False, 'error': 'Project history changed'}, 409)
        else:
            self.reply({'ok': True, 'annotations': {'1': data}})


def main():
    bash = os.environ.get('BASH_EXE') or shutil.which('bash')
    assert bash, 'bash is required'
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    env = {**os.environ, 'NULLOCK_API': f'http://127.0.0.1:{server.server_port}'}

    def run(*args, success=True):
        result = subprocess.run([bash, 'bin/nullock', *args], cwd=ROOT, env=env,
                                capture_output=True, text=True, encoding='utf-8', timeout=15)
        assert (result.returncode == 0) == success, result.stdout + result.stderr
        return result

    try:
        special = 'review "quoted" \\ path\n$(literal) `literal` <tag> café 雪 😀'
        run('history-note', '1', '--comment', special)
        assert received[-1] == ('/api/history/annotation', {
            'id': 1, 'historyGeneration': 'project-generation', 'comment': special}, '1')
        run('history-note', '1', '--color', 'purple')
        assert 'comment' not in received[-1][1]
        run('history-note', '1', '--clear')
        assert received[-1][1]['comment'] == received[-1][1]['color'] == ''
        assert json.loads(run('history-notes').stdout)['annotations']['1']['comment'] == 'saved'
        assert 'Project history changed' in run('history-note', '2', '--color', 'red', success=False).stderr
        count = len(received)
        for args in [('0', '--clear'), ('1.5', '--clear'), ('1',), ('1', '--comment'), ('1', '--unknown')]:
            run('history-note', *args, success=False)
        assert len(received) == count, 'invalid arguments must not mutate the server'
        print('PASS: CLI escaping, field patches, clear/list, stale edits and invalid arguments')
        assert json.loads(run('intruder', 'save').stdout) == workspace
        run('intruder', 'reset')
        assert received[-1] == ('/api/intruder/load', {}, '1')
        with tempfile.TemporaryDirectory(prefix='nullock-cli-workspace-') as temporary:
            saved = Path(temporary) / 'attack.json'
            saved.write_text(json.dumps(workspace), encoding='utf-8')
            run('intruder', 'load', saved.as_posix())
            assert received[-1] == ('/api/intruder/load', workspace, '1'), received[-1]
            saved.write_text('{"config":{"host":"refused.test"},"rows":[]}', encoding='utf-8')
            assert 'refused' in run('intruder', 'load', saved.as_posix(), success=False).stderr
            count = len(received)
            for invalid in ['{invalid', '[]', '{"config":{}}', 'null']:
                saved.write_text(invalid, encoding='utf-8')
                run('intruder', 'load', saved.as_posix(), success=False)
            assert len(received) == count
        print('PASS: CLI workspace save/load/reset, Unicode/quotes, server refusals and malformed files')
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == '__main__':
    main()
