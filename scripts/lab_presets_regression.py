#!/usr/bin/env python3
"""Validate every lab preset, optionally load each in the app and test owned-port isolation."""
import argparse
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

ROOT = Path(__file__).resolve().parents[1]


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('app', nargs='?', type=Path)
    app = parser.parse_args().app
    presets = []
    for path in sorted((ROOT / 'labs').glob('*/.nullock-project.json')):
        preset = json.loads(path.read_text(encoding='utf-8'))
        assert preset['inScope'] == ['localhost', '127.0.0.1'], path
        rules = preset['advancedScope']
        assert len(rules) == 1, path
        rule = rules[0]
        port = 5000 + int(path.parent.name.split('-')[0])
        assert rule == dict(enabled=True, include=True, host=r'(localhost|127\.0\.0\.1)',
                            portFrom=port, portTo=port, protocol=0, file=''), path
        assert re.fullmatch(rule['host'], 'localhost') and re.fullmatch(rule['host'], '127.0.0.1')
        assert not re.fullmatch(rule['host'], 'localhost.example.test')
        published = ROOT / 'docs/labs' / (path.parent.name + '.project.json')
        assert json.loads(published.read_text(encoding='utf-8')) == preset, path
        page = (ROOT / 'docs/labs' / (path.parent.name + '.html')).read_text(encoding='utf-8')
        assert f'href="{path.parent.name}.project.json" download="project.json"' in page
        presets.append((path.parent.name, preset, port))
    assert presets, 'no presets found'
    print(f'PASS: {len(presets)} source/download presets have exact host and port restrictions', flush=True)
    if app is None:
        return

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_GET(self):
            self.server.paths.append(self.path)
            body = b'owned lab fixture'
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    # Bind our own fixture before attempting any traffic. Skip occupied lab ports.
    allowed = None
    for slug, preset, port in presets:
        try:
            allowed = ThreadingHTTPServer(('127.0.0.1', port), Handler)
            selected = slug
            break
        except OSError:
            continue
    assert allowed is not None, 'no available owned lab port'
    denied = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    servers = [allowed, denied]
    for server in servers:
        server.paths = []
        Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix='nullock-lab-presets-') as tmp:
            root = Path(tmp)
            for slug, preset, port in presets:
                project = root / 'projects' / slug
                project.mkdir(parents=True)
                (project / 'project.json').write_text(json.dumps(preset), encoding='utf-8')
            control = free_port()
            with (root / 'app.log').open('wb') as log:
                process = subprocess.Popen([str(app.resolve()), '--headless', '--no-update-check',
                    f'--project={root / "projects" / selected}', f'--control-port={control}',
                    f'--proxy-port={free_port()}', f'--oast-port={free_port()}', f'--dns-port={free_port()}'],
                    env={**os.environ, 'NULLOCK_DATA_DIR': str(root)}, stdout=log, stderr=log,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
                def api(path, data=None):
                    req = urllib.request.Request(f'http://127.0.0.1:{control}' + path,
                        data=None if data is None else json.dumps(data).encode(),
                        headers={'Content-Type': 'application/json', 'X-Nullock-UI': '1'})
                    with urllib.request.urlopen(req, timeout=15) as response:
                        return json.load(response)
                try:
                    for _ in range(180):
                        try:
                            api('/api/snapshot')
                            break
                        except OSError:
                            assert process.poll() is None, 'app exited'
                            time.sleep(.1)
                    else:
                        raise AssertionError('startup timeout')
                    for slug, preset, port in presets:
                        assert api('/api/project/open', {'name': slug})['ok'], slug
                        scope = api('/api/snapshot')['scope']
                        assert not scope.get('validationError'), (slug, scope)
                        assert scope['advanced'] == preset['advancedScope'], (slug, scope)
                    print(f'PASS: all {len(presets)} presets load into the real app without invalid or dropped rules', flush=True)
                    assert api('/api/project/open', {'name': selected})['ok']
                    for server in servers:
                        assert api('/api/repeater/set', {'host': '127.0.0.1', 'port': server.server_port,
                            'tls': False, 'request': 'GET /lab-check HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n'})['ok']
                        result = api('/api/repeater/send', {})
                        deadline = time.monotonic() + 15
                        while api('/api/snapshot')['repeater']['busy']:
                            assert time.monotonic() < deadline
                            time.sleep(.05)
                        if server is allowed:
                            assert result['ok'], result
                    assert allowed.paths == ['/lab-check'] and denied.paths == []
                    print('PASS: opened lab preset permits its owned fixture and blocks the unrelated owned port', flush=True)
                    api('/api/app/quit', {})
                    process.wait(15)
                    assert process.returncode == 0
                finally:
                    if process.poll() is None:
                        process.terminate()
                        process.wait(15)
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == '__main__':
    main()
