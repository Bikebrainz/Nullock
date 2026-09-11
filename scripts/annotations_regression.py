#!/usr/bin/env python3
"""Project-note persistence and isolation checks against an isolated local app."""
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
    with tempfile.TemporaryDirectory(prefix='nullock-annotations-') as temporary:
        root = Path(temporary)
        port = free_port()
        base = f'http://127.0.0.1:{port}'
        env = {**os.environ, 'NULLOCK_DATA_DIR': str(root), 'NULLOCK_NO_UPDATE': '1'}
        process = None
        log = (root / 'app.log').open('wb')

        def api(path, data=None, status=200, ui_header=True):
            headers = {'Content-Type': 'application/json'}
            if ui_header: headers['X-Nullock-UI'] = '1'
            else: headers['Origin'] = 'http://untrusted.example'
            request = urllib.request.Request(base + path,
                data=None if data is None else json.dumps(data).encode(),
                headers=headers)
            try:
                with urllib.request.urlopen(request, timeout=15) as response:
                    code, body = response.status, response.read()
            except urllib.error.HTTPError as error:
                code, body = error.code, error.read()
            assert code == status, (path, code, body)
            try: return json.loads(body) if body else {}
            except json.JSONDecodeError: return {'text': body.decode()}

        def check(name, condition):
            nonlocal checks
            assert condition, name
            checks += 1
            print('PASS', name, flush=True)

        def start():
            nonlocal process
            process = subprocess.Popen([str(app), '--headless', '--no-update-check',
                f'--control-port={port}', f'--proxy-port={free_port()}',
                f'--oast-port={free_port()}', f'--dns-port={free_port()}'],
                env=env, stdout=log, stderr=log,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            for _ in range(150):
                if process.poll() is not None: raise RuntimeError('App exited during startup')
                try:
                    api('/api/snapshot')
                    return
                except (OSError, urllib.error.URLError):
                    time.sleep(.1)
            raise RuntimeError('App did not start')

        def stop():
            if process and process.poll() is None:
                api('/api/app/quit', {})
                process.wait(timeout=15)
                assert process.returncode == 0

        def notes():
            return api('/api/history/annotations')['annotations']

        def edit(row_id, patch, generation=None, status=200):
            generation = generation or api('/api/snapshot')['bootInfo']['historyGeneration']
            return api('/api/history/annotation', {'id': row_id, 'historyGeneration': generation, **patch}, status)

        def entry(path):
            return {'request': {'method': 'GET', 'url': 'http://notes.test/' + path,
                'httpVersion': 'HTTP/1.1', 'headers': []},
                'response': {'status': 200, 'statusText': 'OK', 'httpVersion': 'HTTP/1.1',
                    'headers': [], 'content': {'text': 'fixture'}}}

        def ingest(entries):
            return api('/api/har/import', {'har': {'log': {'version': '1.2', 'entries': entries}}})

        try:
            start()
            check('new project starts with no notes', notes() == {})
            assert api('/api/project/create', {'name': 'notes-a'})['ok']
            first = entry('first')
            first['comment'] = 'Imported note'
            assert ingest([first, entry('second')])['ok']
            check('HAR comments become project notes', notes()['1']['comment'] == 'Imported note')
            before = api('/api/snapshot')
            edit(1, {'color': 'purple'})
            check('color patch preserves existing comment', notes()['1'] == {'color': 'purple', 'comment': 'Imported note'})
            after = api('/api/snapshot')
            check('annotation changes invalidate snapshot sequence', after['seq'] != before['seq'])
            note = '<img src=x onerror=alert(1)>\nUnicode: café 雪'
            edit(2, {'comment': note})
            edit(2, {'color': 'green'})
            check('independent client fields merge', notes()['2'] == {'comment': note, 'color': 'green'})
            good = notes()
            check('annotation writes require POST', 'POST' in api('/api/history/annotation', status=405)['text'])
            api('/api/history/annotation', {'id': 1, 'comment': 'cross-origin'}, 403, ui_header=False)
            check('cross-origin annotation writes are refused', notes() == good)
            for patch in ({'color': 'unknown'}, {'comment': 42}, {'comment': 'x' * 4097}, {'extra': 'value'}):
                assert not edit(1, patch, status=400)['ok']
            check('invalid annotations are rejected without changing notes', notes() == good)
            check('unknown history IDs are rejected', not edit(999, {'color': 'red'}, status=400)['ok'])
            check('fractional history IDs are rejected', not edit(1.5, {'color': 'red'}, status=400)['ok'])
            stale = after['bootInfo']['historyGeneration']
            assert api('/api/project/create', {'name': 'notes-b'})['ok']
            assert ingest([entry('other-project')])['ok']
            check('switching projects starts with independent notes', notes() == {})
            check('stale client cannot annotate a reused row ID', not edit(1, {'color': 'red'}, stale, 409)['ok'])
            assert api('/api/project/open', {'name': 'notes-a'})['ok']
            check('reopening restores project notes', notes() == good)
            edit(1, {'color': '', 'comment': ''})
            check('clearing an imported annotation removes it', '1' not in notes())
            exported = Path(api('/api/har/export', {'redact': False})['path'])
            archive = json.loads(exported.read_text(encoding='utf-8'))['log']['entries']
            check('HAR exports notes and highlight losslessly', archive[1]['comment'] == note
                and archive[1]['_nullockAnnotation']['color'] == 'green')
            check('HAR export honors cleared imported notes', 'comment' not in archive[0])
            assert api('/api/project/open', {'name': 'notes-b'})['ok']
            assert ingest(archive)['ok']
            check('HAR re-import remaps notes to new row IDs', notes() == {'3': good['2']})
            broken = entry('invalid-note')
            broken['_nullockAnnotation'] = {'color': 'bogus'}
            rows_before = len(api('/api/snapshot')['rows'])
            check('malformed HAR notes reject the whole import', not ingest([entry('valid'), broken])['ok']
                and len(api('/api/snapshot')['rows']) == rows_before)
            assert api('/api/project/open', {'name': 'notes-a'})['ok']
            metadata = root / 'projects/notes-a/project.json'
            backup = metadata.with_suffix('.saved')
            metadata.rename(backup)
            metadata.mkdir()
            try:
                result = edit(2, {'comment': 'must not persist'}, status=400)
                check('write failure is visible and rolls back the edit', not result['ok'] and notes()['2'] == good['2'])
            finally:
                metadata.rmdir()
                backup.rename(metadata)
            stop()
            index = root / 'projects/notes-a/history-index.sqlite'
            index.unlink()
            start()
            assert api('/api/project/open', {'name': 'notes-a'})['ok']
            check('restart and index rebuild retain notes and clears', notes() == {'2': good['2']})
            generation = api('/api/snapshot')['bootInfo']['historyGeneration']
            assert api('/api/clear-history', {})['ok']
            check('history clear removes all annotation storage', notes() == {})
            assert ingest([entry('new-history')])['ok']
            check('pre-clear edits cannot attach to new history', not edit(1, {'color': 'red'}, generation, 409)['ok'])
            check('new history has no previous notes', notes() == {})
            stop()
            print(f'{checks} annotation checks passed', flush=True)
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
