#!/usr/bin/env python3
"""Local-only end-to-end regressions for project boundaries and request fidelity."""
import argparse
import base64
import json
import http.client
import os
from pathlib import Path
import socket
import ssl
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('app', type=Path)
    parser.add_argument('--gui', action='store_true', help='also require the embedded native window to load')
    args = parser.parse_args()
    app_path = args.app.resolve()
    ctl, proxy = free_port(), free_port()
    received, checks = [], []
    started, release = threading.Event(), threading.Event()

    class Mock(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_GET(self): self.respond()
        def do_POST(self): self.respond()
        def do_PUT(self): self.respond()
        def respond(self):
            body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            received.append((self.path, dict(self.headers), body))
            if self.path == '/slow':
                started.set()
                release.wait(20)
            if self.path == '/redirect':
                self.send_response(302)
                self.send_header('Location', f'http://localhost:{self.server.server_port}/cookie-destination')
                self.send_header('Set-Cookie', 'restricted=fixture; Path=/private; Secure')
            elif self.path == '/307':
                self.send_response(307)
                self.send_header('Location', '/entity-destination')
            else: self.send_response(200)
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b'OK')

    mock = ThreadingHTTPServer(('127.0.0.1', 0), Mock)
    threading.Thread(target=mock.serve_forever, daemon=True).start()
    host = f'127.0.0.1:{mock.server_port}'
    def api(path, data=None, raw=False, timeout=35):
        payload = data if raw else None if data is None else json.dumps(data).encode()
        req = urllib.request.Request(f'http://127.0.0.1:{ctl}' + path, data=payload,
            headers={'X-Nullock-UI': '1', 'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            content = r.read()
            return json.loads(content) if content else None
    def check(name, value):
        checks.append((name, bool(value)))
        print(('PASS ' if value else 'FAIL ') + name, flush=True)
        if not value: raise AssertionError(name)
    def project(name):
        check('create ' + name, api('/api/project/create', {'name':name})['ok'])
    def entry(path='/body', body=None, content=b'Hello', target=None):
        target = target or host
        headers = [{'name':'Host','value':target}]
        req = {'method':'POST' if body is not None else 'GET', 'url':f'http://{target}{path}',
               'httpVersion':'HTTP/1.1', 'headers':headers}
        if body is not None:
            headers.append({'name':'Content-Type','value':'application/octet-stream'})
            req['postData'] = {'mimeType':'application/octet-stream', '_encoding':'base64',
                               'text':base64.b64encode(body).decode()}
        return {'startedDateTime':'2026-09-10T12:00:00.000Z','request':req,
            'response':{'status':200,'statusText':'OK','httpVersion':'HTTP/1.1','headers':[],
                        'content':{'mimeType':'text/plain','encoding':'base64',
                                   'text':base64.b64encode(content).decode()}}}
    def ingest(*entries):
        return api('/api/har/import', {'har':{'log':{'version':'1.2','entries':entries}}})
    def send(request):
        api('/api/repeater/set', {'host':'127.0.0.1','port':mock.server_port,'tls':False,
            'request':request,'requestEncoding':'utf8','followRedirects':3,'processCookies':True})
        api('/api/repeater/send', {})
        api('/api/snapshot')

    process = None
    tls_mock = None
    with tempfile.TemporaryDirectory(prefix='nullock-regression-') as temporary:
        scratch = Path(temporary)
        initial = scratch/'explicit project'
        env = os.environ.copy()
        env['NULLOCK_DATA_DIR'] = str(scratch/'app-data')
        env['NULLOCK_NO_UPDATE'] = '1'
        env['QT_LOGGING_TO_CONSOLE'] = '1'
        if args.gui:
            env['QT_QPA_PLATFORM'] = 'offscreen'
            env['QT_QUICK_BACKEND'] = 'software'
        # A deployed runtime must not require a machine-specific OpenSSL config.
        env['OPENSSL_CONF'] = str(scratch/'does-not-exist.cnf')
        log = open(scratch/'app.log','wb')
        try:
            process = subprocess.Popen([str(app_path),'--no-browser' if args.gui else '--headless','--no-update-check',
                f'--project={initial}',f'--control-port={ctl}',f'--proxy-port={proxy}',
                f'--oast-port={free_port()}',f'--dns-port={free_port()}'],
                env=env,stdout=log,stderr=log,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            for _ in range(120):
                if process.poll() is not None:
                    log.flush()
                    raise RuntimeError((scratch/'app.log').read_text(errors='replace'))
                try: snap=api('/api/snapshot', timeout=.25); break
                except OSError: time.sleep(.1)
            else: raise RuntimeError('app did not start: ' + (scratch/'app.log').read_text(errors='replace'))
            print('Runtime: Qt', snap['bootInfo']['qtVersion'],
                  'TLS backend', snap['bootInfo']['tlsBackend'], flush=True)
            if args.gui:
                log.flush()
                native_log = (scratch/'app.log').read_text(errors='replace')
                check('embedded native window loads', 'Nullock native UI ready' in native_log)
            check('--project selects the explicit directory', Path(snap['bootInfo']['projectDir']).resolve()==initial.resolve())
            check('snapshot reports a real version', bool(snap['bootInfo']['version']))
            check('CA is created without external config', (scratch/'app-data/ca/ca.pem').exists())
            with urllib.request.urlopen(f'http://127.0.0.1:{ctl}/', timeout=5) as page:
                check('installed browser UI is served', b'id="app"' in page.read())
            check('project templates are installed', bool(api('/api/project/templates')['templates']))
            # Exercise certificate minting, Qt's TLS backend and actual encrypted
            # proxy traffic. The self-signed fixture exception lives only in this
            # isolated project; the test's trust store is a Python SSLContext.
            fixture_conf = scratch/'tls.cnf'
            fixture_conf.write_text('[req]\ndistinguished_name=dn\nprompt=no\nx509_extensions=server\n'
                '[dn]\nCN=localhost\n[server]\nbasicConstraints=critical,CA:false\n'
                'keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n'
                'subjectAltName=DNS:localhost,IP:127.0.0.1\n')
            openssl = str(app_path.parent/'openssl.exe') if os.name == 'nt' else shutil.which('openssl')
            fixture_env = dict(env, OPENSSL_CONF=str(fixture_conf))
            subprocess.run([openssl,'req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                '-keyout',str(scratch/'tls.key'),'-out',str(scratch/'tls.pem'),'-config',str(fixture_conf)],
                env=fixture_env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls_context.load_cert_chain(scratch/'tls.pem', scratch/'tls.key')
            tls_mock = ThreadingHTTPServer(('127.0.0.1', 0), Mock)
            tls_mock.socket = tls_context.wrap_socket(tls_mock.socket, server_side=True)
            threading.Thread(target=tls_mock.serve_forever, daemon=True).start()
            api('/api/proxy/accept-invalid-hosts/add', {'host':f'127.0.0.1:{tls_mock.server_port}'})
            trust = ssl.create_default_context(cafile=str(scratch/'app-data/ca/ca.pem'))
            tunnel = http.client.HTTPSConnection('127.0.0.1', proxy, context=trust, timeout=15)
            try:
                tunnel.set_tunnel('127.0.0.1', tls_mock.server_port)
                tunnel.request('GET', '/tls-package')
                response = tunnel.getresponse()
                check('packaged proxy completes a local HTTPS transaction', response.status==200 and response.read()==b'OK')
            finally:
                tunnel.close()
            send(f'GET /redirect HTTP/1.1\r\nHost: {host}\r\nCookie: original=fixture\r\n\r\n')
            dst=next(r for r in received if r[0]=='/cookie-destination')
            check('redirect does not disclose original or Secure/path cookies', not dst[1].get('Cookie'))
            send(f'POST /307 HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\r\n{{"x":1}}')
            dst=next(r for r in received if r[0]=='/entity-destination')
            check('307 preserves entity semantics', dst[1].get('Content-Type')=='application/json' and dst[2]==b'{"x":1}')
            project('history')
            ingest(entry('/one', target='first.test'))
            epoch=api('/api/snapshot')['bootInfo']['historyEpoch']
            check('clear saved history succeeds', api('/api/clear-history', {})['ok'])
            ingest(entry('/two', target='second.test'))
            full=api('/api/history/full/1')
            check('history metadata and bytes identify the same transaction', full['host']=='second.test' and 'second.test' in full['rawRequest'])
            check('history clear rotates persistent browser identity', api('/api/snapshot')['bootInfo']['historyEpoch']!=epoch)
            check('history archive was actually cleared', len((scratch/'app-data/projects/history/history.ndjson').read_text().splitlines())==1)
            project('binary')
            body=b'\x00\xff\x80\n\r\nABC'+b'x'*70000
            ingest(entry(body=body))
            full=api('/api/history/full/1')
            check('HAR base64 response decoded', full['rawResponse'].endswith('Hello'))
            exported=Path(api('/api/har/export', {'redact':False})['path'])
            har=json.loads(exported.read_text())['log']['entries'][0]
            check('HAR export preserves opaque request bytes', base64.b64decode(har['request']['postData']['text'])==body and har['request']['postData']['_encoding']=='base64')
            check('raw accessor is complete', '[binary' not in full['rawRequest'] and '[truncated' not in full['rawRequest'] and len(full['rawRequest'])>70000)
            api('/api/repeater/tab/addFromHistoryId', {'id':1})
            check('binary request has explicit byte encoding', api('/api/snapshot')['repeater']['requestEncoding']=='latin1')
            api('/api/repeater/send', {})
            api('/api/snapshot')  # send is queued; wait for its main-thread completion
            check('Repeater sends full unchanged binary body', received[-1][2]==body)
            sent_count = len(received)
            api('/api/repeater/set', {'request':full['rawRequest']+'\u20ac'})
            api('/api/repeater/send', {})
            check('Repeater rejects characters outside the selected byte encoding',
                  'outside Latin-1' in api('/api/snapshot')['repeater']['response'] and len(received)==sent_count)
            api('/api/intruder/from-history', {'id':1})
            intr=api('/api/snapshot')['intruder']
            check('Intruder preserves binary template and port', intr['requestEncoding']=='latin1' and intr['port']==mock.server_port and '[truncated' not in intr['template'])
            api('/api/intruder/set', {'template':intr['template'].replace('ABC','§ABC§'), 'payloads':'LONGER-PAYLOAD'})
            api('/api/intruder/start', {})
            for _ in range(150):
                if not api('/api/snapshot')['intruder']['running']: break
                time.sleep(.05)
            check('Intruder preserves binary bytes and updates payload framing', received[-1][2]==body.replace(b'ABC',b'LONGER-PAYLOAD'))
            sent_count = len(received)
            api('/api/intruder/set', {'payloads':'\u20ac'})
            api('/api/intruder/start', {})
            for _ in range(150):
                intr = api('/api/snapshot')['intruder']
                if not intr['running']: break
                time.sleep(.05)
            check('Intruder rejects unrepresentable generated payloads',
                  len(received)==sent_count and 'outside Latin-1' in intr['results'][0]['err'])
            # The index is derived: recreate it and verify old rows plus future IDs.
            project('away')
            index=scratch/'app-data/projects/binary/history-index.sqlite'
            index.unlink()
            check('reopen after index removal', api('/api/project/open', {'name':'binary'})['ok'])
            check('index rebuild retains full row', api('/api/history/full/1')['host']=='127.0.0.1')
            ingest(entry('/after-rebuild'))
            check('index rebuild resumes correct IDs', api('/api/history/full/2')['path']=='/after-rebuild')
            before=len(api('/api/snapshot')['rows'])
            bad=entry(); bad['response']['content']['text']='not valid base64!'
            check('malformed HAR encoding rejected before mutation', not ingest(entry(),bad)['ok'] and len(api('/api/snapshot')['rows'])==before)
            payload=b'{"notes":"INCOMPLETE"}'
            with socket.create_connection(('127.0.0.1',ctl),timeout=12) as sock:
                sock.sendall(f'POST /api/scope/notes HTTP/1.1\r\nHost: 127.0.0.1:{ctl}\r\nX-Nullock-UI: 1\r\nContent-Length: {len(payload)+100}\r\n\r\n'.encode()+payload)
                response=sock.recv(4096)
            check('incomplete API body rejected', response.startswith(b'HTTP/1.1 408') and api('/api/snapshot')['scope']['notes']!='INCOMPLETE')
            check('large valid API body accepted', api('/api/scope/notes',{'notes':'x'*1048576})['ok'])
            project('scan-only')
            xml=b'<nmaprun><host><address addr="127.0.0.2" addrtype="ipv4"/><ports><port protocol="tcp" portid="3306"><state state="open"/><service name="mysql"/></port></ports></host></nmaprun>'
            api('/api/portscan/import-nmap',xml,raw=True)
            api('/api/portscan/to-findings',{})
            check('scan-only project has findings',api('/api/inventory')['totalFindings']>0)
            project('empty')
            check('empty-history project switch clears findings',api('/api/inventory')['totalFindings']==0)
            project('replay-origin')
            ingest(entry('/slow'))
            api('/api/history/1/replay',{})
            check('replay in flight',started.wait(5))
            check('project switch refused during replay',not api('/api/project/create',{'name':'replay-destination'})['ok'])
            release.set()
            for _ in range(100):
                if len(api('/api/snapshot')['rows'])==2: break
                time.sleep(.05)
            check('replay remains in origin history',len(api('/api/snapshot')['rows'])==2)
            project('replay-destination')
            check('destination has no old replay',not api('/api/snapshot')['rows'])
            project('shutdown')
            started.clear(); release.clear()
            ingest(entry('/slow'))
            api('/api/history/1/replay',{})
            check('shutdown fixture started',started.wait(5))
            api('/api/app/quit',{})
            time.sleep(5.5)
            check('shutdown retains dependencies beyond old five-second timeout',process.poll() is None)
            release.set()
            check('graceful shutdown completes successfully',process.wait(timeout=15)==0)
            check('late result persisted before shutdown',len((scratch/'app-data/projects/shutdown/history.ndjson').read_text().splitlines())==2)
            if args.gui:
                native_log = (scratch/'app.log').read_text(errors='replace')
                check('native window has no QML binding errors',
                      'ReferenceError:' not in native_log and 'TypeError:' not in native_log)
        finally:
            release.set()
            if process and process.poll() is None:
                try:
                    api('/api/app/quit', {}, timeout=2)
                    process.wait(timeout=3)
                except (OSError, subprocess.TimeoutExpired):
                    process.terminate(); process.wait(timeout=10)
            log.close()
            if sys.exc_info()[0] is not None:
                print((scratch/'app.log').read_text(errors='replace'), file=sys.stderr)
            mock.shutdown(); mock.server_close()
            if tls_mock:
                tls_mock.shutdown(); tls_mock.server_close()
    print(f'{len(checks)} runtime checks passed')

if __name__ == '__main__': main()
