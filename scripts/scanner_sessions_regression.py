#!/usr/bin/env python3
"""Verify scanner authentication with owned local endpoints and isolated project data."""
import argparse
import gzip
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread, Event, Timer
from outbound_scope_regression import free_port


def main():
    parser=argparse.ArgumentParser(); parser.add_argument('app',type=Path)
    app=parser.parse_args().app.resolve(); captured=[]; bodies=[]; held, release=Event(), Event(); checks=0
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*_): pass
        def do_POST(self):
            bodies.append(self.rfile.read(int(self.headers.get('Content-Length','0'))))
            self.do_GET()
        def do_GET(self):
            captured.append((self.path,dict(self.headers)))
            status=401 if self.path=='/protected/expired' else 200
            body=b'{"csrf":"json-token"}' if self.path=='/protected/json' else b'fixture'
            if self.path=='/login': body=b'{"token":"fresh-login-token"}'
            if self.path.startswith('/api/ws/pull'): body=b'{"ok":true,"findings":[],"seq":0}'
            if self.path=='/protected/hold': held.set(); release.wait(10)
            compressed=self.path in ['/protected/json','/login']
            if compressed: body=gzip.compress(body)
            self.send_response(status)
            self.send_header('Content-Length',str(len(body)))
            self.send_header('X-Sample','sample-token')
            if self.path=='/protected/token': self.send_header('X-CSRF','captured-token')
            if self.path=='/protected/expired': self.send_header('X-CSRF','expired-token')
            if self.path=='/protected/cookie': self.send_header('Set-Cookie','sid=rotated-cookie; Path=/protected')
            if compressed: self.send_header('Content-Encoding','gzip')
            self.end_headers();self.wfile.write(body)
    fixture=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    worker=Thread(target=fixture.serve_forever,daemon=True);worker.start()
    with tempfile.TemporaryDirectory(prefix='nullock-scanner-auth-') as tmp:
        root=Path(tmp); control=free_port(); log=(root/'app.log').open('wb')
        process=subprocess.Popen([str(app),'--headless','--no-update-check',f'--control-port={control}',
            f'--proxy-port={free_port()}',f'--oast-port={free_port()}',f'--dns-port={free_port()}'],
            env={**os.environ,'NULLOCK_DATA_DIR':str(root)},stdout=log,stderr=log,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
        def api(endpoint,data=None):
            req=urllib.request.Request(f'http://127.0.0.1:{control}'+endpoint,
                data=None if data is None else json.dumps(data).encode(),headers={'Content-Type':'application/json','X-Nullock-UI':'1'})
            with urllib.request.urlopen(req,timeout=30) as res:return json.loads(res.read())
        def check(name,ok):
            nonlocal checks
            assert ok,name;checks+=1;print('PASS',name,flush=True)
        def raw(path):return f'GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n'
        def scan(path,host='127.0.0.1'):
            result=api('/api/fingerprint',{'url':f'http://{host}:{fixture.server_port}{path}'})
            assert result['ok'],result
            return captured[-1][1]
        try:
            for _ in range(150):
                try:api('/api/snapshot');break
                except OSError:assert process.poll() is None;time.sleep(.1)
            else:raise AssertionError('startup timeout')
            api('/api/project/create',{'name':'auth-a'})
            api('/api/scope/in/add',{'glob':'127.0.0.1'})
            for name,value,secure in [('sid','jar-cookie',False),('secure-only','private-cookie',True)]:
                assert api('/api/sessions/setCookie',{'host':'127.0.0.1','name':name,'value':value,'path':'/protected','secure':secure})['ok']
            check('cookie injection remains opt-in','Cookie' not in scan('/protected/plain'))
            assert api('/api/sessions/autoInject',{'host':'127.0.0.1','on':True})['ok']
            headers=scan('/protected/plain')
            check('enabled jar injects cookies into scans',headers.get('Cookie')=='sid=jar-cookie')
            check('Secure cookie never crosses HTTP','secure-only' not in headers.get('Cookie',''))
            check('cookie path boundaries hold','Cookie' not in scan('/public'))
            rules=[{'hostGlob':'127.0.0.1','pathGlob':'/protected/*','tools':8,'injectInto':0,'injectKey':'X-Scanner','injectTemplate':'scanner-rule'},
                   {'hostGlob':'127.0.0.1','pathGlob':'*','tools':2,'injectInto':0,'injectKey':'X-Repeater','injectTemplate':'repeater-only'},
                   {'hostGlob':'127.0.0.1','pathGlob':'/protected/*','tools':8,'extractFrom':0,'extractKey':'X-CSRF','variable':'token','injectInto':0,'injectKey':'X-CSRF'},
                   {'hostGlob':'127.0.0.1','pathGlob':'/protected/*','tools':8,'extractFrom':2,'extractKey':'csrf','variable':'jsonToken','injectInto':0,'injectKey':'X-JSON','injectTemplate':'{{jsonToken}}'}]
            assert api('/api/session-rules/set',{'rules':rules})['ok']
            headers=scan('/protected/plain')
            check('scanner tool rules apply and Repeater-only rules do not',headers.get('X-Scanner')=='scanner-rule' and 'X-Repeater' not in headers)
            scan('/protected/token'); headers=scan('/protected/plain')
            check('scanner response tokens refresh the next request',headers.get('X-CSRF')=='captured-token')
            scan('/protected/json');headers=scan('/protected/plain')
            check('compressed response JSON can refresh a session variable',headers.get('X-JSON')=='json-token')
            scan('/protected/cookie');headers=scan('/protected/plain')
            check('scanner Set-Cookie rotation updates the enabled jar',headers.get('Cookie')=='sid=rotated-cookie')
            rule_cookie={'hostGlob':'127.0.0.1','pathGlob':'/protected/*','tools':8,'injectInto':1,'injectKey':'sid','injectTemplate':'explicit-rule-cookie'}
            api('/api/session-rules/set',{'rules':rules+[rule_cookie]})
            check('explicit cookie rule overrides older captured cookie',scan('/protected/plain').get('Cookie')=='sid=explicit-rule-cookie')
            body_rule={'hostGlob':'127.0.0.1','pathGlob':'/protected/form','tools':8,'injectInto':2,'injectKey':'csrf','injectTemplate':'fresh form token'}
            api('/api/session-rules/set',{'rules':rules+[rule_cookie,body_rule]})
            assert api('/api/race/test',{'url':f'http://127.0.0.1:{fixture.server_port}/protected/form','method':'POST',
                'contentType':'application/x-www-form-urlencoded','body':'csrf=stale&keep=a%2Bb&csrf=duplicate','count':2})['ok']
            check('form CSRF refresh replaces stale duplicates and fixes Content-Length',len(bodies)==2 and all(b==b'csrf=fresh%20form%20token&keep=a%2Bb' for b in bodies))
            # Captured crawler traffic preserves the authenticated wire request.
            assert api('/api/crawler/start',{'seed':f'http://127.0.0.1:{fixture.server_port}/protected/plain','maxPages':1,'maxDepth':0,'throttleMs':0})['ok']
            for _ in range(100):
                if not api('/api/snapshot')['crawler']['running']: break
                time.sleep(.04)
            rows=api('/api/snapshot')['rows'];row=max(rows,key=lambda r:r['id'])
            full=api('/api/history/full/'+str(row['id']))
            check('crawler history retains effective authentication bytes','X-Scanner: scanner-rule' in full['rawRequest'] and 'sid=explicit-rule-cookie' in full['rawRequest'])
            before=len(captured)
            result=api('/api/authz-test',{'rowId':row['id'],'identities':[{'name':'one','headers':{'Cookie':'sid=one'}},{'name':'two','headers':{'Cookie':'sid=two'}}]})
            check('identity comparisons preserve each supplied credential',result['ok'] and [h.get('Cookie') for _,h in captured[before:]]==['sid=one','sid=two'])
            macro={'name':'refresh' ,'sessionHost':'127.0.0.1','loggedOutStatus':'401','steps':[{'name':'login','host':'127.0.0.1',
                'port':fixture.server_port,'tls':False,'request':raw('/login'),'extract':[{'from':'json','key':'token','var':'token'}]}]}
            assert api('/api/session-macros',{'macros':[macro]})['ok']
            before=len(captured);scan('/protected/expired')
            check('expired scan refreshes once without replaying the original request',[x[0] for x in captured[before:]]==['/protected/expired','/login'])
            headers=scan('/protected/plain')
            check('fresh login token wins over expired response token',headers.get('X-CSRF')=='fresh-login-token')
            before=sum(p=='/login' for p,_ in captured)
            scan('/protected/expired'); headers=scan('/protected/plain')
            check('later expired responses cannot overwrite fresh tokens or trigger a login storm',headers.get('X-CSRF')=='fresh-login-token' and sum(p=='/login' for p,_ in captured)==before)
            login=next(h for p,h in reversed(captured) if p=='/login')
            check('login macro uses its explicit request without scanner injection','X-Scanner' not in login and 'Cookie' not in login)
            # Operational workspace sync is deliberately outside engagement scope and authentication.
            api('/api/scope/advanced',{'rules':[{'include':False,'host':r'127\.0\.0\.1','file':'/api/.*'}]})
            result=api('/api/workspace/pull',{'url':f'http://127.0.0.1:{fixture.server_port}','key':'local-key','engagement':'local-test'})
            headers=captured[-1][1]
            check('application-service sync stays separate from scan scope and credentials',result['ok'] and 'Cookie' not in headers and 'X-Scanner' not in headers)
            before=sum(p=='/login' for p,_ in captured)
            api('/api/scope/advanced',{'rules':[{'include':False,'host':r'127\.0\.0\.1','file':'/login'}]})
            api('/api/session-macros/run',{'name':'refresh'});time.sleep(.2)
            check('login macros cannot bypass scope',sum(p=='/login' for p,_ in captured)==before)
            api('/api/project/create',{'name':'auth-b'})
            headers=scan('/protected/plain')
            check('project changes clear authentication rules and cookies',not any(k in headers for k in ['Cookie','X-Scanner','X-CSRF']))
            api('/api/project/open',{'name':'auth-a'})
            headers=scan('/protected/plain')
            check('project reopen restores rules and jar but clears transient variables',headers.get('X-Scanner')=='scanner-rule' and headers.get('Cookie')=='sid=explicit-rule-cookie' and 'X-CSRF' not in headers)
            assert api('/api/sequencer/capture/start',{'host':'127.0.0.1','port':fixture.server_port,'tls':False,'request':raw('/protected/hold'),
                'count':10000,'extract':{'from':'header','key':'X-Sample'}})['ok']
            assert held.wait(10)
            timer=Timer(.2,release.set);timer.start()
            api('/api/app/quit',{});process.wait(15);timer.join()
            check('shutdown stops an authenticated capture after its in-flight response',sum(p=='/protected/hold' for p,_ in captured)==1 and process.returncode==0)
            print(f'{checks} scanner authentication checks passed',flush=True)
        except Exception:
            log.flush();print((root/'app.log').read_text(encoding='utf-8',errors='replace')[-2500:]);raise
        finally:
            release.set()
            if process.poll() is None:process.terminate();process.wait(15)
            log.close();fixture.shutdown();fixture.server_close();worker.join()

if __name__=='__main__':main()
