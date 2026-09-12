#!/usr/bin/env python3
"""Nonblocking API intake and asynchronous Repeater against owned loopback fixtures."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread, Event, Timer
from outbound_scope_regression import free_port


def main():
    parser=argparse.ArgumentParser();parser.add_argument('app',type=Path)
    app=parser.parse_args().app.resolve();checks=0;held,release=Event(),Event();hits=[]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*_): pass
        def do_GET(self):
            hits.append(self.path)
            if self.path=='/hold': held.set();release.wait(15)
            self.send_response(302 if self.path=='/hold' else 200)
            if self.path=='/hold': self.send_header('Location','/later')
            self.send_header('Content-Length','7');self.end_headers();self.wfile.write(b'fixture')
    fixture=ThreadingHTTPServer(('127.0.0.1',0),Handler);worker=Thread(target=fixture.serve_forever,daemon=True);worker.start()
    with tempfile.TemporaryDirectory(prefix='nullock-responsive-') as tmp:
        root=Path(tmp);control=free_port();log=(root/'app.log').open('wb');sockets=[]
        process=subprocess.Popen([str(app),'--headless','--no-update-check',f'--control-port={control}',
            f'--proxy-port={free_port()}',f'--oast-port={free_port()}',f'--dns-port={free_port()}'],
            env={**os.environ,'NULLOCK_DATA_DIR':str(root)},stdout=log,stderr=log,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
        def api(path,data=None,status=200):
            req=urllib.request.Request(f'http://127.0.0.1:{control}'+path,data=None if data is None else json.dumps(data).encode(),
                headers={'Content-Type':'application/json','X-Nullock-UI':'1'})
            try:
                with urllib.request.urlopen(req,timeout=3) as r:code,body=r.status,r.read()
            except urllib.error.HTTPError as e:code,body=e.code,e.read()
            assert code==status,(path,code,body)
            return json.loads(body)
        def connect(raw):
            s=socket.create_connection(('127.0.0.1',control),timeout=5);s.sendall(raw);sockets.append(s);return s
        def headers(length,extra=b''):
            return f'POST /api/sequencer/workspace/append HTTP/1.1\r\nHost: 127.0.0.1:{control}\r\nX-Nullock-UI: 1\r\nContent-Length: {length}\r\n'.encode()+extra+b'\r\n'
        def check(name,ok):
            nonlocal checks
            assert ok,name;checks+=1;print('PASS',name,flush=True)
        def close_all():
            for s in sockets:s.close()
            sockets.clear()
        def wait_for(fn):
            deadline=time.monotonic()+15
            while time.monotonic()<deadline:
                if fn():return
                time.sleep(.03)
            raise AssertionError('condition timed out')
        def raw(path):return f'GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n'
        try:
            for _ in range(150):
                try:api('/api/snapshot');break
                except OSError:assert process.poll() is None;time.sleep(.1)
            for _ in range(6):connect(b'GET /api/snapshot HTTP/1.1\r\nHo')
            for _ in range(6):connect(headers(1000)+b'{')
            started=time.monotonic();api('/api/snapshot')
            check('partial headers and bodies do not block snapshot requests',time.monotonic()-started<1)
            close_all();time.sleep(.1)
            for label,extra in [('duplicate length',b'Content-Length: 1\r\n'),('transfer encoding',b'Transfer-Encoding: chunked\r\n'),('duplicate host',b'Host: other.test\r\n')]:
                s=connect(headers(0,extra));check(label+' is rejected before body dispatch',s.recv(4096).startswith(b'HTTP/1.1 400'))
            close_all()
            s=connect(headers(-1));check('invalid length is rejected',s.recv(4096).startswith(b'HTTP/1.1 413'));close_all()
            s=connect(f'GET /api/snapshot HTTP/1.1\r\nHost: 127.0.0.1:{control}\r\nX-Large: '.encode()+b'a'*66000)
            check('oversized header is rejected',s.recv(4096).startswith(b'HTTP/1.1 431'));close_all()
            connect(headers(64*1024*1024));connect(headers(64*1024*1024));time.sleep(.1)
            s=connect(headers(1));check('aggregate pending-body budget is bounded',s.recv(4096).startswith(b'HTTP/1.1 503'))
            started=time.monotonic();api('/api/snapshot');check('read-only API stays available at body budget',time.monotonic()-started<1)
            close_all();time.sleep(.1)
            s=connect(b'GET /api/snapshot HTTP/1.1\r\n');started=time.monotonic();response=s.recv(4096)
            check('absolute header deadline closes incomplete requests',response.startswith(b'HTTP/1.1 408') and time.monotonic()-started<4.5);close_all()
            large='multichunk-'*25000
            check('large valid request body assembles across readyRead events',api('/api/sequencer/workspace/append',{'text':large})['draft']['text']==large)
            api('/api/project/create',{'name':'responsive'})
            api('/api/scope/in/add',{'glob':'127.0.0.1'})
            api('/api/repeater/set',{'host':'127.0.0.1','port':fixture.server_port,'tls':False,'request':raw('/hold'),'followRedirects':3})
            started=time.monotonic();api('/api/repeater/send',{});assert held.wait(3)
            check('Repeater send returns while upstream response is pending',time.monotonic()-started<1)
            started=time.monotonic();snap=api('/api/snapshot')
            check('UI snapshot stays responsive during Repeater traffic',snap['repeater']['busy'] and time.monotonic()-started<1)
            api('/api/repeater/set',{'request':raw('/edited')})
            api('/api/repeater/tab/close',{'index':0},409)
            api('/api/repeater/send',{},409)
            check('project switch is refused while Repeater owns a request',not api('/api/project/create',{'name':'blocked'})['ok'])
            api('/api/repeater/stop',{});check('stop request is visible while the current response finishes',api('/api/snapshot')['repeater']['cancelling'])
            release.set();wait_for(lambda:not api('/api/snapshot')['repeater']['busy'])
            rep=api('/api/snapshot')['repeater']
            check('cancellation prevents following the pending redirect',hits==['/hold'] and 'stopped' in rep['statusLine'])
            check('late response preserves edits made while sending','/edited' in rep['request'] and 'fixture' in rep['response'])
            api('/api/repeater/history/load',{'index':0})
            check('request history records the sent request, not later edits','/hold' in api('/api/snapshot')['repeater']['request'])
            api('/api/repeater/set',{'request':raw('/ok')});api('/api/repeater/send',{})
            wait_for(lambda:not api('/api/snapshot')['repeater']['busy'])
            check('next send works after stopping',api('/api/snapshot')['repeater']['statusLine'].startswith('HTTP/1.0 200'))
            release.clear();held.clear();api('/api/repeater/set',{'request':raw('/hold')});api('/api/repeater/send',{});assert held.wait(3)
            timer=Timer(.3,release.set);timer.start();api('/api/app/quit',{});process.wait(15);timer.join()
            check('shutdown joins Repeater and saves its final status',process.returncode==0 and 'stopped' in (root/'projects/responsive/project.json').read_text())
            check('shutdown never follows another redirect',hits==['/hold','/ok','/hold'])
            print(f'{checks} control responsiveness checks passed',flush=True)
        except Exception:
            log.flush();print((root/'app.log').read_text(encoding='utf-8',errors='replace')[-3500:]);raise
        finally:
            release.set();close_all()
            if process.poll() is None:process.kill();process.wait(10)
            log.close();fixture.shutdown();fixture.server_close();worker.join()


if __name__=='__main__':main()
