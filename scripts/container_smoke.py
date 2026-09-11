#!/usr/bin/env python3
"""Exercise the authenticated, non-root container service via a loopback port."""
import json
import os
import sys
import time
import urllib.request
import urllib.error

base = sys.argv[1]
headers = {'Authorization': 'Bearer ' + os.environ['NULLOCK_API_TOKEN'], 'X-Nullock-UI':'1'}
for _ in range(120):
    try:
        with urllib.request.urlopen(urllib.request.Request(base+'/api/snapshot', headers=headers), timeout=2) as r:
            snap = json.load(r)
        break
    except OSError:
        time.sleep(.25)
else:
    raise SystemExit('Container control server did not become ready')
assert snap['bootInfo']['version'] and snap['bootInfo']['proxyOn']
try:
    urllib.request.urlopen(base+'/api/snapshot', timeout=2)
    raise AssertionError('Unauthenticated control request was accepted')
except urllib.error.HTTPError as e:
    assert e.code == 401
with urllib.request.urlopen(urllib.request.Request(base+'/', headers=headers), timeout=2) as r:
    assert b'id="app"' in r.read()
with urllib.request.urlopen(urllib.request.Request(base+'/api/app/quit', data=b'{}', headers=headers), timeout=2) as r:
    assert json.load(r)['ok']
print('PASS: container starts with CA, serves UI/API, enforces auth, and accepts graceful shutdown')
