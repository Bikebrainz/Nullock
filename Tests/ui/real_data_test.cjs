const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
let tick, project = 'a', generation = 'one', instance = 'server-one', rawFetches = 0;
let failed = false, delayed = false, pending = [], snapshotRequests = 0;
const window = {dispatchEvent() {}};
const context = vm.createContext({window, console, encodeURIComponent,
  CustomEvent: class {}, document: {documentElement:{style:{setProperty(){}}}},
  setInterval(fn) { tick=fn; },
  XMLHttpRequest: class {
    open(method,url,async) {this.url=url;this.async=async;}
    send() {
      const deliver = () => {
        if (failed) {this.onerror?.();return;}
        this.status=200;
        if (this.url.startsWith('/api/snapshot')) this.responseText=JSON.stringify({seq:1,instanceId:instance,
          bootInfo:{project,projectDir:'/projects/'+project,historyGeneration:generation},rows:[{id:1}]});
        else {rawFetches++; this.responseText=project+':'+generation+':'+instance;}
        if(this.async)this.onload();
      };
      if(this.url.startsWith('/api/snapshot')) snapshotRequests++;
      if(delayed && this.async) pending.push(deliver); else deliver();
    }
  }
});
Object.defineProperty(context,'NL',{get(){return window.NL;}});
vm.runInContext(fs.readFileSync(path.join(__dirname,'../../ui-v2/real-data.js'),'utf8'),context);
const NL=window.NL;
assert.equal(NL.connected,true);
assert.equal(NL.requestRawById(1),'a:one:server-one');
assert.equal(NL.requestRawById(1),'a:one:server-one');
assert.equal(rawFetches,1);
project='b'; tick();
assert.equal(NL.requestRawById(1),'b:one:server-one');
generation='two'; tick();
assert.equal(NL.requestRawById(1),'b:two:server-one');
instance='server-two'; tick();
assert.equal(NL.requestRawById(1),'b:two:server-two');
failed=true; tick(); assert.equal(NL.connected,false);
failed=false; tick(); assert.equal(NL.connected,true);
delayed=true; const requests=snapshotRequests;
tick(); tick(); tick(); assert.equal(snapshotRequests,requests+1);
pending.shift()(); tick(); assert.equal(snapshotRequests,requests+2);
pending.shift()();
console.log('PASS: row cache project/clear/restart identity, disconnect/reconnect, serialized polling');
