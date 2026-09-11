const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
let tick, project = 'a', generation = 'a1', revision = 'r1';
const requests = [];
const window = {dispatchEvent() {}};
const context = vm.createContext({window, console, encodeURIComponent, Date,
  AbortController, setTimeout, clearTimeout, CustomEvent: class {},
  document: {documentElement:{style:{setProperty(){}}}},
  setInterval(fn) { tick = fn; },
  fetch(url, options) { return new Promise(resolve => requests.push({url, options, resolve})); },
  XMLHttpRequest: class {
    open(method, url, async) { this.async = async; }
    send() {
      this.status = 200;
      this.responseText = JSON.stringify({seq:1, instanceId:'server', bootInfo:{
        project, projectDir:'/projects/'+project, historyGeneration:generation,
        annotationsRevision:revision}, rows:[{id:1}]});
      if (this.async) this.onload();
    }
  }
});
Object.defineProperty(context, 'NL', {get: () => window.NL});
vm.runInContext(fs.readFileSync(path.join(__dirname, '../../ui-v2/real-data.js'), 'utf8'), context);
const NL = window.NL;
const flush = () => new Promise(resolve => setImmediate(resolve));
const finish = (request, gen, rev, annotations) => request.resolve({ok:true,
  json:async () => ({ok:true, historyGeneration:gen, revision:rev, annotations})});

(async () => {
  const oldProject = requests.shift();
  project = 'b'; generation = 'b1'; revision = 'r2'; tick();
  const current = requests.shift();
  finish(oldProject, 'a1', 'r1', {'1':{comment:'wrong project'}});
  await flush();
  assert.equal(Object.keys(NL.historyAnnotations).length, 0);
  finish(current, 'b1', 'r2', {'1':{comment:'original'}});
  await flush();
  assert.equal(NL.historyAnnotations['1'].comment, 'original');
  tick(); tick(); assert.equal(requests.length, 0, 'unchanged notes are not fetched again');

  revision = 'r3'; tick();
  const staleRead = requests.shift();
  const write = NL.actions.annotateHistory(1, {comment:'saved edit'});
  await flush();
  const mutation = requests.shift();
  assert.equal(JSON.parse(mutation.options.body).historyGeneration, 'b1');
  finish(mutation, 'b1', 'r4', {'1':{comment:'saved edit'}});
  await write;
  finish(staleRead, 'b1', 'r3', {'1':{comment:'older read'}});
  await flush();
  assert.equal(NL.historyAnnotations['1'].comment, 'saved edit', 'late read cannot erase a successful edit');

  const firstWrite = NL.actions.annotateHistory(1, {color:'red'});
  const queuedWrite = NL.actions.annotateHistory(1, {comment:'queued old project'});
  const rejected = assert.rejects(queuedWrite, /Project history changed/);
  await flush();
  const inFlight = requests.shift();
  project = 'c'; generation = 'c1'; revision = 'r5'; tick();
  const newRead = requests.shift();
  finish(inFlight, 'b1', 'r4', {'1':{comment:'saved edit', color:'red'}});
  await firstWrite;
  await rejected;
  assert.equal(requests.length, 0, 'queued edits are not sent after a project switch');
  finish(newRead, 'c1', 'r5', {});
  await flush();
  assert.equal(Object.keys(NL.historyAnnotations).length, 0);
  console.log('PASS: annotation reads and writes reject stale projects/revisions; queued edits stay in their project');
})().catch(error => { console.error(error); process.exitCode = 1; });
