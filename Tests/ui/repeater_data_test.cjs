const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
let tick, project = 'a', host = '';
const requests = [], polls = [];
const window = {dispatchEvent() {}};
const snapshot = () => ({seq:7, instanceId:'server', bootInfo:{project,
  projectDir:'/projects/' + project, historyGeneration:project}, repeater:{host}});
const context = vm.createContext({window, console, encodeURIComponent, Date,
  AbortController, setTimeout, clearTimeout, CustomEvent:class {},
  document:{documentElement:{style:{setProperty(){}}}},
  setInterval(fn) { tick = fn; },
  fetch(url, options) { return new Promise(resolve => requests.push({url, options, resolve})); },
  XMLHttpRequest:class {
    open(method, url, async) { this.async = async; }
    send() {
      if (this.async) polls.push(this);
      else { this.status = 200; this.responseText = JSON.stringify(snapshot()); }
    }
  }
});
Object.defineProperty(context, 'NL', {get:() => window.NL});
vm.runInContext(fs.readFileSync(path.join(__dirname, '../../ui-v2/real-data.js'), 'utf8'), context);
const NL = window.NL;
const flush = () => new Promise(resolve => setImmediate(resolve));
const finishPoll = (poll, data = snapshot()) => {
  poll.status = 200; poll.responseText = JSON.stringify(data); poll.onload();
};
const finishWrite = (request, ok = true) => request.resolve({ok,
  json:async () => ({ok, error:ok ? undefined : 'save refused'})});

(async () => {
  tick(); const stale = polls.shift();
  const first = NL.actions.repeaterSet({host:'a'});
  const second = NL.actions.repeaterSet({host:'ab'});
  assert.equal(NL.repeater.host, 'ab');
  await flush(); assert.equal(requests.length, 1, 'writes are serialized');
  assert.equal(JSON.parse(requests[0].options.body).historyGeneration, 'a');
  finishWrite(requests.shift()); await first; await flush();
  finishWrite(requests.shift()); await second;
  finishPoll(stale);
  assert.equal(NL.repeater.host, 'ab', 'a late poll cannot erase newer typing');
  assert.equal(NL._seq, 0, 'a skipped draft forces another snapshot');
  host = 'ab'; tick(); finishPoll(polls.shift());
  assert.equal(NL.repeater.host, 'ab');

  const edit = NL.actions.repeaterSet({host:'before-start'});
  const start = NL.actions.repeaterSend();
  await flush(); assert.equal(requests[0].url, '/api/repeater/set');
  finishWrite(requests.shift()); await edit; await flush();
  assert.equal(requests[0].url, '/api/repeater/send');
  finishWrite(requests.shift()); await start;

  const inFlight = NL.actions.repeaterSet({host:'outgoing'});
  const queued = NL.actions.repeaterSet({host:'must-not-leak'});
  const rejected = assert.rejects(queued, /Project history changed/);
  await flush(); const mutation = requests.shift();
  project = 'b'; host = 'independent'; tick(); finishPoll(polls.shift());
  assert.equal(NL.repeater.host, 'independent');
  finishWrite(mutation); await inFlight; await rejected;
  assert.equal(requests.length, 0, 'queued edits do not enter another project');
  assert.equal(NL._repeaterPendingWrites, 0);

  const failed = NL.actions.repeaterSet({host:'unsaved'});
  const failure = assert.rejects(failed, /save refused/);
  await flush(); finishWrite(requests.shift(), false); await failure;
  tick(); finishPoll(polls.shift());
  assert.equal(NL.repeater.host, 'independent');
  assert.equal(NL._repeaterPendingWrites, 0);
  console.log('PASS: Repeater typing survives stale polls; writes/start are ordered; project changes and failures recover safely');
})().catch(error => {console.error(error); process.exitCode = 1;});
