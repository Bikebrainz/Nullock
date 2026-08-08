// Scope, Repeater, Intercept, Intruder tabs.

// ===================== SCOPE =====================
function ScopeTab({ scope, dispatch, bootInfo, onCopyCa }) {
  const [newIn, setNewIn] = React.useState("");
  const [newOut, setNewOut] = React.useState("");
  const [copied, setCopied] = React.useState(false);

  return (
    <div className="tab-body" style={{ gridTemplateRows: "auto auto 1fr" }}>
      <div className="ca-card">
        <div className="ca-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
            <polygon points="12,2 22,7 22,17 12,22 2,17 2,7" />
            <path d="M9 12 l2 2 l4 -4" />
          </svg>
        </div>
        <div>
          <div className="ca-title">ROOT CA · {bootInfo.hasOpenssl ? "openssl ✓" : "openssl ✗"}</div>
          <div className="ca-path">{bootInfo.caPath}</div>
        </div>
        <div className="ca-actions">
          <button className="btn" onClick={() => { onCopyCa(); setCopied(true); setTimeout(() => setCopied(false), 1400); }}>
            {copied ? "✓ COPIED" : "COPY PATH"}
          </button>
          <button className="btn" onClick={() => {
            const u = "file:///" + (bootInfo.caDir || "");
            if (typeof Qt !== "undefined" && Qt.openUrlExternally) Qt.openUrlExternally(u);
            else window.open(u, "_blank");
          }}>OPEN FOLDER</button>
        </div>
      </div>

      <div className="pane-head" style={{ borderTop: "1px solid var(--line)" }}>
        <span className="ph-corner">▸</span>
        <span>SCOPE · {scope.in.length} IN / {scope.out.length} OUT</span>
        <span className="ph-count">project: {bootInfo.project}</span>
      </div>

      <div className="scope-grid">
        <div className="scope-col">
          <div className="pane-head" style={{ background:"var(--pane)" }}>
            <span style={{ color: "var(--ok)" }}>▸</span>
            <span>IN-SCOPE GLOBS</span>
            <span className="ph-count">{scope.in.length}</span>
          </div>
          <div className="scope-list">
            {scope.in.map((g, i) => (
              <div key={g} className="scope-item in">
                <span className="glob">{g}</span>
                <span className="rm" onClick={() => dispatch({ type: "scope-remove-in", index: i })}>×</span>
              </div>
            ))}
            {scope.in.length === 0 && <div style={{ padding: 16, color: "var(--dim)", fontSize: "var(--fz-sm)" }}>nothing in scope — all hosts captured</div>}
          </div>
          <div className="scope-add">
            <div className="fld" style={{ flex: 1 }}>
              <span className="pre">+IN</span>
              <input
                placeholder="e.g. *.acme.corp"
                value={newIn}
                onChange={e => setNewIn(e.target.value)}
                onKeyDown={e => { if (e.key === "Enter" && newIn.trim()) { dispatch({ type: "scope-add-in", value: newIn.trim() }); setNewIn(""); } }}
              />
            </div>
            <button className="btn" onClick={() => { if (newIn.trim()) { dispatch({ type: "scope-add-in", value: newIn.trim() }); setNewIn(""); } }}>ADD</button>
          </div>
        </div>
        <div className="scope-col">
          <div className="pane-head" style={{ background:"var(--pane)" }}>
            <span style={{ color: "var(--err)" }}>▸</span>
            <span>OUT-OF-SCOPE GLOBS</span>
            <span className="ph-count">{scope.out.length}</span>
          </div>
          <div className="scope-list">
            {scope.out.map((g, i) => (
              <div key={g} className="scope-item out">
                <span className="glob">{g}</span>
                <span className="rm" onClick={() => dispatch({ type: "scope-remove-out", index: i })}>×</span>
              </div>
            ))}
            {scope.out.length === 0 && <div style={{ padding: 16, color: "var(--dim)", fontSize: "var(--fz-sm)" }}>no exclusions</div>}
          </div>
          <div className="scope-add">
            <div className="fld" style={{ flex: 1 }}>
              <span className="pre">+OUT</span>
              <input
                placeholder="e.g. *.analytics.com"
                value={newOut}
                onChange={e => setNewOut(e.target.value)}
                onKeyDown={e => { if (e.key === "Enter" && newOut.trim()) { dispatch({ type: "scope-add-out", value: newOut.trim() }); setNewOut(""); } }}
              />
            </div>
            <button className="btn" onClick={() => { if (newOut.trim()) { dispatch({ type: "scope-add-out", value: newOut.trim() }); setNewOut(""); } }}>ADD</button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ===================== REPEATER =====================
// ---- Repeater editor helpers: selection readout + in-editor search ----
// Pure logic kept outside the component so it is unit-testable without a DOM.

function repeaterDisplayChar(ch) {
  if (ch === "\n") return "\\n";
  if (ch === "\t") return "\\t";
  if (ch === "\r") return "\\r";
  if (ch === " ") return "space";
  return ch;
}

// Burp's Inspector "Selection" widget: length + first byte's decimal/hex value.
function repeaterSelectionStats(text, start, end) {
  if (text == null || start == null || end == null || start === end) return null;
  const sel = text.slice(start, end);
  if (!sel.length) return null;
  const code = sel.charCodeAt(0);
  return {
    length: sel.length,
    firstChar: sel[0],
    firstCharDec: code,
    firstCharHex: "0x" + code.toString(16).toUpperCase().padStart(2, "0"),
  };
}

// Case-insensitive substring search returning [start,end) match ranges.
// Capped so a common single-character query against a huge response can't
// hang the tab.
function repeaterFindMatches(text, query, limit) {
  if (!text || !query) return [];
  const cap = limit || 5000;
  const hay = text.toLowerCase();
  const needle = query.toLowerCase();
  const out = [];
  let idx = 0;
  while (idx <= hay.length && out.length < cap) {
    const found = hay.indexOf(needle, idx);
    if (found === -1) break;
    out.push([found, found + needle.length]);
    idx = found + Math.max(needle.length, 1);
  }
  return out;
}

// Wrap-around navigation over a match list; curIdx may be any integer
// (including the initial -1 sentinel) -- normalized modulo matches.length.
function repeaterGotoMatch(matches, curIdx, dir) {
  if (!matches || !matches.length) return null;
  const idx = (((curIdx + dir) % matches.length) + matches.length) % matches.length;
  return { idx, range: matches[idx] };
}

function RepeaterEditorToolbar({ views, active, onView, search, onSearch, matchCount, onNext, onPrev }) {
  return (
    <div className="detail-tabs">
      {views.map(v => (
        <button key={v} className={active === v ? "on" : ""} onClick={() => onView(v)}>{v}</button>
      ))}
      <span className="spacer" />
      <input
        value={search}
        onChange={e => onSearch(e.target.value)}
        onKeyDown={e => {
          if (e.key !== "Enter") return;
          e.preventDefault();
          (e.shiftKey ? onPrev : onNext)();
        }}
        placeholder="find…"
        title="Enter: next match · Shift+Enter: previous match"
        style={{
          width: 110, background: "var(--bg-deep)", color: "var(--text)",
          border: "1px solid var(--line)", fontFamily: "var(--ff-mono)",
          fontSize: "11px", padding: "2px 6px",
        }}
      />
      {search && (
        <span className="ph-count" style={{ cursor: matchCount ? "pointer" : "default" }} onClick={onNext}>
          {matchCount} match{matchCount === 1 ? "" : "es"}
        </span>
      )}
    </div>
  );
}

function RepeaterSelectionReadout({ sel }) {
  return (
    <div style={{
      padding: "3px 10px", borderTop: "1px solid var(--line-soft)",
      color: "var(--dim)", fontSize: "10px", fontFamily: "var(--ff-mono)",
      letterSpacing: "0.05em",
    }}>
      {sel
        ? `SELECTION: ${sel.length} char${sel.length === 1 ? "" : "s"} · first '${repeaterDisplayChar(sel.firstChar)}' dec=${sel.firstCharDec} hex=${sel.firstCharHex}`
        : "SELECTION: none"}
    </div>
  );
}

function RepeaterTab({ rep, dispatch, onSwitchTab }) {
  // Real backend handles the send. We only show a spinner-y label while
  // the snapshot reports busy=true, then flip back to the response.
  const send = () => dispatch({ type: "repeater-send" });
  const busy = rep && rep.busy;

  const sendToComparer = (label, text) => {
    dispatch({ type: "comparer-add", label, text });
    if (onSwitchTab) onSwitchTab("comparer");
  };

  // Live tab strip pulled from the snapshot. Fall back to a single fake
  // entry if the backend hasn't reported tabs yet (older builds).
  const tabs = (window.NL && NL.repeater && NL.repeater.tabs)
                  ? NL.repeater.tabs : [];
  const active = (window.NL && NL.repeater && typeof NL.repeater.activeTab === "number")
                  ? NL.repeater.activeTab : 0;

  const onRename = (i) => {
    const cur = tabs[i] ? tabs[i].name : "";
    const next = prompt("Rename tab", cur);
    if (next !== null && next !== cur) NL.actions.repeaterTabRename(i, next);
  };

  // COPY AS: the request the tester just finished crafting, exported as a
  // command for another tool. Reuses renderRequestAs()/parseRawRequest() from
  // proxy.jsx (both are top-level function declarations, so they live in the
  // shared global scope; proxy.jsx loads before tabs.jsx). Those helpers
  // re-derive method/headers/body from the raw request text and need only the
  // scheme/host/port + path to build the URL, which we assemble from the
  // Repeater target here. Matches Burp's clipboard-based "Copy as curl".
  const [copyOpen, setCopyOpen] = React.useState(false);
  const [copied, setCopied] = React.useState("");

  // Message editor views (#342), sandboxed HTML render (#341), in-editor
  // search (#348) and a Burp-style selection readout (#362).
  const [reqView, setReqView] = React.useState("raw");
  const [respView, setRespView] = React.useState("raw");
  const [reqSearch, setReqSearch] = React.useState("");
  const [respSearch, setRespSearch] = React.useState("");
  const [reqMatchIdx, setReqMatchIdx] = React.useState(-1);
  const [respMatchIdx, setRespMatchIdx] = React.useState(-1);
  const [reqSel, setReqSel] = React.useState(null);
  const [respSel, setRespSel] = React.useState(null);
  const reqRef = React.useRef(null);
  const respRef = React.useRef(null);

  const reqText = reqView === "raw" ? rep.request : renderView(rep.request, reqView);
  const respBody = renderView(rep.response, "body");
  const respText = respView === "raw" ? rep.response : renderView(rep.response, respView);

  const reqMatches = React.useMemo(() => repeaterFindMatches(reqText, reqSearch), [reqText, reqSearch]);
  const respMatches = React.useMemo(() => repeaterFindMatches(respText, respSearch), [respText, respSearch]);

  const jumpReq = (dir) => {
    const hit = repeaterGotoMatch(reqMatches, reqMatchIdx, dir);
    if (!hit || !reqRef.current) return;
    setReqMatchIdx(hit.idx);
    reqRef.current.focus();
    reqRef.current.setSelectionRange(hit.range[0], hit.range[1]);
  };
  const jumpResp = (dir) => {
    const hit = repeaterGotoMatch(respMatches, respMatchIdx, dir);
    if (!hit || !respRef.current) return;
    setRespMatchIdx(hit.idx);
    respRef.current.focus();
    respRef.current.setSelectionRange(hit.range[0], hit.range[1]);
  };
  const onReqSelect = () => {
    const el = reqRef.current;
    if (el) setReqSel(repeaterSelectionStats(el.value, el.selectionStart, el.selectionEnd));
  };
  const onRespSelect = () => {
    const el = respRef.current;
    if (el) setRespSel(repeaterSelectionStats(el.value, el.selectionStart, el.selectionEnd));
  };

  const copyAs = (k) => {
    setCopyOpen(false);
    if (typeof renderRequestAs !== "function") return;
    const firstLine = (rep.request || "").split(/\r?\n/, 1)[0] || "";
    const parts = firstLine.split(" ");
    const row = {
      // id is used only as a label in the postman/nuclei exports; there is no
      // history row behind a Repeater tab, so give it a stable readable tag
      // instead of letting it render as "undefined".
      id: "repeater",
      tls: rep.tls,
      host: rep.host,
      port: parseInt(rep.port, 10) || (rep.tls ? 443 : 80),
      url: parts[1] || "/",
      method: parts[0] || "GET",
    };
    try {
      const out = renderRequestAs(k, row, rep.request);
      const done = () => { setCopied(k); setTimeout(() => setCopied(""), 1200); };
      if (navigator.clipboard && navigator.clipboard.writeText)
        navigator.clipboard.writeText(out).then(done, done);
      else done();
    } catch (e) { /* renderRequestAs is defensive; swallow */ }
  };

  return (
    <div className="tab-body" style={{ gridTemplateRows: "auto auto auto 1fr" }}>
      <div className="pane-head">
        <span className="ph-corner">▸</span>
        <span>REPEATER · one-shot request editor</span>
        <span className="ph-count">{tabs.length} tab{tabs.length === 1 ? "" : "s"}</span>
      </div>

      {/* Tab strip */}
      <div style={{
        display: "flex", alignItems: "stretch", gap: 2,
        padding: "4px 8px", borderBottom: "1px solid var(--line)",
        overflowX: "auto", background: "var(--pane)",
      }}>
        {tabs.map((t, i) => {
          const isActive = i === active;
          return (
            <div key={i}
                 onClick={() => NL.actions.repeaterTabActivate(i)}
                 onDoubleClick={() => onRename(i)}
                 title={(t.host || "") + " · double-click to rename"}
                 style={{
                   display: "flex", alignItems: "center", gap: 6,
                   padding: "4px 8px", cursor: "pointer",
                   background: isActive ? "var(--bg-deep)" : "transparent",
                   color: isActive ? "var(--accent)" : "var(--text-2)",
                   borderTop:    "1px solid " + (isActive ? "var(--accent)" : "var(--line)"),
                   borderLeft:   "1px solid " + (isActive ? "var(--accent)" : "var(--line)"),
                   borderRight:  "1px solid " + (isActive ? "var(--accent)" : "var(--line)"),
                   borderBottom: "1px solid " + (isActive ? "var(--bg-deep)" : "var(--line)"),
                   fontSize: "11px", fontFamily: "var(--ff-mono)",
                   whiteSpace: "nowrap", maxWidth: 240, overflow: "hidden",
                   textOverflow: "ellipsis", marginBottom: -1,
                 }}>
              <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>
                {t.name || ("tab " + (i + 1))}
              </span>
              {t.statusLine && (
                <span style={{ color: "var(--dim)", fontSize: "10px" }}>
                  ·{t.statusLine.split(" ").slice(0, 2).join(" ")}
                </span>
              )}
              <span style={{
                color: "var(--dim)", padding: "0 2px",
                opacity: 0.6,
              }} onClick={(e) => { e.stopPropagation(); NL.actions.repeaterTabClose(i); }}
                 title="close">×</span>
            </div>
          );
        })}
        <button onClick={() => NL.actions.repeaterTabAdd("")}
                title="New tab"
                style={{
                  background: "transparent", color: "var(--accent)",
                  border: "1px dashed var(--line)", padding: "0 10px",
                  fontFamily: "var(--ff-mono)", cursor: "pointer", fontSize: "12px",
                }}>+ NEW</button>
        <button onClick={() => NL.actions.repeaterTabDuplicate(active)}
                title="Duplicate current tab"
                style={{
                  background: "transparent", color: "var(--text-2)",
                  border: "1px dashed var(--line)", padding: "0 8px",
                  fontFamily: "var(--ff-mono)", cursor: "pointer", fontSize: "11px",
                }}>DUP</button>
      </div>

      <div className="target-row">
        <span className="arrow">▶</span>
        <div className="fld" style={{ flex: "0 0 80px" }}>
          <span className="pre">PROTO</span>
          <span style={{ color: rep.tls ? "var(--accent)" : "var(--dim)" }}>{rep.tls ? "HTTPS" : "HTTP"}</span>
        </div>
        <div className="fld" style={{ flex: "1 1 auto" }}>
          <span className="pre">HOST</span>
          <input value={rep.host} onChange={e => dispatch({ type:"repeater-set", payload:{ host: e.target.value }})} />
        </div>
        <div className="fld" style={{ flex: "0 0 90px" }}>
          <span className="pre">:</span>
          <input value={rep.port} onChange={e => dispatch({ type:"repeater-set", payload:{ port: e.target.value }})} />
        </div>
        <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: "var(--fz-xs)", letterSpacing: "0.14em", textTransform: "uppercase", color: "var(--text-2)", cursor: "pointer" }}>
          <input
            type="checkbox"
            checked={rep.tls}
            onChange={e => dispatch({ type:"repeater-set", payload:{ tls: e.target.checked }})}
            style={{ accentColor: "var(--accent)" }}
          />
          TLS
        </label>
        <span style={{ flex: 1 }} />
        <span style={{ color: "var(--dim)", fontSize: "var(--fz-xs)", letterSpacing: "0.14em", textTransform: "uppercase" }}>
          STATUS: <span style={{ color: "var(--accent)" }}>{rep.statusLine}</span>
        </span>
        <div style={{ position: "relative", display: "inline-block" }}>
          <button className="btn" onClick={() => setCopyOpen(o => !o)}
                  title="Copy this request as a command for another tool">
            {copied ? "✓ " + copied.toUpperCase() : "↦ COPY AS ▾"}
          </button>
          {copyOpen && (
            <div onClick={(e) => e.stopPropagation()}
                 style={{
                   position: "absolute", top: "100%", right: 0, zIndex: 30,
                   background: "var(--pane)", border: "1px solid var(--accent)",
                   boxShadow: "0 8px 24px rgba(0,0,0,0.4)",
                   fontFamily: "var(--ff-mono)", fontSize: "11px",
                   minWidth: 180, marginTop: 4,
                 }}>
              {[
                ["curl",       "Unix-y, --insecure for self-signed"],
                ["wget",       "Same syntax shape as curl"],
                ["httpie",     "Cleaner one-liner"],
                ["powershell", "Invoke-WebRequest"],
                ["fetch",      "JavaScript fetch() in browser/node"],
                ["sqlmap",     "Pre-armed sqlmap command line"],
                ["postman",    "Single-item Postman collection JSON"],
                ["nuclei",     "Nuclei template skeleton"],
                ["burp-raw",   "Raw request bytes (Burp Repeater paste)"],
              ].map(([k, hint]) => (
                <div key={k}
                     onClick={() => copyAs(k)}
                     style={{
                       padding: "5px 10px", cursor: "pointer",
                       borderBottom: "1px solid var(--line-soft)",
                       color: "var(--text)",
                     }}>
                  <div style={{ color: "var(--accent)" }}>{k}</div>
                  <div style={{ color: "var(--dim)", fontSize: "10px" }}>{hint}</div>
                </div>
              ))}
            </div>
          )}
        </div>
        <button className="btn" onClick={() => dispatch({ type: "repeater-clear" })}>CLEAR</button>
        <button className="btn primary" onClick={send} disabled={busy}>
          {busy ? "SENDING…" : "▶ SEND"}
        </button>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1px 1fr", height: "100%", minHeight: 0, borderTop: "1px solid var(--line)" }}>
        <div className="pane" style={{ minWidth: 0 }}>
          <div className="pane-head">
            <span style={{ color:"var(--accent-2)" }}>▸</span>
            <span>REQUEST · editable</span>
            <span className="ph-count">{rep.request.split("\n").length} LINES</span>
            <button className="btn" style={{ marginLeft: 6 }} title="Send to Comparer"
                    onClick={() => sendToComparer("repeater request", rep.request)}>↦ CMP</button>
          </div>
          <RepeaterEditorToolbar
            views={["raw", "headers", "body", "preview", "hex"]}
            active={reqView}
            onView={v => { setReqView(v); setReqSearch(""); setReqMatchIdx(-1); }}
            search={reqSearch}
            onSearch={s => { setReqSearch(s); setReqMatchIdx(-1); }}
            matchCount={reqMatches.length}
            onNext={() => jumpReq(1)}
            onPrev={() => jumpReq(-1)}
          />
          {reqView === "raw" ? (
            <textarea
              ref={reqRef}
              className="txt"
              value={rep.request}
              onChange={e => dispatch({ type: "repeater-set", payload: { request: e.target.value }})}
              onKeyDown={e => { if (e.ctrlKey && e.code === "Space") { e.preventDefault(); send(); } }}
              onSelect={onReqSelect}
              onMouseUp={onReqSelect}
              onKeyUp={onReqSelect}
              spellCheck={false}
              title="Ctrl+Space to send"
            />
          ) : (
            <textarea
              ref={reqRef}
              className="txt readonly"
              value={reqText}
              readOnly
              onSelect={onReqSelect}
              onMouseUp={onReqSelect}
              onKeyUp={onReqSelect}
            />
          )}
          <RepeaterSelectionReadout sel={reqSel} />
        </div>
        <div className="divider-v" />
        <div className="pane" style={{ minWidth: 0 }}>
          <div className="pane-head">
            <span style={{ color:"var(--accent)" }}>▸</span>
            <span>RESPONSE · read-only</span>
            <span className="ph-count">{rep.response.split("\n").length} LINES</span>
            <button className="btn" style={{ marginLeft: 6 }} title="Send to Comparer"
                    onClick={() => sendToComparer("repeater response", rep.response)}>↦ CMP</button>
          </div>
          <RepeaterEditorToolbar
            views={["raw", "headers", "body", "preview", "hex", "render"]}
            active={respView}
            onView={v => { setRespView(v); setRespSearch(""); setRespMatchIdx(-1); }}
            search={respSearch}
            onSearch={s => { setRespSearch(s); setRespMatchIdx(-1); }}
            matchCount={respMatches.length}
            onNext={() => jumpResp(1)}
            onPrev={() => jumpResp(-1)}
          />
          {respView === "render" ? (
            <React.Fragment>
              <iframe
                title="repeater-render"
                // Empty sandbox: no scripts, no forms, no same-origin, no
                // popups. A reflected-XSS payload in the response body is
                // rendered inert -- this is a viewer, not a browser.
                sandbox=""
                srcDoc={respBody}
                style={{ width: "100%", height: "100%", border: "none", background: "#fff" }}
              />
              <div style={{
                padding: "3px 10px", borderTop: "1px solid var(--line-soft)",
                color: "var(--dim)", fontSize: "10px", fontFamily: "var(--ff-mono)",
              }}>
                sandboxed static render · scripts and same-origin access blocked
              </div>
            </React.Fragment>
          ) : (
            <React.Fragment>
              <textarea
                ref={respRef}
                className="txt readonly"
                value={respText}
                readOnly
                onSelect={onRespSelect}
                onMouseUp={onRespSelect}
                onKeyUp={onRespSelect}
              />
              <RepeaterSelectionReadout sel={respSel} />
            </React.Fragment>
          )}
        </div>
      </div>
    </div>
  );
}

// ===================== INTERCEPT =====================
function InterceptTab({ intercept, interceptResponses, intercepted, dispatch }) {
  const current = intercepted[0] || null;
  const more = Math.max(0, intercepted.length - 1);

  const [editedText, setEditedText] = React.useState(current ? current.text : "");
  React.useEffect(() => { setEditedText(current ? current.text : ""); }, [current?.id]);

  return (
    <div className="tab-body" style={{ gridTemplateRows: "auto 1fr" }}>
      <div className="icp-toggle">
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div className={"pwr" + (intercept ? " on" : "")} onClick={() => dispatch({ type: "intercept-toggle" })} />
          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            <span style={{ fontSize: "var(--fz-xs)", letterSpacing: "0.18em", textTransform: "uppercase", color: "var(--dim)" }}>
              REQUESTS
            </span>
            <span style={{ fontSize: "var(--fz-md)", color: intercept ? "var(--err)" : "var(--text-2)" }}>
              {intercept ? "held" : "pass through"}
            </span>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div className={"pwr" + (interceptResponses ? " on" : "")} onClick={() => dispatch({ type: "intercept-responses-toggle" })} />
          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            <span style={{ fontSize: "var(--fz-xs)", letterSpacing: "0.18em", textTransform: "uppercase", color: "var(--dim)" }}>
              RESPONSES
            </span>
            <span style={{ fontSize: "var(--fz-md)", color: interceptResponses ? "var(--err)" : "var(--text-2)" }}>
              {interceptResponses ? "held" : "pass through"}
            </span>
          </div>
        </div>
        <span style={{ flex: 1 }} />
        <div className="chip">
          QUEUE <span style={{ color: "var(--accent)", marginLeft: 8, fontSize: "var(--fz-md)" }}>{intercepted.length}</span>
        </div>
        <button className="btn" onClick={() => dispatch({ type: "intercept-forward-all" })} disabled={(!intercept && !interceptResponses) || intercepted.length === 0}>
          FORWARD ALL
        </button>
      </div>

      {current ? (
        <div className="icp-current">
          <div className="icp-meta">
            <span className="id">#{current.id}</span>
            <span className="chip accent">{current.kind === 1 ? "RESPONSE" : "REQUEST"}</span>
            <span className="url">
              <span className="proto">{current.tls ? "https://" : "http://"}</span>
              {current.host}<span className="proto">:{current.port}</span>
            </span>
            <span style={{ flex: 1 }} />
            {more > 0 && (
              <span style={{ color: "var(--warn)", fontSize: "var(--fz-xs)", letterSpacing: "0.14em", textTransform: "uppercase" }} className="blink">
                ▮ {more} more waiting
              </span>
            )}
          </div>
          <textarea
            className="txt"
            value={editedText}
            onChange={e => setEditedText(e.target.value)}
            spellCheck={false}
          />
          <div style={{ display: "flex", gap: 8, padding: 12, borderTop: "1px solid var(--line)", background: "var(--pane-2)" }}>
            <span style={{ color: "var(--dim)", fontSize: "var(--fz-xs)", letterSpacing: "0.14em", textTransform: "uppercase", alignSelf:"center" }}>
              edit then forward, or drop to abort
            </span>
            <span style={{ flex: 1 }} />
            <button className="btn danger" onClick={() => dispatch({ type: "intercept-drop" })}>DROP</button>
            <button className="btn primary" onClick={() => dispatch({ type: "intercept-forward", text: editedText })}>
              ↦ FORWARD
            </button>
          </div>
        </div>
      ) : (
        <div className="icp-empty">
          {(intercept || interceptResponses)
            ? <AsciiRadar label="awaiting next message" />
            : "── intercept off · no queue ──"}
        </div>
      )}
    </div>
  );
}

// ===================== INTRUDER =====================
// Compact payload presets so the user has something to throw at a target
// without first hunting down a wordlist. Curated/short on purpose -- meant
// to be a starting point that the user expands, not an exhaustive bank.
const PAYLOAD_PRESETS = {
  "numbers (1-100)":
    Array.from({ length: 100 }, (_, i) => String(i + 1)).join("\n"),
  "common usernames": [
    "admin","administrator","root","user","test","guest","support",
    "demo","operator","manager","sysadmin","webmaster","ftp","ubuntu",
    "ec2-user","oracle","postgres","mysql",
  ].join("\n"),
  "weak passwords": [
    "password","123456","12345678","qwerty","letmein","admin","welcome",
    "monkey","dragon","master","abc123","iloveyou","Password1","P@ssw0rd",
    "changeme","summer2024","Winter2024!","123456789",
  ].join("\n"),
  "sqli (basic)": [
    "'", "''", "`", "``", "\\\"",
    "' OR '1'='1", "' OR '1'='1' --", "' OR 1=1 --", "\" OR 1=1 --",
    "admin' --", "admin' #", "admin'/*",
    "') OR ('1'='1", "1' UNION SELECT NULL--",
    "'; DROP TABLE users--", "' AND 1=CONVERT(int,(SELECT @@version))--",
    "SLEEP(5)", "1' AND SLEEP(5)--",
  ].join("\n"),
  "xss (basic)": [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "</script><script>alert(1)</script>",
  ].join("\n"),
  "path traversal": [
    "../", "..\\",
    "../etc/passwd", "../../etc/passwd", "../../../etc/passwd", "../../../../etc/passwd",
    "..%2fetc%2fpasswd", "..%252fetc%252fpasswd",
    "..\\windows\\win.ini", "..\\..\\..\\windows\\win.ini",
    "/etc/passwd", "C:\\windows\\win.ini",
    "file:///etc/passwd",
  ].join("\n"),
  "ssrf candidates": [
    "http://127.0.0.1/", "http://127.0.0.1:22/",
    "http://localhost/", "http://[::1]/",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/",
    "http://0.0.0.0/", "http://[0:0:0:0:0:ffff:127.0.0.1]/",
    "gopher://127.0.0.1:6379/_INFO", "file:///etc/passwd",
    "dict://127.0.0.1:11211/stats",
  ].join("\n"),
  "common files": [
    "/.env",".env","/robots.txt","/sitemap.xml","/.git/config","/.git/HEAD",
    "/.svn/entries","/composer.json","/package.json","/web.config","/.htaccess",
    "/wp-config.php","/config.php","/phpinfo.php","/server-status",
    "/admin","/admin/","/manager/html","/.well-known/security.txt",
    "/api","/api/v1","/api/v2","/swagger.json","/openapi.json",
  ].join("\n"),
  "common paths (dir-brute)": [
    "admin","admin/","login","logout","register","signup","signin",
    "dashboard","panel","portal","wp-admin","wp-login.php","phpmyadmin",
    "manager","manage","console","control","controlpanel","setup",
    "install","installer","installation","backup","backups","old",
    "test","tests","testing","dev","development","staging","beta",
    "api","api/v1","api/v2","api/v3","graphql","rest","gateway",
    "swagger","swagger-ui","docs","documentation","help",
    "users","user","accounts","account","profile","profiles",
    "uploads","upload","files","file","media","assets",
    "static","public","private","internal",
    "config","configuration","settings","options",
    "log","logs","logfile","logfiles","trace","traces",
    ".git","/.git/HEAD","/.git/config","/.svn","/.hg","/.bzr",
    ".env",".env.local",".env.production",".env.development",
    ".aws/credentials","credentials.json","keys.json","secrets.json",
    "robots.txt","sitemap.xml","humans.txt","crossdomain.xml",
    "favicon.ico","favicon.png","manifest.json","sw.js",
    ".well-known/security.txt",".well-known/openid-configuration",
    ".well-known/jwks.json",".well-known/acme-challenge/",
    "actuator","actuator/health","actuator/info","actuator/env",
    "metrics","health","healthcheck","ping","status","stats",
    "server-status","server-info","nginx_status",
    "phpinfo.php","info.php","test.php","shell.php","cmd.php",
    "wp-config.php","wp-config.php.bak","wp-config.bak","config.php.bak",
    ".htaccess",".htpasswd",".bash_history",".ssh","id_rsa",
    "web.config","Web.config","global.asax",
    "console","logs/error.log","logs/access.log","error.log","access.log",
    "Trace.axd","trace.axd","elmah.axd",
    "jenkins","hudson","jenkins/login","jenkins/script",
    "kibana","grafana","prometheus","prometheus/api/v1/query",
    "rabbitmq","rabbitmq/api","redis","mongo","mongodb",
    "phpinfo","testfile","cgi-bin","cgi-bin/test","scripts","perl",
  ].join("\n"),
  "fuzz strings (small)": [
    "", "a", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "0","-1","null","NULL","undefined","NaN","Infinity",
    "true","false","[]","{}","[null]",
    "%00","%0a","%0d%0a","%ff"," ","\\n","\\r\\n",
    "../","./","\\\\","\\\\?\\",
    "${jndi:ldap://x}", "{{7*7}}", "<%= 7*7 %>",
  ].join("\n"),
  "user-agents (rotation)": [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/17.4",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "curl/8.6.0", "Wget/1.21.4", "python-requests/2.32.0",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
  ].join("\n"),
};

function IntruderTab({ intruder, dispatch }) {
  const total = intruder.payloads.length;
  const completed = intruder.results.filter(r => r.status !== null).length;
  const pct = total ? Math.round((completed / total) * 100) : 0;

  const [presetMenuOpen, setPresetMenuOpen] = React.useState(false);
  const [hide404, setHide404] = React.useState(false);

  // Quick "set up content discovery" -- prompts for a URL and pre-fills
  // host/port/tls/template/payloads in one shot. Cuts the "type the
  // template by hand" step that scares people away from the Intruder.
  const setupDiscovery = () => {
    const u = prompt("Discovery target URL", "http://" + (intruder.host || "127.0.0.1") + "/");
    if (!u) return;
    let parsed;
    try { parsed = new URL(u); }
    catch { alert("Couldn't parse that URL"); return; }
    const tls = parsed.protocol === "https:";
    const port = parseInt(parsed.port, 10) || (tls ? 443 : 80);
    const host = parsed.hostname;
    // Use root path with §§ marker -- the payload becomes the path itself.
    const template =
      "GET /§§ HTTP/1.1\r\n" +
      "Host: " + host + (port === (tls ? 443 : 80) ? "" : ":" + port) + "\r\n" +
      "User-Agent: Nullock-Discovery\r\n" +
      "Accept: */*\r\n" +
      "Connection: close\r\n\r\n";
    dispatch({ type: "intruder-set", payload: {
      host, port, tls, template,
      payloads: PAYLOAD_PRESETS["common paths (dir-brute)"].split("\n"),
    }});
  };
  const applyPreset = (key, mode) => {
    const text = PAYLOAD_PRESETS[key];
    if (!text) return;
    const lines = text.split("\n");
    const next = mode === "append"
      ? [...intruder.payloads, ...lines]
      : lines;
    dispatch({ type: "intruder-set", payload: { payloads: next.filter(s => s !== undefined) } });
    setPresetMenuOpen(false);
  };

  // Save/load the whole attack (config + result rows) as a JSON document.
  // Export is a GET that returns the saved-run doc; we hand it to the browser
  // as a file download. Load reads a JSON file and POSTs it back (the backend
  // refuses while an attack is running).
  const fileRef = React.useRef(null);
  const doExport = () => {
    NL.actions.intruderExport().then(doc => {
      const safe = (intruder.host || "attack").replace(/[^a-z0-9._-]/gi, "_");
      const blob = new Blob([JSON.stringify(doc, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "nullock-intruder-" + safe + ".json";
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    }).catch(() => alert("Export failed"));
  };
  const doLoad = (file) => {
    const reader = new FileReader();
    reader.onload = () => {
      let doc;
      try { doc = JSON.parse(reader.result); }
      catch { alert("That file isn't valid JSON"); return; }
      NL.actions.intruderLoad(doc).then(res => {
        if (res && res.ok === false)
          alert("Load refused -- stop the running attack first, then load.");
      }).catch(() => alert("Load failed"));
    };
    reader.readAsText(file);
  };

  return (
    <div className="tab-body" style={{ gridTemplateRows: "auto auto auto 1fr" }}>
      <div className="pane-head">
        <span className="ph-corner">▸</span>
        <span>INTRUDER · sniper mode</span>
        <span className="ph-count">
          template uses §marker§ as insertion point
        </span>
      </div>
      <div className="target-row">
        <span className="arrow">▶</span>
        <div className="fld" style={{ flex: "0 0 80px" }}>
          <span className="pre">PROTO</span>
          <span style={{ color: intruder.tls ? "var(--accent)" : "var(--dim)" }}>{intruder.tls ? "HTTPS" : "HTTP"}</span>
        </div>
        <div className="fld" style={{ flex: "1 1 auto" }}>
          <span className="pre">HOST</span>
          <input value={intruder.host} onChange={e => dispatch({ type:"intruder-set", payload:{ host: e.target.value }})} />
        </div>
        <div className="fld" style={{ flex: "0 0 90px" }}>
          <span className="pre">:</span>
          <input value={intruder.port} onChange={e => dispatch({ type:"intruder-set", payload:{ port: e.target.value }})} />
        </div>
        <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: "var(--fz-xs)", letterSpacing: "0.14em", textTransform: "uppercase", color: "var(--text-2)", cursor: "pointer" }}>
          <input type="checkbox" checked={intruder.tls} onChange={e => dispatch({ type:"intruder-set", payload:{ tls: e.target.checked }})} style={{ accentColor: "var(--accent)" }} />
          TLS
        </label>
        <span style={{ flex: 1 }} />
        <span style={{ color: "var(--dim)", fontSize: "var(--fz-xs)", letterSpacing: "0.14em", textTransform: "uppercase" }}>
          PROGRESS <span style={{ color: "var(--accent)" }}>{completed}/{total}</span>
        </span>
        <button className="btn" onClick={setupDiscovery} title="Pre-fill template + a curated wordlist for content discovery">↦ DISCOVERY</button>
        <button className="btn" onClick={() => dispatch({ type: "intruder-clear" })}>CLEAR</button>
        {intruder.running ? (
          <button className="btn danger" onClick={() => dispatch({ type: "intruder-stop" })}>■ STOP</button>
        ) : (
          <button className="btn primary" onClick={() => dispatch({ type: "intruder-start" })}>▶ START</button>
        )}
      </div>

      <div className="target-row">
        <span className="arrow">▶</span>
        <div className="fld" style={{ flex: "1 1 auto" }}>
          <span className="pre">GREP·MATCH</span>
          <input
            placeholder="needles, comma-separated (regex or literal) — flags the Grep column"
            value={intruder.grepMatchText || ""}
            onChange={e => dispatch({ type: "intruder-set", payload: {
              grepMatchText: e.target.value,
              grepMatch: e.target.value.split(/[\n,]/).map(s => s.trim()).filter(Boolean),
            }})}
          />
        </div>
        <div className="fld" style={{ flex: "1 1 auto" }}>
          <span className="pre">GREP·EXTRACT</span>
          <input
            placeholder="regex — 1st capture group fills the Extract column"
            value={intruder.grepExtractRegex || ""}
            onChange={e => dispatch({ type: "intruder-set", payload: {
              grepExtractRegex: e.target.value,
              grepExtract: e.target.value ? { regex: e.target.value } : {},
            }})}
          />
        </div>
        <div className="fld" style={{ flex: "0 0 92px" }}>
          <span className="pre">CONC</span>
          <input
            type="number" min="1" max="64"
            value={intruder.concurrency ?? 10}
            onChange={e => dispatch({ type: "intruder-set", payload: { concurrency: parseInt(e.target.value, 10) || 1 }})}
            title="Max in-flight requests (backend clamps 1..64)"
          />
        </div>
        <div className="fld" style={{ flex: "0 0 120px" }}>
          <span className="pre">THROTTLE·MS</span>
          <input
            type="number" min="0"
            value={intruder.throttleMs ?? 0}
            onChange={e => dispatch({ type: "intruder-set", payload: { throttleMs: parseInt(e.target.value, 10) || 0 }})}
            title="Inter-dispatch delay in milliseconds (0 = as fast as concurrency allows)"
          />
        </div>
        <button className="btn" onClick={doExport} title="Save this attack (config + results) to a JSON file">⭳ SAVE</button>
        <button className="btn" onClick={() => fileRef.current && fileRef.current.click()} title="Load a saved attack from JSON (refused while running)">⭱ LOAD</button>
        <input ref={fileRef} type="file" accept="application/json,.json" style={{ display: "none" }}
               onChange={e => { const f = e.target.files && e.target.files[0]; if (f) doLoad(f); e.target.value = ""; }} />
      </div>

      <div style={{ display: "grid", gridTemplateRows: "1fr 1fr", height: "100%", minHeight: 0, borderTop: "1px solid var(--line)" }}>
        <div style={{ display: "grid", gridTemplateColumns: "1.5fr 1px 1fr", minHeight: 0, borderBottom: "1px solid var(--line)" }}>
          <div className="pane" style={{ minWidth: 0 }}>
            <div className="pane-head">
              <span style={{ color:"var(--accent-2)" }}>▸</span>
              <span>TEMPLATE</span>
              <span className="ph-count">
                {(intruder.template.match(/§/g)?.length || 0) / 2} INSERTION POINT
              </span>
            </div>
            <textarea
              className="txt"
              value={intruder.template}
              onChange={e => dispatch({ type: "intruder-set", payload: { template: e.target.value }})}
              spellCheck={false}
            />
          </div>
          <div className="divider-v" />
          <div className="pane" style={{ minWidth: 0, position: "relative" }}>
            <div className="pane-head">
              <span style={{ color:"var(--accent)" }}>▸</span>
              <span>PAYLOADS</span>
              <span className="ph-count">{intruder.payloads.length}</span>
              <span style={{ flex: 1 }} />
              <button
                onClick={() => setPresetMenuOpen(o => !o)}
                style={{
                  background: "transparent", color: "var(--accent)",
                  border: "1px solid var(--accent)", padding: "2px 8px",
                  fontSize: "10px", fontFamily: "var(--ff-mono)",
                  cursor: "pointer", letterSpacing: "0.04em",
                  textTransform: "uppercase",
                }}
              >+ PRESET ▾</button>
            </div>
            {presetMenuOpen && (
              <div
                onClick={(e) => e.stopPropagation()}
                style={{
                  position: "absolute", top: 28, right: 6, zIndex: 30,
                  background: "var(--pane)", border: "1px solid var(--accent)",
                  boxShadow: "0 8px 24px rgba(0,0,0,0.4)",
                  fontFamily: "var(--ff-mono)", fontSize: "11px",
                  minWidth: 240, maxHeight: 360, overflow: "auto",
                }}>
                <div style={{
                  padding: "6px 10px", color: "var(--dim)", fontSize: "10px",
                  textTransform: "uppercase", letterSpacing: "0.06em",
                  borderBottom: "1px solid var(--line)",
                }}>
                  Load preset
                  <span style={{ float: "right", cursor: "pointer", color: "var(--dim)" }}
                        onClick={() => setPresetMenuOpen(false)}>×</span>
                </div>
                {Object.keys(PAYLOAD_PRESETS).map(k => {
                  const count = PAYLOAD_PRESETS[k].split("\n").length;
                  return (
                    <div key={k} style={{
                      padding: "5px 10px", display: "flex",
                      alignItems: "center", gap: 6,
                      borderBottom: "1px solid var(--line-soft)",
                    }}>
                      <span style={{ flex: 1, color: "var(--text)" }}>
                        {k} <span style={{ color: "var(--dim)" }}>· {count}</span>
                      </span>
                      <button onClick={() => applyPreset(k, "replace")}
                              title="Replace current payloads"
                              style={{
                                background: "transparent", color: "var(--accent)",
                                border: "1px solid var(--line)", padding: "1px 6px",
                                fontSize: "10px", fontFamily: "var(--ff-mono)",
                                cursor: "pointer",
                              }}>SET</button>
                      <button onClick={() => applyPreset(k, "append")}
                              title="Append to current payloads"
                              style={{
                                background: "transparent", color: "var(--text-2)",
                                border: "1px solid var(--line)", padding: "1px 6px",
                                fontSize: "10px", fontFamily: "var(--ff-mono)",
                                cursor: "pointer",
                              }}>+ADD</button>
                    </div>
                  );
                })}
              </div>
            )}
            <textarea
              className="txt"
              value={intruder.payloads.join("\n")}
              onChange={e => dispatch({ type: "intruder-set", payload: { payloads: e.target.value.split("\n").filter(Boolean) }})}
              spellCheck={false}
            />
          </div>
        </div>

        <div className="pane" style={{ minHeight: 0 }}>
          <div className="pane-head">
            <span className="ph-corner">▸</span>
            <span>RESULTS</span>
            <span className="ph-count">{completed} / {total} · {pct}%</span>
            <span style={{ flex: 1 }} />
            <label style={{ fontSize: "10.5px", color: "var(--dim)", display: "flex", gap: 4, alignItems: "center" }}>
              <input type="checkbox" checked={hide404}
                     onChange={e => setHide404(e.target.checked)} />
              hide 404s
            </label>
          </div>
          <div className="progress"><div className="bar" style={{ width: pct + "%" }} /></div>
          <div style={{ overflow: "auto", flex: 1 }}>
            <table className="intruder-results">
              <colgroup>
                <col style={{ width: 50 }} />
                <col style={{ width: 220 }} />
                <col style={{ width: 80 }} />
                <col style={{ width: 100 }} />
                <col style={{ width: 80 }} />
                <col style={{ width: 56 }} />
                <col style={{ width: 150 }} />
                <col />
              </colgroup>
              <thead>
                <tr><th>#</th><th>Payload</th><th>Status</th><th>Size</th><th>Time</th><th title="Grep-match hit">Grep</th><th title="Grep-extract capture">Extract</th><th>Error</th><th></th></tr>
              </thead>
              <tbody>
                {intruder.payloads.map((p, i) => {
                  const r = intruder.results[i] || { status: null, size: 0, ms: 0, err: "", matched: false, extracted: "" };
                  const pending = r.status === null;
                  const cls = (r.status >= 400) ? "s4" : (r.status >= 300) ? "s3" : (r.status >= 200) ? "s2" : "";
                  if (hide404 && r.status === 404) return null;
                  return (
                    <tr key={i} className={pending ? "pending" : ""}>
                      <td>{(i + 1).toString().padStart(3, "0")}</td>
                      <td><span style={{ color: pending ? "var(--dim)" : "var(--text)" }}>{p}</span></td>
                      <td><span className={"status " + cls}>{pending ? "—" : r.status}</span></td>
                      <td>{pending ? "—" : (r.size + " B")}</td>
                      <td>{pending ? "—" : (r.ms + " ms")}</td>
                      <td style={{ textAlign: "center" }}>{pending ? "—" : (r.matched
                        ? <span style={{ color: "var(--accent)", fontWeight: 600 }} title="grep-match hit">✓</span>
                        : <span style={{ color: "var(--dim)" }}>·</span>)}</td>
                      <td style={{ maxWidth: 150, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: r.extracted ? "var(--text)" : "var(--dim)" }}
                          title={r.extracted || ""}>{pending ? "" : (r.extracted || "·")}</td>
                      <td style={{ color: r.err ? "var(--err)" : "var(--dim)" }}>{r.err || (pending ? "queued" : "")}</td>
                      <td>
                        {!intruder.running && !pending && (
                          <button onClick={() => NL.actions.intruderResend(i)}
                                  title={"Resend row " + (i + 1)}
                                  style={{
                                    background: "transparent", color: "var(--accent)",
                                    border: "1px solid var(--line)", padding: "1px 6px",
                                    fontSize: "10px", fontFamily: "var(--ff-mono)", cursor: "pointer",
                                  }}>↻</button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { ScopeTab, RepeaterTab, InterceptTab, IntruderTab });
