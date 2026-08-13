// Scope, Repeater, Intercept, Intruder tabs.

// ===================== SCOPE =====================
// Turn a pasted URL (or bare host) into a host glob. Returns null if the
// text doesn't parse as a URL/host at all.
function urlToScopeGlob(text) {
  const t = text.trim();
  if (!t) return null;
  try {
    const u = new URL(t.includes("://") ? t : "https://" + t);
    return u.hostname || null;
  } catch (e) {
    return null;
  }
}

function ScopeColumn({ label, colorVar, list, kind, dispatch, includeSubdomains }) {
  const [value, setValue] = React.useState("");
  const [editIndex, setEditIndex] = React.useState(null); // index of glob being edited, or null
  const fileRef = React.useRef(null);
  const addType = kind === "in" ? "scope-add-in" : "scope-add-out";
  const removeType = kind === "in" ? "scope-remove-in" : "scope-remove-out";

  function commit() {
    const v = value.trim();
    if (!v) return;
    if (editIndex !== null) {
      dispatch({ type: removeType, index: editIndex });
    }
    dispatch({ type: addType, value: v });
    if (includeSubdomains && editIndex === null && !v.startsWith("*.")) {
      dispatch({ type: addType, value: "*." + v });
    }
    setValue("");
    setEditIndex(null);
  }

  function fromUrl() {
    const glob = urlToScopeGlob(value);
    if (glob) setValue(glob);
  }

  function loadFile(e) {
    const f = e.target.files && e.target.files[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = () => {
      const lines = String(reader.result).split(/\r?\n/).map(s => s.trim()).filter(Boolean);
      lines.forEach(g => dispatch({ type: addType, value: g }));
    };
    reader.readAsText(f);
    e.target.value = "";
  }

  return (
    <div className="scope-col">
      <div className="pane-head" style={{ background: "var(--pane)" }}>
        <span style={{ color: `var(${colorVar})` }}>▸</span>
        <span>{label}</span>
        <span className="ph-count">{list.length}</span>
      </div>
      <div className="scope-list">
        {list.map((g, i) => (
          <div key={g} className={"scope-item " + kind}>
            <span
              className="glob"
              style={{ cursor: "pointer" }}
              title="click to edit"
              onClick={() => { setValue(g); setEditIndex(i); }}
            >{g}</span>
            <span className="rm" onClick={() => dispatch({ type: removeType, index: i })}>×</span>
          </div>
        ))}
        {list.length === 0 && <div style={{ padding: 16, color: "var(--dim)", fontSize: "var(--fz-sm)" }}>{kind === "in" ? "nothing in scope — all hosts captured" : "no exclusions"}</div>}
      </div>
      <div className="scope-add" style={{ flexWrap: "wrap", rowGap: 6 }}>
        <div className="fld" style={{ flex: 1, minWidth: 160 }}>
          <span className="pre">{editIndex !== null ? "EDIT" : (kind === "in" ? "+IN" : "+OUT")}</span>
          <input
            placeholder="e.g. acme.corp, *.acme.corp, or paste a URL"
            value={value}
            onChange={e => setValue(e.target.value)}
            onKeyDown={e => { if (e.key === "Enter") commit(); if (e.key === "Escape") { setValue(""); setEditIndex(null); } }}
          />
        </div>
        <button className="btn" title="Convert a pasted URL into a host glob" onClick={fromUrl}>URL→HOST</button>
        <button className="btn" onClick={() => fileRef.current && fileRef.current.click()}>LOAD FILE</button>
        <input ref={fileRef} type="file" accept=".txt,.csv" style={{ display: "none" }} onChange={loadFile} />
        <button className="btn" onClick={commit}>{editIndex !== null ? "SAVE" : "ADD"}</button>
        {editIndex !== null && <button className="btn ghost" onClick={() => { setValue(""); setEditIndex(null); }}>CANCEL</button>}
      </div>
    </div>
  );
}

function ScopeTab({ scope, dispatch, bootInfo, onCopyCa }) {
  const [includeSubdomains, setIncludeSubdomains] = React.useState(true);
  const [copied, setCopied] = React.useState(false);
  const [notesDraft, setNotesDraft] = React.useState(scope.notes || "");
  const [notesDirty, setNotesDirty] = React.useState(false);
  const [notesSaved, setNotesSaved] = React.useState(false);

  // Stay in sync with the snapshot (e.g. another client editing the same
  // project) except while the user has unsaved local edits -- otherwise a
  // poll mid-typing would stomp on what they're writing.
  React.useEffect(() => {
    if (!notesDirty) setNotesDraft(scope.notes || "");
  }, [scope.notes, notesDirty]);

  const saveNotes = () => {
    dispatch({ type: "scope-set-notes", value: notesDraft });
    setNotesDirty(false);
    setNotesSaved(true);
    setTimeout(() => setNotesSaved(false), 1400);
  };

  return (
    <div className="tab-body" style={{ gridTemplateRows: "auto auto auto 1fr" }}>
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
        <label style={{ display: "flex", alignItems: "center", gap: 6, cursor: "pointer", color: "var(--dim)", fontSize: "var(--fz-xs)" }}>
          <input type="checkbox" checked={includeSubdomains} onChange={e => setIncludeSubdomains(e.target.checked)} />
          include subdomains when adding
        </label>
        <span className="ph-count">project: {bootInfo.project}</span>
      </div>

      <div style={{ padding: "8px 10px", borderTop: "1px solid var(--line)", display: "flex", flexDirection: "column", gap: 4 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span className="ph-corner">▸</span>
          <span style={{ fontSize: "var(--fz-xs)", letterSpacing: "0.06em", textTransform: "uppercase", color: "var(--dim)" }}>Notes</span>
          <span style={{ flex: 1 }} />
          {notesDirty && <span style={{ fontSize: "var(--fz-xs)", color: "var(--accent)" }}>unsaved</span>}
          <button className="btn" disabled={!notesDirty} onClick={saveNotes}>
            {notesSaved ? "✓ SAVED" : "SAVE"}
          </button>
        </div>
        <textarea
          value={notesDraft}
          onChange={e => { setNotesDraft(e.target.value); setNotesDirty(true); }}
          onBlur={() => { if (notesDirty) saveNotes(); }}
          onKeyDown={e => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); saveNotes(); } }}
          placeholder="free-text engagement notes for this project…"
          style={{
            width: "100%", minHeight: 44, maxHeight: 120, resize: "vertical",
            background: "var(--bg-deep)", color: "var(--text)",
            border: "1px solid var(--line)", fontFamily: "var(--ff-mono)",
            fontSize: "var(--fz-sm)", padding: "6px 8px", boxSizing: "border-box",
          }}
        />
      </div>

      <div className="scope-grid">
        <ScopeColumn label="IN-SCOPE GLOBS" colorVar="--ok" list={scope.in} kind="in" dispatch={dispatch} includeSubdomains={includeSubdomains} />
        <ScopeColumn label="OUT-OF-SCOPE GLOBS" colorVar="--err" list={scope.out} kind="out" dispatch={dispatch} includeSubdomains={includeSubdomains} />
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

// Substring (or regex) search returning [start,end) match ranges.
// Capped so a common single-character query against a huge response can't
// hang the tab. opts: { caseSensitive, regex } -- both default false, so
// the default behavior (case-insensitive plain substring) is unchanged.
function repeaterFindMatches(text, query, opts, limit) {
  if (!text || !query) return [];
  const cap = limit || 5000;
  const o = opts || {};
  const out = [];

  if (o.regex) {
    let re;
    try { re = new RegExp(query, o.caseSensitive ? "g" : "gi"); }
    catch (e) { return []; } // invalid pattern mid-typing -- no matches, no throw
    let m;
    let guard = 0;
    while ((m = re.exec(text)) !== null && out.length < cap) {
      const end = m.index + Math.max(m[0].length, 1);
      out.push([m.index, m.index + m[0].length]);
      re.lastIndex = end; // guarantee progress on zero-length matches
      if (++guard > cap * 2) break;
    }
    return out;
  }

  const hay = o.caseSensitive ? text : text.toLowerCase();
  const needle = o.caseSensitive ? query : query.toLowerCase();
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

function RepeaterEditorToolbar({
  views, active, onView, search, onSearch, matchCount, onNext, onPrev,
  caseSensitive, onCaseSensitive, regex, onRegex,
}) {
  const toggleStyle = (on) => ({
    background: on ? "var(--accent)" : "transparent",
    color: on ? "var(--bg)" : "var(--dim)",
    border: "1px solid " + (on ? "var(--accent)" : "var(--line)"),
    fontFamily: "var(--ff-mono)", fontSize: "9.5px", padding: "2px 5px",
    cursor: "pointer", letterSpacing: "0.04em",
  });
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
      <button
        title="Case-sensitive search"
        style={toggleStyle(caseSensitive)}
        onClick={() => onCaseSensitive(!caseSensitive)}
      >Aa</button>
      <button
        title="Regex search (JavaScript regex syntax)"
        style={toggleStyle(regex)}
        onClick={() => onRegex(!regex)}
      >.*</button>
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

// Burp's Inspector: a docked structured side panel, live in the message
// editor, not a separate paste-and-parse tool. Reuses the same /api/inspect
// backend as the standalone INSPECTOR tab, but is scoped to whichever
// Repeater pane it is mounted in and re-runs whenever that pane's text
// changes (debounced so keystrokes in the request editor don't spam the
// backend).
function repeaterInspectorKV(rows) {
  const th = { textAlign: "left", color: "var(--dim)", fontWeight: 500, padding: "2px 8px 2px 0", whiteSpace: "nowrap", verticalAlign: "top" };
  const td = { padding: "2px 8px 2px 0", wordBreak: "break-all", color: "var(--text)" };
  return (
    <table style={{ borderCollapse: "collapse", fontSize: "11.5px", fontFamily: "var(--ff-mono)", width: "100%" }}>
      <tbody>{(rows || []).map((r, i) => (
        <tr key={i}><td style={th}>{r.name}</td><td style={td}>{String(r.value == null ? "" : r.value)}</td></tr>
      ))}</tbody>
    </table>
  );
}
function RepeaterInspectorSection({ title, children }) {
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ fontSize: "9.5px", color: "var(--accent)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 3 }}>{title}</div>
      {children}
    </div>
  );
}
function RepeaterInspectorPanel({ raw, kind, sel }) {
  const [view, setView] = React.useState(null);
  const [err, setErr] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  React.useEffect(() => {
    if (!raw || !raw.trim()) { setView(null); setErr(""); return; }
    let cancelled = false;
    setBusy(true);
    const t = setTimeout(() => {
      NL.actions.inspect(raw, kind).then(r => {
        if (cancelled) return;
        setBusy(false);
        if (r && r.ok) { setView(r.view || {}); setErr(""); }
        else { setView(null); setErr((r && r.error) || "inspect failed"); }
      }).catch(e => {
        if (cancelled) return;
        setBusy(false);
        setView(null);
        setErr(String(e && e.message ? e.message : e));
      });
    }, 250);
    return () => { cancelled = true; clearTimeout(t); };
  }, [raw, kind]);

  const isResp = kind === "response";
  const Section = RepeaterInspectorSection;
  const KV = repeaterInspectorKV;

  // Burp's Inspector "Selection Info" widget (#362): length + first byte's
  // decimal/hex value for whatever text was last highlighted in this pane's
  // editor (raw/headers/body/hex), fed in by the caller and kept live even
  // while this Inspector view itself is the active tab.
  const selectionSection = (
    <Section title="Selection">
      {sel ? (
        <KV rows={[
          { name: "length", value: sel.length + " char" + (sel.length === 1 ? "" : "s") },
          { name: "first char", value: repeaterDisplayChar(sel.firstChar) },
          { name: "decimal", value: sel.firstCharDec },
          { name: "hex", value: sel.firstCharHex },
        ]} />
      ) : (
        <span style={{ color: "var(--dim)", fontSize: "11px" }}>nothing selected</span>
      )}
    </Section>
  );

  return (
    <div style={{ flex: 1, overflow: "auto", padding: "10px 12px", minHeight: 0 }}>
      {selectionSection}
      {!raw || !raw.trim() ? (
        <span style={{ color: "var(--dim)", fontSize: "11.5px" }}>nothing to inspect yet</span>
      ) : err ? (
        <span style={{ color: "var(--err)", fontSize: "11.5px" }}>{err}</span>
      ) : !view ? (
        <span style={{ color: "var(--dim)", fontSize: "11.5px" }}>{busy ? "parsing…" : "structured breakdown appears here"}</span>
      ) : isResp ? (
        <div>
          <Section title="Status line">
            <KV rows={[{ name: "version", value: view.version }, { name: "status", value: view.status }, { name: "reason", value: view.reason }, { name: "content-type", value: view.contentType }, { name: "body size", value: view.bodySize }]} />
          </Section>
          {view.headers && view.headers.length ? <Section title={"Headers (" + view.headers.length + ")"}><KV rows={view.headers} /></Section> : null}
          {view.setCookies && view.setCookies.length ? <Section title={"Set-Cookie (" + view.setCookies.length + ")"}>
            {repeaterInspectorKV(view.setCookies.map(c => ({ name: c.name, value: c.value + (c.attributes ? "  [" + c.attributes + "]" : "") })))}
          </Section> : null}
          {view.jwts && view.jwts.length ? <Section title={"JWTs decoded (" + view.jwts.length + ")"}>
            {view.jwts.map((j, i) => (
              <div key={i} style={{ marginBottom: 6 }}>
                <div style={{ color: "var(--dim)", fontSize: "10.5px" }}>{j.where} · alg={j.alg || "?"}</div>
                <pre style={{ margin: 0, fontSize: "10.5px", whiteSpace: "pre-wrap", wordBreak: "break-all", color: "var(--text-2)" }}>
                  {JSON.stringify(j.payload == null ? { header: j.header } : { header: j.header, payload: j.payload }, null, 2)}
                </pre>
              </div>
            ))}
          </Section> : null}
        </div>
      ) : (
        <div>
          <Section title="Request line">
            <KV rows={[{ name: "method", value: view.method }, { name: "path", value: view.path }, { name: "version", value: view.version }, { name: "content-type", value: view.contentType }, { name: "body size", value: view.bodySize }, { name: "body kind", value: view.bodyKind }]} />
          </Section>
          {view.queryParams && view.queryParams.length ? <Section title={"Query params (" + view.queryParams.length + ")"}><KV rows={view.queryParams} /></Section> : null}
          {view.headers && view.headers.length ? <Section title={"Headers (" + view.headers.length + ")"}><KV rows={view.headers} /></Section> : null}
          {view.cookies && view.cookies.length ? <Section title={"Cookies (" + view.cookies.length + ")"}><KV rows={view.cookies} /></Section> : null}
          {view.bodyParams && view.bodyParams.length ? <Section title={"Body params (" + view.bodyParams.length + ")"}><KV rows={view.bodyParams} /></Section> : null}
          {view.jwts && view.jwts.length ? <Section title={"JWTs decoded (" + view.jwts.length + ")"}>
            {view.jwts.map((j, i) => (
              <div key={i} style={{ marginBottom: 6 }}>
                <div style={{ color: "var(--dim)", fontSize: "10.5px" }}>{j.where} · alg={j.alg || "?"}</div>
                <pre style={{ margin: 0, fontSize: "10.5px", whiteSpace: "pre-wrap", wordBreak: "break-all", color: "var(--text-2)" }}>
                  {JSON.stringify(j.payload == null ? { header: j.header } : { header: j.header, payload: j.payload }, null, 2)}
                </pre>
              </div>
            ))}
          </Section> : null}
        </div>
      )}
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
  const sendToDecoder = (label, text) => {
    dispatch({ type: "send-to-decoder", label, text });
    if (onSwitchTab) onSwitchTab("decoder");
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

  const onNotes = (i) => {
    const cur = tabs[i] ? (tabs[i].notes || "") : "";
    const next = prompt("Notes for this tab (what are you testing?)", cur);
    if (next !== null && next !== cur) NL.actions.repeaterTabNotes(i, next);
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
  const [reqCaseSensitive, setReqCaseSensitive] = React.useState(false);
  const [respCaseSensitive, setRespCaseSensitive] = React.useState(false);
  const [reqRegex, setReqRegex] = React.useState(false);
  const [respRegex, setRespRegex] = React.useState(false);
  const [reqSel, setReqSel] = React.useState(null);
  const [respSel, setRespSel] = React.useState(null);
  const reqRef = React.useRef(null);
  const respRef = React.useRef(null);

  const reqText = reqView === "raw" ? rep.request : renderView(rep.request, reqView);
  const respBody = renderView(rep.response, "body");
  const respText = respView === "raw" ? rep.response : renderView(rep.response, respView);

  const reqMatches = React.useMemo(
    () => repeaterFindMatches(reqText, reqSearch, { caseSensitive: reqCaseSensitive, regex: reqRegex }),
    [reqText, reqSearch, reqCaseSensitive, reqRegex]
  );
  const respMatches = React.useMemo(
    () => repeaterFindMatches(respText, respSearch, { caseSensitive: respCaseSensitive, regex: respRegex }),
    [respText, respSearch, respCaseSensitive, respRegex]
  );

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
                 title={(t.host || "") + " · double-click to rename"
                        + (t.notes ? ("\nnotes: " + t.notes) : "")}
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
              {t.notes && (
                <span style={{ color: "var(--accent-2)", fontSize: "10px" }} title={t.notes}>✎</span>
              )}
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
        <button onClick={() => onNotes(active)}
                title="Edit notes for the current tab"
                style={{
                  background: "transparent", color: "var(--text-2)",
                  border: "1px dashed var(--line)", padding: "0 8px",
                  fontFamily: "var(--ff-mono)", cursor: "pointer", fontSize: "11px",
                }}>NOTES</button>
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
            <button className="btn" style={{ marginLeft: 6 }} title="Send to Decoder"
                    onClick={() => sendToDecoder("repeater request", rep.request)}>↦ DEC</button>
          </div>
          <RepeaterEditorToolbar
            views={["raw", "headers", "body", "preview", "hex", "inspector"]}
            active={reqView}
            onView={v => { setReqView(v); setReqSearch(""); setReqMatchIdx(-1); }}
            search={reqSearch}
            onSearch={s => { setReqSearch(s); setReqMatchIdx(-1); }}
            matchCount={reqMatches.length}
            onNext={() => jumpReq(1)}
            onPrev={() => jumpReq(-1)}
            caseSensitive={reqCaseSensitive}
            onCaseSensitive={v => { setReqCaseSensitive(v); setReqMatchIdx(-1); }}
            regex={reqRegex}
            onRegex={v => { setReqRegex(v); setReqMatchIdx(-1); }}
          />
          {reqView === "inspector" ? (
            <RepeaterInspectorPanel raw={rep.request} kind="request" sel={reqSel} />
          ) : reqView === "raw" ? (
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
          {reqView !== "inspector" && <RepeaterSelectionReadout sel={reqSel} />}
        </div>
        <div className="divider-v" />
        <div className="pane" style={{ minWidth: 0 }}>
          <div className="pane-head">
            <span style={{ color:"var(--accent)" }}>▸</span>
            <span>RESPONSE · read-only</span>
            <span className="ph-count">{rep.response.split("\n").length} LINES</span>
            <button className="btn" style={{ marginLeft: 6 }} title="Send to Comparer"
                    onClick={() => sendToComparer("repeater response", rep.response)}>↦ CMP</button>
            <button className="btn" style={{ marginLeft: 6 }} title="Send to Decoder"
                    onClick={() => sendToDecoder("repeater response", rep.response)}>↦ DEC</button>
          </div>
          <RepeaterEditorToolbar
            views={["raw", "headers", "body", "preview", "hex", "render", "inspector"]}
            active={respView}
            onView={v => { setRespView(v); setRespSearch(""); setRespMatchIdx(-1); }}
            search={respSearch}
            onSearch={s => { setRespSearch(s); setRespMatchIdx(-1); }}
            matchCount={respMatches.length}
            onNext={() => jumpResp(1)}
            onPrev={() => jumpResp(-1)}
            caseSensitive={respCaseSensitive}
            onCaseSensitive={v => { setRespCaseSensitive(v); setRespMatchIdx(-1); }}
            regex={respRegex}
            onRegex={v => { setRespRegex(v); setRespMatchIdx(-1); }}
          />
          {respView === "inspector" ? (
            <RepeaterInspectorPanel raw={rep.response} kind="response" sel={respSel} />
          ) : respView === "render" ? (
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
// Response modification helpers -- Burp's eight one-click client-side-control
// removals (Proxy > Options > Response Modification), reproduced here as
// manual per-message transforms applied to a held response's raw text
// (status line + headers + body) before it's forwarded. Unlike Burp's
// checkboxes these aren't a standing auto-apply setting -- each is a
// one-shot edit on the currently-held item -- so the gap is closed as
// "partial", not "present".
function respUnhideHiddenFields(text) {
  return text.replace(/type\s*=\s*(["'])hidden\1/gi, "type=$1text$1");
}
function respEnableDisabledFields(text) {
  return text.replace(/\s+disabled(=["'][^"']*["'])?/gi, "");
}
function respRemoveLengthLimits(text) {
  return text.replace(/\s+maxlength\s*=\s*(["']?)\d+\1/gi, "");
}
function respRemoveJsValidation(text) {
  return text
    .replace(/\s+required(=["'][^"']*["'])?/gi, "")
    .replace(/\s+pattern=(["'])[^"']*\1/gi, "")
    .replace(/\s+onsubmit=(["'])[^"']*\1/gi, "");
}
function respRemoveAllJs(text) {
  return text
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "")
    .replace(/\s+on[a-z]+=(["'])[^"']*\1/gi, "");
}
function respRemoveObjectTags(text) {
  return text.replace(/<object\b[^>]*>[\s\S]*?<\/object>/gi, "");
}
function respHttpsToHttp(text) {
  return text.replace(/https:\/\//gi, "http://");
}
function respStripSecureCookie(text) {
  return text.replace(/^(Set-Cookie:.*?);\s*Secure(?=\s*(;|$))/gim, "$1");
}

function InterceptTab({ intercept, interceptResponses, intercepted, dispatch, onSwitchTab }) {
  const current = intercepted[0] || null;
  const more = Math.max(0, intercepted.length - 1);

  const [editedText, setEditedText] = React.useState(current ? current.text : "");
  React.useEffect(() => { setEditedText(current ? current.text : ""); }, [current?.id]);

  const sendToRepeater = () => current && dispatch({ type: "send-to-repeater-raw", host: current.host, port: current.port, tls: current.tls, text: editedText });
  const sendToIntruder = () => current && dispatch({ type: "send-to-intruder-raw", host: current.host, port: current.port, tls: current.tls, text: editedText });
  const sendToComparer = () => {
    if (!current) return;
    dispatch({ type: "comparer-add", label: (current.kind === 1 ? "intercept response" : "intercept request") + " #" + current.id, text: editedText });
    if (onSwitchTab) onSwitchTab("comparer");
  };
  const sendToDecoder = () => {
    if (!current) return;
    dispatch({ type: "send-to-decoder", label: (current.kind === 1 ? "intercept response" : "intercept request") + " #" + current.id, text: editedText });
    if (onSwitchTab) onSwitchTab("decoder");
  };

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
            {current.kind !== 1 && (
              <button className="btn" style={{ padding: "2px 8px", fontSize: "var(--fz-xs)" }} title="send this held request to Repeater" onClick={sendToRepeater}>↦ REP</button>
            )}
            {current.kind !== 1 && (
              <button className="btn" style={{ padding: "2px 8px", fontSize: "var(--fz-xs)" }} title="send this held request to Intruder" onClick={sendToIntruder}>↦ INT</button>
            )}
            <button className="btn" style={{ padding: "2px 8px", fontSize: "var(--fz-xs)" }} title="send this held message to Comparer" onClick={sendToComparer}>↦ CMP</button>
            <button className="btn" style={{ padding: "2px 8px", fontSize: "var(--fz-xs)" }} title="send this held message to Decoder" onClick={sendToDecoder}>↦ DEC</button>
            {more > 0 && (
              <span style={{ color: "var(--warn)", fontSize: "var(--fz-xs)", letterSpacing: "0.14em", textTransform: "uppercase" }} className="blink">
                ▮ {more} more waiting
              </span>
            )}
          </div>
          {current.kind === 1 && (
            <div style={{ display: "flex", gap: 8, padding: "6px 12px", borderBottom: "1px solid var(--line)", background: "var(--pane-2)", flexWrap: "wrap" }}>
              <span style={{ color: "var(--dim)", fontSize: "var(--fz-xs)", letterSpacing: "0.14em", textTransform: "uppercase", alignSelf: "center" }}>
                response mods:
              </span>
              <button className="btn" style={{ padding: "2px 8px", fontSize: "var(--fz-xs)" }} onClick={() => setEditedText(t => respUnhideHiddenFields(t))}>UNHIDE FIELDS</button>
              <button className="btn" style={{ padding: "2px 8px", fontSize: "var(--fz-xs)" }} onClick={() => setEditedText(t => respEnableDisabledFields(t))}>ENABLE DISABLED</button>
              <button className="btn" style={{ padding: "2px 8px", fontSize: "var(--fz-xs)" }} onClick={() => setEditedText(t => respRemoveLengthLimits(t))}>REMOVE LENGTH LIMITS</button>
              <button className="btn" style={{ padding: "2px 8px", fontSize: "var(--fz-xs)" }} onClick={() => setEditedText(t => respRemoveJsValidation(t))}>REMOVE JS VALIDATION</button>
              <button className="btn" style={{ padding: "2px 8px", fontSize: "var(--fz-xs)" }} onClick={() => setEditedText(t => respRemoveAllJs(t))}>REMOVE ALL JS</button>
              <button className="btn" style={{ padding: "2px 8px", fontSize: "var(--fz-xs)" }} onClick={() => setEditedText(t => respRemoveObjectTags(t))}>REMOVE OBJECT TAGS</button>
              <button className="btn" style={{ padding: "2px 8px", fontSize: "var(--fz-xs)" }} onClick={() => setEditedText(t => respHttpsToHttp(t))}>HTTPS -&gt; HTTP LINKS</button>
              <button className="btn" style={{ padding: "2px 8px", fontSize: "var(--fz-xs)" }} onClick={() => setEditedText(t => respStripSecureCookie(t))}>STRIP SECURE FLAG</button>
            </div>
          )}
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

const ATTACK_TYPES = [
  { v: 0, label: "sniper" },
  { v: 1, label: "battering ram" },
  { v: 2, label: "pitchfork" },
  { v: 3, label: "cluster bomb" },
];

const RULE_OPS_FALLBACK = [
  "prefix", "suffix", "uppercase", "lowercase", "reverse", "match-replace",
  "base64-encode", "base64url-encode", "url-encode", "hex-encode",
  "html-encode", "unicode-escape", "rot13", "md5", "sha1", "sha256", "sha512",
];

const RESULT_COLS = [
  ["#", "#"], ["payload", "Payload"], ["status", "Status"], ["size", "Size"],
  ["ms", "Time"], ["matched", "Grep"], ["extracted", "Extract"], ["err", "Error"],
];

function IntruderTab({ intruder, dispatch }) {
  const total = intruder.payloads.length;
  const completed = intruder.results.filter(r => r.status !== null).length;
  const pct = total ? Math.round((completed / total) * 100) : 0;

  const [presetMenuOpen, setPresetMenuOpen] = React.useState(false);
  const [hide404, setHide404] = React.useState(false);
  const [templateView, setTemplateView] = React.useState("edit"); // edit|inspector
  const templateRef = React.useRef(null);
  const [ruleOps, setRuleOps] = React.useState(RULE_OPS_FALLBACK);

  // Discover the live rule-op list from the backend once (falls back to the
  // static list above if the fetch fails -- the ops rarely change).
  React.useEffect(() => {
    NL.actions.intruderRuleOps().then(res => {
      if (res && Array.isArray(res.operations) && res.operations.length)
        setRuleOps(res.operations);
    }).catch(() => {});
  }, []);

  // Generator dialog -- server-side payload generation (numbers/dates/
  // brute forcer). The engine+API already exist (intruder_generators.cpp);
  // this is purely a GUI on top of /api/intruder/generate (live preview)
  // and /api/intruder/set {generator} (apply, which fills payload set 0).
  const [genMenuOpen, setGenMenuOpen] = React.useState(false);
  const [genTypes, setGenTypes] = React.useState(["numbers", "dates", "brute"]);
  const [genType, setGenType] = React.useState("numbers");
  const [genNumbers, setGenNumbers] = React.useState({ from: "1", to: "10", step: "1", width: "0", hex: false });
  const [genDates, setGenDates] = React.useState({ from: "", to: "", stepDays: "1", format: "yyyy-MM-dd" });
  const [genBrute, setGenBrute] = React.useState({ charset: "abc123", minLen: "1", maxLen: "3" });
  const [genPreview, setGenPreview] = React.useState(null);
  const [genErr, setGenErr] = React.useState("");

  React.useEffect(() => {
    NL.actions.intruderGeneratorTypes().then(res => {
      if (res && Array.isArray(res.types) && res.types.length) setGenTypes(res.types);
    }).catch(() => {});
  }, []);

  const buildGenSpec = () => {
    if (genType === "numbers") {
      return {
        type: "numbers",
        from: Number(genNumbers.from) || 0,
        to: Number(genNumbers.to) || 0,
        step: Number(genNumbers.step) || 1,
        width: Number(genNumbers.width) || 0,
        hex: !!genNumbers.hex,
      };
    }
    if (genType === "dates") {
      return {
        type: "dates",
        from: genDates.from,
        to: genDates.to,
        stepDays: Number(genDates.stepDays) || 1,
        format: genDates.format || "yyyy-MM-dd",
      };
    }
    if (genType === "brute") {
      return {
        type: "brute",
        charset: genBrute.charset,
        minLen: Number(genBrute.minLen) || 1,
        maxLen: Number(genBrute.maxLen) || 1,
      };
    }
    return { type: genType };
  };

  // Live count+sample preview, debounced while the dialog is open and the
  // user is still typing.
  React.useEffect(() => {
    if (!genMenuOpen) return;
    const spec = buildGenSpec();
    const t = setTimeout(() => {
      NL.actions.intruderGenerate(spec)
        .then(res => { setGenPreview(res); setGenErr(""); })
        .catch(() => { setGenPreview(null); setGenErr("preview failed"); });
    }, 250);
    return () => clearTimeout(t);
  }, [genMenuOpen, genType, genNumbers, genDates, genBrute]);

  // Apply: POST the generator spec directly (not through the local
  // intruder-set dispatch) -- the full expansion can exceed what the
  // preview samples, so we let the next snapshot poll bring the real
  // payloads array back rather than guessing it client-side.
  const applyGenerator = () => {
    NL.actions.intruderSet({ generator: buildGenSpec() });
    setGenMenuOpen(false);
  };

  const attackType = intruder.attackType ?? 0;
  const posCount = Math.floor((intruder.template.match(/§/g) || []).length / 2);
  const isMultiSet = (attackType === 2 || attackType === 3) && posCount > 1;

  const setPayloadColumn = (idx, text) => {
    const lines = text.split("\n");
    const cur = intruder.payloadSets || [];
    const next = Array.from({ length: posCount }, (_, k) => (k < cur.length ? cur[k] : []));
    next[idx] = lines;
    dispatch({ type: "intruder-set", payload: { payloadSets: next } });
  };

  const rules = intruder.rules || [];
  const addRule = () => dispatch({ type: "intruder-set", payload: { rules: [...rules, { op: ruleOps[0] || "prefix", arg: "" }] } });
  const updateRule = (i, patch) => dispatch({ type: "intruder-set", payload: { rules: rules.map((r, idx) => idx === i ? { ...r, ...patch } : r) } });
  const removeRule = (i) => dispatch({ type: "intruder-set", payload: { rules: rules.filter((_, idx) => idx !== i) } });
  const moveRule = (i, dir) => {
    const j = i + dir;
    if (j < 0 || j >= rules.length) return;
    const next = [...rules];
    [next[i], next[j]] = [next[j], next[i]];
    dispatch({ type: "intruder-set", payload: { rules: next } });
  };

  const [statusOn, setStatusOn] = React.useState({ 2: true, 3: true, 4: true, 5: true });
  const [minLen, setMinLen] = React.useState("");
  const [maxLen, setMaxLen] = React.useState("");
  const [resultFilter, setResultFilter] = React.useState("");
  const [sortKey, setSortKey] = React.useState(null);
  const [sortDir, setSortDir] = React.useState(1);
  const toggleSort = (key) => {
    if (sortKey === key) { if (sortDir === 1) setSortDir(-1); else { setSortKey(null); setSortDir(1); } }
    else { setSortKey(key); setSortDir(1); }
  };

  let viewRows = intruder.payloads.map((p, i) => ({
    p, i, r: intruder.results[i] || { status: null, size: 0, ms: 0, err: "", matched: false, extracted: "" },
  })).filter(({ p, r }) => intruderRowVisible(p, r, { hide404, statusOn, minLen, maxLen, search: resultFilter }));
  if (sortKey) {
    viewRows = [...viewRows].sort((a, b) => {
      const va = intruderSortValue(a.p, a.r, a.i, sortKey);
      const vb = intruderSortValue(b.p, b.r, b.i, sortKey);
      if (va < vb) return -sortDir;
      if (va > vb) return sortDir;
      return 0;
    });
  }

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
        <span>INTRUDER · {ATTACK_TYPES.find(a => a.v === attackType)?.label || "sniper"} mode</span>
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
        <div className="fld" style={{ flex: "0 0 150px" }}>
          <span className="pre">MODE</span>
          <select style={{ border: "none", background: "transparent", color: "var(--text)", flex: 1, height: "100%" }}
                  value={attackType}
                  onChange={e => dispatch({ type: "intruder-set", payload: { attackType: parseInt(e.target.value, 10) } })}
                  title="Attack type: how payload sets combine across insertion points">
            {ATTACK_TYPES.map(a => <option key={a.v} value={a.v}>{a.label}</option>)}
          </select>
        </div>
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

      <div style={{ display: "grid", gridTemplateRows: "1fr auto 1fr", height: "100%", minHeight: 0, borderTop: "1px solid var(--line)" }}>
        <div style={{ display: "grid", gridTemplateColumns: "1.5fr 1px 1fr", minHeight: 0, borderBottom: "1px solid var(--line)" }}>
          <div className="pane" style={{ minWidth: 0 }}>
            <div className="pane-head">
              <span style={{ color:"var(--accent-2)" }}>▸</span>
              <span>TEMPLATE</span>
              <span className="ph-count">
                {posCount} INSERTION POINT{posCount === 1 ? "" : "S"}
              </span>
              <button className="btn" style={{ marginLeft: 6 }} disabled={templateView !== "edit"}
                      title="Wrap the current selection in §markers§"
                      onClick={() => {
                        const ta = templateRef.current;
                        if (!ta) return;
                        const s = ta.selectionStart, e = ta.selectionEnd;
                        const val = intruder.template;
                        const next = val.slice(0, s) + "§" + val.slice(s, e) + "§" + val.slice(e);
                        dispatch({ type: "intruder-set", payload: { template: next } });
                      }}>+ §</button>
              <button className="btn"
                      title="Strip every § marker from the template"
                      onClick={() => dispatch({ type: "intruder-set", payload: { template: intruder.template.replace(/§/g, "") } })}>CLEAR §</button>
              <button className="btn"
                      title="Auto-mark every query-string, form-body and Cookie value"
                      onClick={() => dispatch({ type: "intruder-set", payload: { template: autoMarkTemplate(intruder.template) } })}>AUTO §</button>
              <button className="btn" style={{ marginLeft: 6 }}
                      title="Structured breakdown of the template (Inspector)"
                      onClick={() => setTemplateView(v => v === "edit" ? "inspector" : "edit")}>
                {templateView === "edit" ? "▤ INSPECTOR" : "✎ EDIT"}
              </button>
            </div>
            {templateView === "inspector" ? (
              <RepeaterInspectorPanel raw={intruder.template} kind="request" />
            ) : (
              <textarea
                ref={templateRef}
                className="txt"
                value={intruder.template}
                onChange={e => dispatch({ type: "intruder-set", payload: { template: e.target.value }})}
                spellCheck={false}
              />
            )}
          </div>
          <div className="divider-v" />
          {isMultiSet ? (
          <div className="pane" style={{ minWidth: 0 }}>
            <div className="pane-head">
              <span style={{ color:"var(--accent)" }}>▸</span>
              <span>PAYLOAD SETS</span>
              <span className="ph-count">
                {posCount} positions · {attackType === 2 ? "pitchfork (zipped)" : "cluster bomb (product)"}
              </span>
            </div>
            <div style={{ display: "flex", height: "100%", minHeight: 0 }}>
              {Array.from({ length: posCount }).map((_, idx) => (
                <div key={idx} style={{ flex: "1 1 0", minWidth: 0, display: "flex", flexDirection: "column", borderRight: idx < posCount - 1 ? "1px solid var(--line)" : "none" }}>
                  <div style={{ padding: "2px 6px", fontSize: 10, color: "var(--dim)", borderBottom: "1px solid var(--line-soft)", display: "flex", justifyContent: "space-between" }}>
                    <span>SET {idx + 1}</span>
                    <span>{((intruder.payloadSets || [])[idx] || []).length}</span>
                  </div>
                  <textarea
                    className="txt"
                    style={{ flex: 1 }}
                    value={((intruder.payloadSets || [])[idx] || []).join("\n")}
                    onChange={e => setPayloadColumn(idx, e.target.value)}
                    spellCheck={false}
                  />
                </div>
              ))}
            </div>
          </div>
          ) : (
          <div className="pane" style={{ minWidth: 0, position: "relative" }}>
            <div className="pane-head">
              <span style={{ color:"var(--accent)" }}>▸</span>
              <span>PAYLOADS</span>
              <span className="ph-count">{intruder.payloads.length}</span>
              <span style={{ flex: 1 }} />
              <button
                onClick={() => { setGenMenuOpen(o => !o); setPresetMenuOpen(false); }}
                style={{
                  background: "transparent", color: "var(--accent)",
                  border: "1px solid var(--accent)", padding: "2px 8px",
                  fontSize: "10px", fontFamily: "var(--ff-mono)",
                  cursor: "pointer", letterSpacing: "0.04em",
                  textTransform: "uppercase", marginRight: 6,
                }}
              >GENERATOR ▾</button>
              <button
                onClick={() => { setPresetMenuOpen(o => !o); setGenMenuOpen(false); }}
                style={{
                  background: "transparent", color: "var(--accent)",
                  border: "1px solid var(--accent)", padding: "2px 8px",
                  fontSize: "10px", fontFamily: "var(--ff-mono)",
                  cursor: "pointer", letterSpacing: "0.04em",
                  textTransform: "uppercase",
                }}
              >+ PRESET ▾</button>
            </div>
            {genMenuOpen && (
              <div
                onClick={(e) => e.stopPropagation()}
                style={{
                  position: "absolute", top: 28, right: 6, zIndex: 30,
                  background: "var(--pane)", border: "1px solid var(--accent)",
                  boxShadow: "0 8px 24px rgba(0,0,0,0.4)",
                  fontFamily: "var(--ff-mono)", fontSize: "11px",
                  width: 320, maxHeight: 440, overflow: "auto",
                }}>
                <div style={{
                  padding: "6px 10px", color: "var(--dim)", fontSize: "10px",
                  textTransform: "uppercase", letterSpacing: "0.06em",
                  borderBottom: "1px solid var(--line)",
                  display: "flex", alignItems: "center",
                }}>
                  <span style={{ flex: 1 }}>Generate payloads</span>
                  <span style={{ cursor: "pointer", color: "var(--dim)" }}
                        onClick={() => setGenMenuOpen(false)}>×</span>
                </div>
                <div style={{ display: "flex", gap: 4, padding: "6px 10px", borderBottom: "1px solid var(--line-soft)" }}>
                  {genTypes.map(t => (
                    <button key={t} onClick={() => { setGenType(t); setGenPreview(null); }}
                      style={{
                        background: genType === t ? "var(--accent)" : "transparent",
                        color: genType === t ? "var(--bg)" : "var(--text-2)",
                        border: "1px solid var(--line)", padding: "2px 8px",
                        fontSize: "10px", fontFamily: "var(--ff-mono)",
                        cursor: "pointer", textTransform: "uppercase",
                      }}>{t}</button>
                  ))}
                </div>
                <div style={{ padding: "8px 10px", display: "flex", flexDirection: "column", gap: 6 }}>
                  {genType === "numbers" && (
                    <>
                      <div className="fld"><span className="pre">FROM</span>
                        <input type="number" value={genNumbers.from} onChange={e => setGenNumbers({ ...genNumbers, from: e.target.value })} /></div>
                      <div className="fld"><span className="pre">TO</span>
                        <input type="number" value={genNumbers.to} onChange={e => setGenNumbers({ ...genNumbers, to: e.target.value })} /></div>
                      <div className="fld"><span className="pre">STEP</span>
                        <input type="number" value={genNumbers.step} onChange={e => setGenNumbers({ ...genNumbers, step: e.target.value })} /></div>
                      <div className="fld"><span className="pre">WIDTH</span>
                        <input type="number" min="0" value={genNumbers.width} onChange={e => setGenNumbers({ ...genNumbers, width: e.target.value })}
                               title="Zero-pad to this many digits (0 = no padding)" /></div>
                      <label style={{ display: "flex", alignItems: "center", gap: 6, color: "var(--text-2)", cursor: "pointer" }}>
                        <input type="checkbox" checked={genNumbers.hex} onChange={e => setGenNumbers({ ...genNumbers, hex: e.target.checked })}
                               style={{ accentColor: "var(--accent)" }} />
                        HEX
                      </label>
                    </>
                  )}
                  {genType === "dates" && (
                    <>
                      <div className="fld"><span className="pre">FROM</span>
                        <input placeholder="2026-01-01" value={genDates.from} onChange={e => setGenDates({ ...genDates, from: e.target.value })} /></div>
                      <div className="fld"><span className="pre">TO</span>
                        <input placeholder="2026-12-31" value={genDates.to} onChange={e => setGenDates({ ...genDates, to: e.target.value })} /></div>
                      <div className="fld"><span className="pre">STEP·DAYS</span>
                        <input type="number" value={genDates.stepDays} onChange={e => setGenDates({ ...genDates, stepDays: e.target.value })} /></div>
                      <div className="fld"><span className="pre">FORMAT</span>
                        <input value={genDates.format} onChange={e => setGenDates({ ...genDates, format: e.target.value })}
                               title="Qt date format string, e.g. yyyy-MM-dd" /></div>
                    </>
                  )}
                  {genType === "brute" && (
                    <>
                      <div className="fld"><span className="pre">CHARSET</span>
                        <input value={genBrute.charset} onChange={e => setGenBrute({ ...genBrute, charset: e.target.value })} /></div>
                      <div className="fld"><span className="pre">MIN·LEN</span>
                        <input type="number" min="1" value={genBrute.minLen} onChange={e => setGenBrute({ ...genBrute, minLen: e.target.value })} /></div>
                      <div className="fld"><span className="pre">MAX·LEN</span>
                        <input type="number" min="1" value={genBrute.maxLen} onChange={e => setGenBrute({ ...genBrute, maxLen: e.target.value })} /></div>
                    </>
                  )}
                </div>
                <div style={{ padding: "4px 10px 8px", borderTop: "1px solid var(--line-soft)", color: "var(--dim)" }}>
                  {genErr ? (
                    <div style={{ color: "var(--accent-2)" }}>{genErr}</div>
                  ) : genPreview ? (
                    <>
                      <div>{genPreview.count} payload{genPreview.count === 1 ? "" : "s"}{genPreview.capped ? " (capped)" : ""}</div>
                      <pre style={{ maxHeight: 100, overflow: "auto", margin: "4px 0", whiteSpace: "pre-wrap", color: "var(--text-2)" }}>
                        {(genPreview.sample || []).slice(0, 20).join("\n")}
                        {genPreview.sample && genPreview.sample.length > 20 ? "\n…" : ""}
                      </pre>
                    </>
                  ) : (
                    <div>…</div>
                  )}
                </div>
                <div style={{ padding: "6px 10px", display: "flex", justifyContent: "flex-end", gap: 6 }}>
                  <button className="btn" onClick={() => setGenMenuOpen(false)}>CANCEL</button>
                  <button className="btn primary" disabled={!genPreview || !genPreview.count}
                          onClick={applyGenerator}>APPLY</button>
                </div>
              </div>
            )}
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
          )}
        </div>

        <div className="pane" style={{ minHeight: 0 }}>
          <div className="pane-head">
            <span className="ph-corner">▸</span>
            <span>RULES</span>
            <span className="ph-count">{rules.length}</span>
            <span style={{ flex: 1 }} />
            <button className="btn" onClick={addRule}>+ ADD RULE</button>
          </div>
          <div style={{ display: "flex", gap: 6, overflowX: "auto", padding: "4px 8px", minHeight: 30, alignItems: "center" }}>
            {rules.length === 0 && (
              <span style={{ color: "var(--dim)", fontSize: 11 }}>no rules — payloads go on the wire as typed</span>
            )}
            {rules.map((r, i) => (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: 4, border: "1px solid var(--line)", padding: "2px 4px", whiteSpace: "nowrap", flex: "0 0 auto" }}>
                <select className="fld" style={{ border: "none", background: "transparent" }}
                        value={r.op} onChange={e => updateRule(i, { op: e.target.value, arg: "" })}>
                  {ruleOps.map(op => <option key={op} value={op}>{op}</option>)}
                </select>
                {(r.op === "prefix" || r.op === "suffix") && (
                  <input style={{ width: 90 }} placeholder="text" value={r.arg || ""}
                         onChange={e => updateRule(i, { arg: e.target.value })} />
                )}
                {r.op === "match-replace" && (
                  <React.Fragment>
                    <input style={{ width: 70 }} placeholder="find" value={(r.arg || "").split("")[0] || ""}
                           onChange={e => updateRule(i, { arg: e.target.value + "" + ((r.arg || "").split("")[1] || "") })} />
                    <input style={{ width: 70 }} placeholder="replace" value={(r.arg || "").split("")[1] || ""}
                           onChange={e => updateRule(i, { arg: ((r.arg || "").split("")[0] || "") + "" + e.target.value })} />
                  </React.Fragment>
                )}
                <button className="btn" disabled={i === 0} onClick={() => moveRule(i, -1)} title="move earlier">↑</button>
                <button className="btn" disabled={i === rules.length - 1} onClick={() => moveRule(i, 1)} title="move later">↓</button>
                <button className="btn" onClick={() => removeRule(i)} title="remove">×</button>
              </div>
            ))}
          </div>
        </div>

        <div className="pane" style={{ minHeight: 0 }}>
          <div className="pane-head">
            <span className="ph-corner">▸</span>
            <span>RESULTS</span>
            <span className="ph-count">{viewRows.length} shown · {completed} / {total} · {pct}%</span>
          </div>
          <div style={{ display: "flex", gap: 8, alignItems: "center", padding: "4px 8px", borderBottom: "1px solid var(--line-soft)", flexWrap: "wrap" }}>
            <div className="seg-btns">
              {[2, 3, 4, 5].map(c => (
                <button key={c} className={statusOn[c] ? "on s" + c : ""}
                        onClick={() => setStatusOn(s => ({ ...s, [c]: !s[c] }))}>{c}XX</button>
              ))}
            </div>
            <label style={{ fontSize: "10.5px", color: "var(--dim)", display: "flex", gap: 4, alignItems: "center" }}>
              <input type="checkbox" checked={hide404}
                     onChange={e => setHide404(e.target.checked)} />
              hide 404s
            </label>
            <input type="number" placeholder="min B" style={{ width: 64 }}
                   value={minLen} onChange={e => setMinLen(e.target.value)} />
            <input type="number" placeholder="max B" style={{ width: 64 }}
                   value={maxLen} onChange={e => setMaxLen(e.target.value)} />
            <input placeholder="filter payload/extract (regex, -invert)" style={{ flex: "1 1 160px", minWidth: 160 }}
                   value={resultFilter} onChange={e => setResultFilter(e.target.value)} />
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
                <tr>
                  {RESULT_COLS.map(([key, label]) => (
                    <th key={key} onClick={() => toggleSort(key)} title="Click to sort" style={{ cursor: "pointer", userSelect: "none" }}>
                      {label}{sortKey === key ? (sortDir > 0 ? " ▲" : " ▼") : ""}
                    </th>
                  ))}
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {viewRows.map(({ p, i, r }) => {
                  const pending = r.status === null;
                  const cls = (r.status >= 400) ? "s4" : (r.status >= 300) ? "s3" : (r.status >= 200) ? "s2" : "";
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

// Pure helper: auto-mark Intruder payload positions in a raw HTTP request --
// wraps every query-string value, Cookie value, and (for urlencoded bodies)
// every form-field value in §markers§. Idempotent: a value already wrapped
// in § is left alone rather than double-wrapped, so running it twice is safe.
function autoMarkTemplate(raw) {
  if (!raw) return raw;
  const nl = raw.includes("\r\n") ? "\r\n" : "\n";
  const sep = nl + nl;
  const cut = raw.indexOf(sep);
  const head = cut >= 0 ? raw.slice(0, cut) : raw;
  const body = cut >= 0 ? raw.slice(cut + sep.length) : null;
  const lines = head.split(nl);
  if (!lines.length) return raw;

  const markValue = (v) => (v.startsWith("§") && v.endsWith("§") && v.length >= 2) ? v : "§" + v + "§";

  // Request line: mark every query-param value.
  const rl = lines[0].match(/^(\S+\s+[^\s?]*)(\?[^\s]*)?(\s+HTTP\/\S+)?$/);
  if (rl && rl[2]) {
    const marked = rl[2].replace(/=([^&\s]*)/g, (m, v) => "=" + markValue(v));
    lines[0] = rl[1] + marked + (rl[3] || "");
  }

  // Headers: mark Cookie values only (leave every other header alone).
  for (let i = 1; i < lines.length; i++) {
    const m = lines[i].match(/^(Cookie:\s*)(.*)$/i);
    if (m) lines[i] = m[1] + m[2].replace(/=([^;]*)/g, (mm, v) => "=" + markValue(v));
  }

  let newBody = body;
  const ct = lines.find(l => /^Content-Type:/i.test(l));
  if (body != null && ct && /x-www-form-urlencoded/i.test(ct)) {
    newBody = body.replace(/=([^&]*)/g, (mm, v) => "=" + markValue(v));
  }

  const newHead = lines.join(nl);
  return body != null ? newHead + sep + newBody : newHead;
}

// Pure predicate: should this Intruder result row show through the current
// filter set? Pending rows (status still null, request in flight) always
// pass so progress stays visible while an attack is running.
function intruderRowVisible(payload, r, opts) {
  const { hide404, statusOn, minLen, maxLen, search } = opts;
  if (r.status == null) return true;
  if (hide404 && r.status === 404) return false;
  const cls = Math.floor(r.status / 100);
  if (statusOn && statusOn[cls] === false) return false;
  if (minLen !== "" && minLen != null && r.size < Number(minLen)) return false;
  if (maxLen !== "" && maxLen != null && r.size > Number(maxLen)) return false;
  if (search) {
    const neg = search.startsWith("-");
    const term = neg ? search.slice(1) : search;
    if (term) {
      let re = null;
      try { re = new RegExp(term, "i"); } catch (e) { /* invalid regex: fail open, no filtering */ }
      if (re) {
        const hit = re.test(payload) || re.test(r.extracted || "");
        if (neg ? hit : !hit) return false;
      }
    }
  }
  return true;
}

// Pure accessor: the value to compare for a given results-table sort key,
// numeric-aware for the numeric columns so "10" sorts after "2".
function intruderSortValue(payload, r, i, key) {
  switch (key) {
    case "#":         return i;
    case "payload":   return payload;
    case "status":    return r.status == null ? -1 : r.status;
    case "size":      return r.size || 0;
    case "ms":        return r.ms || 0;
    case "matched":   return r.matched ? 1 : 0;
    case "extracted": return r.extracted || "";
    case "err":       return r.err || "";
    default:          return i;
  }
}

Object.assign(window, {
  ScopeTab, RepeaterTab, InterceptTab, IntruderTab,
  autoMarkTemplate, intruderRowVisible, intruderSortValue,
});
