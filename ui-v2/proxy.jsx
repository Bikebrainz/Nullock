// Proxy tab: sitemap left, history top-right, detail panes bottom-right.

function fmtSize(n) {
  if (n === 0) return "—";
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / 1024 / 1024).toFixed(2) + " MB";
}
function fmtMs(n) { if (!n) return "—"; return n + " ms"; }
function statusKind(s) {
  if (!s) return "s0";
  return "s" + Math.floor(s / 100);
}

function MethodCell({ m }) {
  let cls = "meth " + m.replace("↑", "").replace("↓", "");
  if (m === "WS↑") cls = "meth WS";
  if (m === "WS↓") cls = "meth WSdown";
  return <span className={cls}>{m}</span>;
}

function HistoryTable({ rows, selectedId, onSelect, hostFilter, statusClass, methodFilter, search, deepHits }) {
  const filtered = React.useMemo(() => rows.filter(r => {
    if (hostFilter && !r.host.includes(hostFilter)) return false;
    if (search) {
      const s = search.toLowerCase();
      // Search across every column we display so the box behaves the way
      // people expect: typing "401" matches status, "json" matches mime,
      // "POST" matches method, etc. When deep search is on, also keep
      // rows whose request/response *bodies* matched on the server.
      const blob = [
        r.url, r.path, r.host, r.method, r.mime,
        String(r.status || ""), String(r.params || ""),
        r.ip || "",
      ].join(" ").toLowerCase();
      const localHit = blob.includes(s);
      const deepHit  = deepHits ? deepHits.has(r.id) : false;
      if (!localHit && !deepHit) return false;
    }
    if (statusClass !== "all") {
      const sc = Math.floor(r.status / 100) + "xx";
      if (sc !== statusClass) return false;
    }
    if (methodFilter !== "ALL" && r.method !== methodFilter) return false;
    return true;
  }), [rows, hostFilter, statusClass, methodFilter, search, deepHits]);

  return (
    <div style={{ height: "100%", overflow: "auto" }}>
      <table className="tbl">
        <colgroup>
          <col style={{ width: 44 }} />
          <col style={{ width: 64 }} />
          <col style={{ width: 78 }} />
          <col style={{ width: 200 }} />
          <col />
          <col style={{ width: 70 }} />
          <col style={{ width: 110 }} />
          <col style={{ width: 70 }} />
          <col style={{ width: 70 }} />
          <col style={{ width: 78 }} />
          <col style={{ width: 88 }} />
        </colgroup>
        <thead>
          <tr>
            <th>#</th>
            <th>Method</th>
            <th>Status</th>
            <th>Host</th>
            <th>Path</th>
            <th>Params</th>
            <th>Mime</th>
            <th>Size</th>
            <th>Time</th>
            <th>IP</th>
            <th>Captured</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map(r => (
            <tr key={r.id} className={selectedId === r.id ? "sel" : ""} onClick={() => onSelect(r)}>
              <td className="num">{r.id.toString().padStart(3, "0")}</td>
              <td><MethodCell m={r.method} /></td>
              <td><span className={"status " + statusKind(r.status)}>{r.status || "—"}</span></td>
              <td><span className={"tls-dot " + (r.tls ? "" : "off")} />{r.host}</td>
              <td>{r.path}</td>
              <td className="num">{r.params || ""}</td>
              <td className="num">{r.mime}</td>
              <td className="num">{fmtSize(r.size)}</td>
              <td className="num">{fmtMs(r.elapsed)}</td>
              <td className="num">{r.ip}</td>
              <td className="num">{r.ts}</td>
            </tr>
          ))}
          {filtered.length === 0 && (
            <tr><td colSpan={11} style={{ textAlign: "center", color: "var(--dim)", height: 80 }}>
              ╌╌  no rows match filters  ╌╌
            </td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function FilterBar({ hostFilter, setHostFilter, statusClass, setStatusClass, methodFilter, setMethodFilter, search, setSearch, hidden, onClearFilters, onSelectHost, selectedHost, deepSearch, setDeepSearch, deepCount }) {
  const methods = ["ALL", "GET", "POST", "PUT", "DELETE", "PATCH", "WS↑", "WS↓"];
  return (
    <div className="filterbar">
      <div className="fld" style={{ flex: "0 0 300px" }}>
        <span className="pre">HOST</span>
        <input
          placeholder="substring filter…"
          value={hostFilter}
          onChange={e => setHostFilter(e.target.value)}
        />
        {hostFilter && <span style={{ cursor:"pointer", color:"var(--dim)" }} onClick={() => setHostFilter("")}>×</span>}
      </div>
      <div className="seg-btns">
        {["all", "2xx", "3xx", "4xx", "5xx"].map(s => (
          <button
            key={s}
            className={statusClass === s ? `on ${s === "all" ? "" : "s" + s[0]}` : ""}
            onClick={() => setStatusClass(s)}
          >{s.toUpperCase()}</button>
        ))}
      </div>
      <select
        className="fld"
        style={{ flex: "0 0 110px", paddingRight: 8 }}
        value={methodFilter}
        onChange={e => setMethodFilter(e.target.value)}
      >
        {methods.map(m => <option key={m} value={m}>{m}</option>)}
      </select>
      <div className="fld" style={{ flex: 1 }}>
        <span className="pre">/</span>
        <input
          placeholder={deepSearch ? "regex search (body too)…" : "search url or path…"}
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        {search && <span style={{ cursor:"pointer", color:"var(--dim)" }} onClick={() => setSearch("")}>×</span>}
      </div>
      <button
        onClick={() => setDeepSearch && setDeepSearch(!deepSearch)}
        title="Also search through request and response bodies (regex)"
        style={{
          background: deepSearch ? "var(--accent)" : "transparent",
          color: deepSearch ? "var(--bg)" : "var(--accent)",
          border: "1px solid var(--accent)", padding: "3px 10px",
          fontSize: "10px", fontFamily: "var(--ff-mono)", cursor: "pointer",
          textTransform: "uppercase", letterSpacing: "0.06em",
          height: 22,
        }}>
        DEEP{deepSearch && deepCount !== null ? " · " + deepCount : ""}
      </button>
      {selectedHost && (
        <div className="chip accent" style={{ height: 22 }}>
          ◉ {selectedHost}
          <span style={{ cursor:"pointer", marginLeft: 8 }} onClick={() => onSelectHost(null)}>×</span>
        </div>
      )}
      <span style={{ color: "var(--dim)", fontSize: "var(--fz-xs)", letterSpacing: "0.1em", textTransform:"uppercase" }}>
        {hidden} hidden
      </span>
      <button className="btn ghost sm" onClick={onClearFilters}>RESET</button>
    </div>
  );
}

function SiteMap({ entries, selectedHost, onSelect, totalRows }) {
  return (
    <div className="pane" style={{ height: "100%" }}>
      <div className="pane-head">
        <span className="ph-corner">▸</span>
        <span>SITE MAP</span>
        <span className="ph-count">{entries.length} HOSTS · {totalRows} REQ</span>
      </div>
      <div className="pane-body">
        <div
          className={"sm-row " + (selectedHost === null ? "sel" : "")}
          onClick={() => onSelect(null)}
        >
          <span style={{ color: "var(--accent)" }}>◆</span>
          <span className="sm-host">all hosts</span>
          <span className="sm-count">{totalRows}</span>
        </div>
        {entries.map(e => (
          <div
            key={e.host}
            className={"sm-row " + (selectedHost === e.host ? "sel" : "")}
            onClick={() => onSelect(e.host)}
          >
            <span className={"sm-tls" + (e.tls ? "" : " off")}>◉</span>
            <span className="sm-host" title={e.host}>{e.host}</span>
            <span className="sm-count">{e.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function DetailPane({ row, onSendRepeater, onSendIntruder }) {
  const [view, setView] = React.useState("split"); // split | req | resp
  const [reqTab, setReqTab] = React.useState("raw"); // raw|headers|body
  const [respTab, setRespTab] = React.useState("raw");
  // The "marked for diff" row id is stashed on window so it survives row
  // selection. Only one mark at a time -- the second row triggers the diff.
  const [diffMark, setDiffMark] = React.useState(window.__nl_diff_mark || null);
  React.useEffect(() => { window.__nl_diff_mark = diffMark; }, [diffMark]);
  const [diffOpen, setDiffOpen] = React.useState(null); // {idA, idB}

  if (!row) {
    return (
      <div className="pane" style={{ height: "100%" }}>
        <div className="pane-head">
          <span className="ph-corner">▸</span>
          <span>DETAIL</span>
        </div>
        <div className="pane-body" style={{ display:"grid", placeItems:"center", color:"var(--dim)", letterSpacing:"0.18em", textTransform:"uppercase", fontSize:"var(--fz-sm)" }}>
          select a row to inspect ──
        </div>
      </div>
    );
  }

  const req = NL.requestRawAt(row.id - 1);
  const resp = NL.responseRawAt(row.id - 1);

  const reqRef  = React.useRef(null);
  const respRef = React.useRef(null);
  const [overlay, setOverlay] = React.useState(null); // { title, body } | null

  // Pull either the user's text selection or the entire textarea contents.
  // Clicking a codec button with no selection runs it against the whole
  // pane -- handy for "decode this whole base64 body".
  const grabFrom = (ref) => {
    const el = ref.current;
    if (!el) return "";
    const sel = el.value.substring(el.selectionStart, el.selectionEnd);
    return sel || el.value;
  };

  return (
    <div className="pane" style={{ height: "100%" }}>
      <div className="pane-head">
        <span className="ph-corner">▸</span>
        <span>#{row.id.toString().padStart(3,"0")}</span>
        <span style={{ color: "var(--text)" }}>{row.method}</span>
        <span style={{ color: "var(--text-2)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", maxWidth: 540 }}>
          {row.url}
        </span>
        <span className={"chip " + (row.status >= 400 ? "err" : row.status >= 300 ? "" : "ok")}>
          {row.status} {NL.statusText(row.status)}
        </span>
        <span className="ph-count">{fmtSize(row.size)} · {fmtMs(row.elapsed)}</span>
        <button onClick={onSendRepeater} title="Send to Repeater">↦ REPEATER</button>
        <button onClick={onSendIntruder} title="Send to Intruder">↦ INTRUDER</button>
        <button onClick={async () => {
          try {
            const r = await NL.actions.replayRow(row.id);
            if (!r.ok) alert("Replay failed: " + (r.error || "unknown"));
          } catch (e) {
            alert("Replay error: " + e);
          }
        }} title="Replay through proxy (mutations apply, lands as new row)">↻ REPLAY</button>
        <button onClick={async () => {
          try {
            const r = await NL.actions.probeRow(row.id);
            if (r.skipped) alert("Probe skipped: " + r.skipped);
            else if (r.ok) alert("Probe queued against " + r.params + " param(s). Watch the Issues tab for hits.");
          } catch (e) {
            alert("Probe error: " + e);
          }
        }} title="Light reflected-XSS probe against this row's query params">⚡ PROBE</button>
        {diffMark === null && (
          <button onClick={() => setDiffMark(row.id)}
                  title="Mark this row as the left-hand side of a diff">
            ⊟ MARK
          </button>
        )}
        {diffMark !== null && diffMark === row.id && (
          <button onClick={() => setDiffMark(null)}
                  title="Clear diff mark"
                  style={{ borderColor: "var(--accent)", color: "var(--accent)" }}>
            ⊟ MARKED
          </button>
        )}
        {diffMark !== null && diffMark !== row.id && (
          <button onClick={() => setDiffOpen({ idA: diffMark, idB: row.id })}
                  title={"Diff with row #" + String(diffMark).padStart(3, "0")}
                  style={{ borderColor: "var(--accent)", color: "var(--accent)" }}>
            ⊟ DIFF vs #{String(diffMark).padStart(3, "0")}
          </button>
        )}
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", height: "100%", minHeight: 0, borderTop: "1px solid var(--line)" }}>
        <div style={{ display:"flex", flexDirection:"column", borderRight: "1px solid var(--line)", minHeight: 0 }}>
          <div className="detail-tabs">
            {["raw", "headers", "body", "hex"].map(t => (
              <button key={t} className={reqTab === t ? "on" : ""} onClick={() => setReqTab(t)}>
                REQ · {t}
              </button>
            ))}
          </div>
          <CodecBar onRun={(name) => {
            const input = grabFrom(reqRef);
            setOverlay({ title: "REQ · " + name, body: runCodec(name, input) });
          }} />
          <textarea ref={reqRef} className="txt readonly" value={renderView(req, reqTab)} readOnly />
        </div>
        <div style={{ display:"flex", flexDirection:"column", minHeight: 0 }}>
          <div className="detail-tabs">
            {["raw", "headers", "body", "preview", "hex"].map(t => (
              <button key={t} className={respTab === t ? "on" : ""} onClick={() => setRespTab(t)}>
                RES · {t}
              </button>
            ))}
          </div>
          <CodecBar onRun={(name) => {
            const input = grabFrom(respRef);
            setOverlay({ title: "RES · " + name, body: runCodec(name, input) });
          }} />
          <textarea ref={respRef} className="txt readonly" value={renderView(resp, respTab)} readOnly />
        </div>
      </div>
      {overlay && (
        <CodecOverlay title={overlay.title} body={overlay.body}
                      onClose={() => setOverlay(null)} />
      )}
      {diffOpen && (
        <DiffOverlay
          idA={diffOpen.idA}
          idB={diffOpen.idB}
          onClose={() => setDiffOpen(null)}
          onClearMark={() => { setDiffMark(null); setDiffOpen(null); }}
        />
      )}
    </div>
  );
}

// ============================== DIFF =================================

// Naive line-level LCS diff. Returns an array of { tag, a, b } rows where
// tag is "eq" / "del" / "add". Quadratic in line count; fine for the
// few-hundred-line HTTP messages we're comparing.
function diffLines(aText, bText) {
  const A = aText.split("\n");
  const B = bText.split("\n");
  const n = A.length, m = B.length;
  // LCS length table
  const dp = Array.from({ length: n + 1 }, () => new Int32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      if (A[i] === B[j]) dp[i][j] = dp[i + 1][j + 1] + 1;
      else dp[i][j] = Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const out = [];
  let i = 0, j = 0;
  while (i < n && j < m) {
    if (A[i] === B[j]) { out.push({ tag: "eq",  a: A[i], b: B[j] }); i++; j++; }
    else if (dp[i + 1][j] >= dp[i][j + 1]) { out.push({ tag: "del", a: A[i], b: "" }); i++; }
    else                                    { out.push({ tag: "add", a: "",    b: B[j] }); j++; }
  }
  while (i < n) { out.push({ tag: "del", a: A[i++], b: "" }); }
  while (j < m) { out.push({ tag: "add", a: "",    b: B[j++] }); }
  return out;
}

// Stats helper -- count add/del lines.
function diffStats(rows) {
  let adds = 0, dels = 0, same = 0;
  for (const r of rows) {
    if (r.tag === "add") adds++;
    else if (r.tag === "del") dels++;
    else same++;
  }
  return { adds, dels, same };
}

function DiffOverlay({ idA, idB, onClose, onClearMark }) {
  React.useEffect(() => {
    const onKey = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const [side, setSide] = React.useState("response"); // request | response

  const rowA = (window.NL.rows || []).find(r => r.id === idA);
  const rowB = (window.NL.rows || []).find(r => r.id === idB);
  const reqA  = idA != null ? (NL.requestRawAt(idA - 1)  || "") : "";
  const reqB  = idB != null ? (NL.requestRawAt(idB - 1)  || "") : "";
  const respA = idA != null ? (NL.responseRawAt(idA - 1) || "") : "";
  const respB = idB != null ? (NL.responseRawAt(idB - 1) || "") : "";
  const rows  = React.useMemo(
    () => side === "request" ? diffLines(reqA, reqB) : diffLines(respA, respB),
    [side, reqA, reqB, respA, respB]
  );
  const stats = diffStats(rows);

  const tabBtn = (k, label) => (
    <button onClick={() => setSide(k)}
            style={{
              background: side === k ? "var(--bg-deep)" : "transparent",
              color: side === k ? "var(--accent)" : "var(--text-2)",
              border: "1px solid " + (side === k ? "var(--accent)" : "var(--line)"),
              padding: "3px 12px", fontSize: "11px",
              fontFamily: "var(--ff-mono)", cursor: "pointer",
              letterSpacing: "0.04em", textTransform: "uppercase",
            }}>{label}</button>
  );

  const renderCell = (text, tag, kind) => {
    let bg = "transparent", color = "var(--text)";
    if (kind === "a" && tag === "del") { bg = "rgba(255, 80, 80, 0.12)"; color = "var(--err, #f88)"; }
    if (kind === "b" && tag === "add") { bg = "rgba(80, 220, 120, 0.12)"; color = "#8ee5a0"; }
    if (text === "" && (tag === "del" || tag === "add")
        && ((kind === "b" && tag === "del") || (kind === "a" && tag === "add"))) {
      bg = "rgba(255,255,255,0.02)";
      text = "";
    }
    return (
      <div style={{
        whiteSpace: "pre", overflow: "hidden", textOverflow: "ellipsis",
        background: bg, color, padding: "0 8px", minHeight: 16,
        borderBottom: "1px solid var(--line-soft)",
        fontFamily: "var(--ff-mono)", fontSize: "11px",
      }}>{text || " "}</div>
    );
  };

  return (
    <div onClick={onClose}
         style={{
           position: "fixed", inset: 0, background: "rgba(0,0,0,0.6)",
           display: "grid", placeItems: "center", zIndex: 60,
         }}>
      <div onClick={(e) => e.stopPropagation()}
           style={{
             background: "var(--pane)", border: "1px solid var(--accent)",
             width: "min(95vw, 1400px)", height: "85vh",
             display: "flex", flexDirection: "column",
             boxShadow: "0 0 0 1px var(--line), 0 12px 40px rgba(0,0,0,0.5)",
           }}>
        <div style={{
          display: "flex", alignItems: "center", gap: 8, padding: "8px 12px",
          borderBottom: "1px solid var(--line)",
          color: "var(--accent)", fontSize: "11px",
          textTransform: "uppercase", letterSpacing: "0.06em",
        }}>
          <span>DIFF</span>
          <span style={{ color: "var(--text-2)" }}>
            #{String(idA).padStart(3, "0")} {rowA ? "· " + rowA.method + " " + (rowA.url || "") : ""}
            &nbsp;↔&nbsp;
            #{String(idB).padStart(3, "0")} {rowB ? "· " + rowB.method + " " + (rowB.url || "") : ""}
          </span>
          <span style={{ flex: 1 }} />
          {tabBtn("request",  "REQUEST")}
          {tabBtn("response", "RESPONSE")}
          <span style={{ color: "var(--dim)", marginLeft: 8 }}>
            +<span style={{ color: "#8ee5a0" }}>{stats.adds}</span>{" "}
            -<span style={{ color: "var(--err,#f88)" }}>{stats.dels}</span>{" "}
            <span style={{ color: "var(--dim)" }}>={stats.same}</span>
          </span>
          <button onClick={onClearMark} title="Clear mark"
                  style={{
                    background: "transparent", color: "var(--dim)",
                    border: "1px solid var(--line)", padding: "2px 8px",
                    fontSize: "10px", fontFamily: "var(--ff-mono)", cursor: "pointer",
                  }}>CLEAR MARK</button>
          <button onClick={onClose} style={{
            background: "transparent", color: "var(--dim)",
            border: "1px solid var(--line)", padding: "2px 8px",
            fontSize: "10px", fontFamily: "var(--ff-mono)", cursor: "pointer",
          }}>CLOSE</button>
        </div>
        <div style={{
          display: "grid", gridTemplateColumns: "1fr 1fr",
          flex: 1, minHeight: 0, overflow: "auto",
          background: "var(--bg-deep)",
        }}>
          <div style={{ borderRight: "1px solid var(--line)" }}>
            <div style={{
              padding: "4px 8px", color: "var(--dim)", fontSize: "10px",
              borderBottom: "1px solid var(--line)", background: "var(--pane)",
              textTransform: "uppercase", letterSpacing: "0.06em",
            }}>#{String(idA).padStart(3,"0")} · A</div>
            {rows.map((r, i) => <div key={i}>{renderCell(r.a, r.tag, "a")}</div>)}
          </div>
          <div>
            <div style={{
              padding: "4px 8px", color: "var(--dim)", fontSize: "10px",
              borderBottom: "1px solid var(--line)", background: "var(--pane)",
              textTransform: "uppercase", letterSpacing: "0.06em",
            }}>#{String(idB).padStart(3,"0")} · B</div>
            {rows.map((r, i) => <div key={i}>{renderCell(r.b, r.tag, "b")}</div>)}
          </div>
        </div>
      </div>
    </div>
  );
}

// Compact codec toolbar shown above each detail textarea. Operates on
// the current selection (or whole pane if nothing selected) and pops
// the result in an overlay so the raw view stays untouched.
function CodecBar({ onRun }) {
  const btn = {
    background: "transparent", color: "var(--accent)",
    border: "1px solid var(--line)", padding: "2px 6px",
    fontSize: "10.5px", fontFamily: "var(--ff-mono)",
    cursor: "pointer", letterSpacing: "0.04em",
  };
  const tools = [
    "url-decode", "url-encode",
    "b64-decode", "b64-encode",
    "jwt-decode",
    "hex-decode", "hex-encode",
    "html-decode",
  ];
  return (
    <div style={{
      display: "flex", flexWrap: "wrap", gap: 4, padding: "4px 6px",
      borderBottom: "1px solid var(--line-soft)",
      background: "var(--pane)",
    }}>
      <span style={{ color: "var(--dim)", fontSize: "10px", alignSelf: "center", paddingRight: 4 }}>codec ▸</span>
      {tools.map(t => (
        <button key={t} style={btn} onClick={() => onRun(t)} title={"Run " + t + " on selection (or whole pane)"}>
          {t}
        </button>
      ))}
    </div>
  );
}

// Read-only result overlay for codec output. ESC or click outside closes.
function CodecOverlay({ title, body, onClose }) {
  React.useEffect(() => {
    const onKey = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  const copy = () => { try { navigator.clipboard?.writeText(body); } catch {} };
  return (
    <div onClick={onClose}
         style={{
           position: "fixed", inset: 0, background: "rgba(0,0,0,0.55)",
           display: "grid", placeItems: "center", zIndex: 50,
         }}>
      <div onClick={(e) => e.stopPropagation()}
           style={{
             background: "var(--pane)", border: "1px solid var(--accent)",
             width: "min(80vw, 900px)", maxHeight: "80vh",
             display: "flex", flexDirection: "column",
             boxShadow: "0 0 0 1px var(--line), 0 12px 40px rgba(0,0,0,0.5)",
           }}>
        <div style={{
          display: "flex", alignItems: "center", gap: 8, padding: "8px 12px",
          borderBottom: "1px solid var(--line)",
          color: "var(--accent)", fontSize: "11px",
          textTransform: "uppercase", letterSpacing: "0.06em",
        }}>
          <span style={{ flex: 1 }}>{title}</span>
          <button onClick={copy} style={{
            background: "transparent", color: "var(--accent)",
            border: "1px solid var(--accent)", padding: "2px 8px",
            fontSize: "10px", fontFamily: "var(--ff-mono)", cursor: "pointer",
          }}>COPY</button>
          <button onClick={onClose} style={{
            background: "transparent", color: "var(--dim)",
            border: "1px solid var(--line)", padding: "2px 8px",
            fontSize: "10px", fontFamily: "var(--ff-mono)", cursor: "pointer",
          }}>CLOSE</button>
        </div>
        <textarea readOnly value={body}
                  style={{
                    flex: 1, minHeight: 240, padding: 10,
                    background: "var(--bg-deep)", color: "var(--text)",
                    border: "none", outline: "none", resize: "none",
                    fontFamily: "var(--ff-mono)", fontSize: "12px",
                    whiteSpace: "pre", overflow: "auto",
                  }} />
      </div>
    </div>
  );
}

// Codec dispatch. Errors are caught and surfaced as text so the user
// can see "this isn't base64" or "not a JWT" instead of an empty overlay.
function runCodec(name, input) {
  if (!input) return "(nothing to decode)";
  try {
    switch (name) {
      case "url-decode":  return decodeURIComponent(input);
      case "url-encode":  return encodeURIComponent(input);
      case "b64-decode": {
        // Support both standard and URL-safe base64; tolerate missing padding.
        let s = input.replace(/-/g, "+").replace(/_/g, "/");
        while (s.length % 4) s += "=";
        const bin = atob(s);
        // Try UTF-8 first; if it's binary, fall through to a hex dump.
        try { return decodeURIComponent(escape(bin)); } catch { return toHexDump(bin); }
      }
      case "b64-encode":  return btoa(unescape(encodeURIComponent(input)));
      case "jwt-decode": {
        const parts = input.trim().split(".");
        if (parts.length !== 3) throw new Error("not a JWT (need 3 dot-separated segments)");
        const decodePart = (p) => {
          let s = p.replace(/-/g, "+").replace(/_/g, "/");
          while (s.length % 4) s += "=";
          const txt = decodeURIComponent(escape(atob(s)));
          try { return JSON.stringify(JSON.parse(txt), null, 2); }
          catch { return txt; }
        };
        return "// header\n"   + decodePart(parts[0])
             + "\n\n// payload\n" + decodePart(parts[1])
             + "\n\n// signature (raw)\n" + parts[2];
      }
      case "hex-encode":
        return Array.from(new TextEncoder().encode(input))
          .map(b => b.toString(16).padStart(2, "0")).join(" ");
      case "hex-decode": {
        const cleaned = input.replace(/[^0-9a-fA-F]/g, "");
        if (cleaned.length % 2) throw new Error("odd number of hex digits");
        const bytes = new Uint8Array(cleaned.length / 2);
        for (let i = 0; i < bytes.length; i++)
          bytes[i] = parseInt(cleaned.substr(i * 2, 2), 16);
        try { return new TextDecoder("utf-8", { fatal: false }).decode(bytes); }
        catch { return toHexDump(String.fromCharCode(...bytes)); }
      }
      case "html-decode": {
        const ta = document.createElement("textarea");
        ta.innerHTML = input;
        return ta.value;
      }
    }
    return input;
  } catch (e) {
    return "// codec error: " + (e && e.message ? e.message : String(e))
         + "\n\n// input (first 200 chars):\n" + input.slice(0, 200);
  }
}

// Split a raw HTTP message into {firstLine, headers, body} and render
// according to the selected view tab. 'raw' = original, 'headers' =
// status/request line + header block, 'body' = body only, 'preview' =
// pretty-print JSON or just the body, 'hex' = canonical hex dump.
function renderView(raw, view) {
  if (!raw || view === "raw") return raw || "";
  const splitIdx = raw.indexOf("\n\n");
  const headers = splitIdx >= 0 ? raw.slice(0, splitIdx) : raw;
  const body    = splitIdx >= 0 ? raw.slice(splitIdx + 2) : "";

  if (view === "headers") return headers;
  if (view === "body")    return body || "(no body)";
  if (view === "preview") {
    // Try JSON pretty-print first; fall back to body as-is.
    const t = (body || "").trim();
    if (t.startsWith("{") || t.startsWith("[")) {
      try { return JSON.stringify(JSON.parse(t), null, 2); } catch (e) {}
    }
    return body || "(no body)";
  }
  if (view === "hex") return toHexDump(body);
  return raw;
}

function toHexDump(s) {
  if (!s) return "";
  // Treat input as UTF-8 bytes for the dump.
  const bytes = new TextEncoder().encode(s);
  const lines = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const offset = i.toString(16).padStart(8, "0");
    const hex = Array.from(chunk).map(b => b.toString(16).padStart(2, "0")).join(" ").padEnd(48, " ");
    const ascii = Array.from(chunk).map(b => (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : ".").join("");
    lines.push(`${offset}  ${hex}  ${ascii}`);
    if (i > 64 * 1024) { lines.push("... [truncated at 64 KiB]"); break; }
  }
  return lines.join("\n");
}

function ProxyTab({ state, dispatch, showSitemap }) {
  const { rows, selectedRowId, hostFilter, statusClass, methodFilter, search, selectedHost } = state;
  const sitemapEntries = NL.sitemap;

  // Deep search: when enabled, the search box query is also run against
  // request and response bodies via /api/search. We debounce by 250ms so
  // typing doesn't fire a scan on every keystroke. deepHits is a Set of
  // row ids -- if it's non-null and the row id isn't in it, the row hides.
  const [deepSearch, setDeepSearch] = React.useState(false);
  const [deepHits, setDeepHits]     = React.useState(null);  // null = no body filter
  const [deepCount, setDeepCount]   = React.useState(null);  // last hit count
  React.useEffect(() => {
    if (!deepSearch || !search) { setDeepHits(null); setDeepCount(null); return; }
    let cancelled = false;
    const t = setTimeout(async () => {
      try {
        const res = await NL.actions.search(search, "both", 500);
        if (cancelled) return;
        const ids = new Set((res.hits || []).map(h => h.id));
        setDeepHits(ids);
        setDeepCount(res.count || 0);
      } catch (e) {
        if (!cancelled) { setDeepHits(new Set()); setDeepCount(0); }
      }
    }, 250);
    return () => { cancelled = true; clearTimeout(t); };
  }, [deepSearch, search]);

  // visibleHost feeds the table filter as hostFilter, but when sitemap selects a host we want exact match
  const tableHostFilter = selectedHost || hostFilter;
  const selectedRow = rows.find(r => r.id === selectedRowId) || null;

  // count hidden
  const shown = rows.filter(r => {
    if (tableHostFilter && !r.host.includes(tableHostFilter)) return false;
    if (statusClass !== "all" && (Math.floor(r.status / 100) + "xx") !== statusClass) return false;
    if (methodFilter !== "ALL" && r.method !== methodFilter) return false;
    if (search && !r.url.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  }).length;
  const hidden = rows.length - shown;

  const columns = showSitemap
    ? "minmax(220px, 280px) 1px 1fr"
    : "1fr";

  return (
    <div className="tab-body" style={{ gridTemplateColumns: columns }}>
      {showSitemap && (
        <SiteMap
          entries={sitemapEntries}
          selectedHost={selectedHost}
          onSelect={h => dispatch({ type: "set", payload: { selectedHost: h }})}
          totalRows={rows.length}
        />
      )}
      {showSitemap && <div className="divider-v" />}
      <div className="pane" style={{ display: "grid", gridTemplateRows: "auto auto 1fr 1fr", minHeight: 0 }}>
        <div className="pane-head">
          <span className="ph-corner">▸</span>
          <span>HTTP HISTORY</span>
          <span className="ph-count">{shown} / {rows.length}</span>
        </div>
        <FilterBar
          hostFilter={hostFilter}
          setHostFilter={v => dispatch({ type: "set", payload: { hostFilter: v }})}
          statusClass={statusClass}
          setStatusClass={v => dispatch({ type: "set", payload: { statusClass: v }})}
          methodFilter={methodFilter}
          setMethodFilter={v => dispatch({ type: "set", payload: { methodFilter: v }})}
          search={search}
          setSearch={v => dispatch({ type: "set", payload: { search: v }})}
          hidden={hidden}
          onClearFilters={() => { setDeepSearch(false); setDeepHits(null); setDeepCount(null); dispatch({ type: "set", payload: {
            hostFilter: "", statusClass: "all", methodFilter: "ALL", search: "", selectedHost: null
          }}); }}
          selectedHost={selectedHost}
          onSelectHost={h => dispatch({ type: "set", payload: { selectedHost: h }})}
          deepSearch={deepSearch}
          setDeepSearch={setDeepSearch}
          deepCount={deepCount}
        />
        <div style={{ minHeight: 0, borderBottom: "1px solid var(--line)" }}>
          <HistoryTable
            rows={rows}
            selectedId={selectedRowId}
            onSelect={r => dispatch({ type: "set", payload: { selectedRowId: r.id }})}
            hostFilter={tableHostFilter}
            statusClass={statusClass}
            methodFilter={methodFilter}
            search={search}
            deepHits={deepSearch ? deepHits : null}
          />
        </div>
        <DetailPane
          row={selectedRow}
          onSendRepeater={() => dispatch({ type: "send-to-repeater", row: selectedRow })}
          onSendIntruder={() => dispatch({ type: "send-to-intruder", row: selectedRow })}
        />
      </div>
    </div>
  );
}

Object.assign(window, { ProxyTab });
