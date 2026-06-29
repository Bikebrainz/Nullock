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
  // These four hooks MUST run on EVERY render -- before the `if (!row)` early
  // return below. React requires a stable hook count per render; a row toggling
  // null<->selected (select a row, then CLEAR) would otherwise change the count
  // ("Rendered more hooks than during the previous render") and, with no error
  // boundary, unmount the entire app to a white screen.
  const reqRef  = React.useRef(null);
  const respRef = React.useRef(null);
  const [overlay, setOverlay] = React.useState(null); // { title, body } | null
  const [copyMenuOpen, setCopyMenuOpen] = React.useState(false);

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
        <div style={{ position: "relative", display: "inline-block" }}>
          <button onClick={() => setCopyMenuOpen(o => !o)}
                  title="Copy this request as a command for another tool">
            ↦ COPY AS ▾
          </button>
          {copyMenuOpen && (
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
                     onClick={() => {
                       const out = renderRequestAs(k, row, req);
                       setOverlay({ title: "↦ " + k.toUpperCase(), body: out });
                       setCopyMenuOpen(false);
                     }}
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

// ===================== COPY AS (tool integration) ====================

// Parse a captured raw HTTP request into { method, fullUrl, headers, body }.
// row gives us the scheme/host/port that the bare request line doesn't.
function parseRawRequest(row, raw) {
  const out = { method: row.method || "GET", fullUrl: "", headers: [], body: "" };
  const proto = row.tls ? "https" : "http";
  const defaultPort = row.tls ? 443 : 80;
  const portStr = (row.port && row.port !== defaultPort) ? ":" + row.port : "";
  const path = row.url || "/";
  out.fullUrl = proto + "://" + (row.host || "") + portStr + path;

  if (!raw) return out;
  // Body is whatever follows a blank line.
  let headerBlock = raw;
  const idx = raw.indexOf("\r\n\r\n");
  const idx2 = raw.indexOf("\n\n");
  let split = -1, splitLen = 0;
  if (idx >= 0 && (idx2 < 0 || idx < idx2)) { split = idx; splitLen = 4; }
  else if (idx2 >= 0) { split = idx2; splitLen = 2; }
  if (split >= 0) {
    headerBlock = raw.slice(0, split);
    out.body = raw.slice(split + splitLen);
  }
  const lines = headerBlock.split(/\r?\n/);
  const first = lines.shift() || "";
  const fp = first.split(" ");
  if (fp.length >= 2) out.method = fp[0];
  for (const ln of lines) {
    const c = ln.indexOf(":");
    if (c <= 0) continue;
    const k = ln.slice(0, c).trim();
    const v = ln.slice(c + 1).trim();
    // Drop hop-by-hop / proxy-only headers when copying to another tool.
    const lc = k.toLowerCase();
    if (lc === "host" || lc === "content-length" || lc === "proxy-connection")
      continue;
    out.headers.push([k, v]);
  }
  return out;
}

// Bash/sh single-quote escape: any ' becomes '\''.
function shq(s) { return "'" + String(s).replace(/'/g, "'\\''") + "'"; }
function psq(s) { return "'" + String(s).replace(/'/g, "''") + "'"; } // PowerShell

// Sensitive header policy mirrors backend project_store::isSensitiveHeader.
// Default-on so a tester who hits "COPY AS curl" and pastes into Slack /
// a ticket / a recording doesn't ship their session cookies along with
// the bug repro.
const REDACTED_HEADERS = new Set([
  "authorization", "proxy-authorization", "cookie", "set-cookie",
  "x-api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token",
  "x-session-id", "x-amz-security-token",
  "x-goog-iam-authorization-token",
]);
function maybeRedact(k, v) {
  return REDACTED_HEADERS.has(k.toLowerCase())
    ? "<redacted: " + v.length + " chars>" : v;
}

function renderRequestAs(kind, row, raw) {
  const r = parseRawRequest(row, raw);
  const hasBody = r.body && r.body.length > 0;

  if (kind === "curl") {
    let out = "curl -k -X " + r.method + " " + shq(r.fullUrl);
    for (const [k, v] of r.headers) out += " \\\n  -H " + shq(k + ": " + maybeRedact(k, v));
    if (hasBody) out += " \\\n  --data-raw " + shq(r.body);
    return out;
  }

  if (kind === "wget") {
    let out = "wget --no-check-certificate --method=" + r.method
            + " --output-document=- " + shq(r.fullUrl);
    for (const [k, v] of r.headers) out += " \\\n  --header=" + shq(k + ": " + maybeRedact(k, v));
    if (hasBody) out += " \\\n  --body-data=" + shq(r.body);
    return out;
  }

  if (kind === "httpie") {
    // httpie infers method from presence of body; force it anyway.
    let out = "http --verify=no " + r.method + " " + shq(r.fullUrl);
    for (const [k, v] of r.headers) out += " " + shq(k + ":" + maybeRedact(k, v));
    if (hasBody) out += " <<< " + shq(r.body);
    return out;
  }

  if (kind === "powershell") {
    let out = "$headers = @{}\n";
    for (const [k, v] of r.headers)
      out += "$headers[" + psq(k) + "] = " + psq(maybeRedact(k, v)) + "\n";
    out += "Invoke-WebRequest -Uri " + psq(r.fullUrl)
         + " -Method " + r.method
         + " -Headers $headers"
         + " -SkipCertificateCheck";
    if (hasBody) out += " -Body " + psq(r.body);
    return out;
  }

  if (kind === "fetch") {
    const headersObj = {};
    for (const [k, v] of r.headers) headersObj[k] = maybeRedact(k, v);
    const opts = { method: r.method, headers: headersObj };
    if (hasBody) opts.body = r.body;
    return "fetch(" + JSON.stringify(r.fullUrl) + ", "
         + JSON.stringify(opts, null, 2) + ");";
  }

  if (kind === "sqlmap") {
    // sqlmap defaults to GET with -u; for POST add --data and --method.
    let out = "sqlmap --batch --random-agent -u " + shq(r.fullUrl);
    for (const [k, v] of r.headers) {
      // sqlmap takes one -H per header.
      out += " \\\n  -H " + shq(k + ": " + v);
    }
    if (hasBody) {
      out += " \\\n  --data " + shq(r.body) + " --method=" + r.method;
    } else if (r.method !== "GET") {
      out += " --method=" + r.method;
    }
    out += " --level=2 --risk=2";
    return out;
  }

  if (kind === "postman") {
    // Single Postman v2.1 collection item. Drop in via Import > Raw text.
    const item = {
      info: {
        name: "Nullock export · row " + row.id,
        schema: "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
      },
      item: [{
        name: row.method + " " + (row.url || "/"),
        request: {
          method: r.method,
          header: r.headers.map(([k, v]) => ({ key: k, value: v })),
          body: hasBody ? { mode: "raw", raw: r.body } : undefined,
          url: { raw: r.fullUrl },
        },
      }],
    };
    return JSON.stringify(item, null, 2);
  }

  if (kind === "nuclei") {
    // Minimal Nuclei template skeleton; user fills in matcher details.
    let yaml = "id: nullock-row-" + row.id + "\n\n"
             + "info:\n"
             + "  name: TODO -- describe the check\n"
             + "  author: nullock\n"
             + "  severity: medium\n"
             + "  description: |\n"
             + "    Captured from Nullock row #" + row.id + " (" + (row.host || "") + ")\n\n"
             + "requests:\n"
             + "  - raw:\n";
    // Indent raw request under YAML literal block.
    yaml += "    - |\n";
    const reqText = raw || (r.method + " " + (row.url || "/") + " HTTP/1.1\r\nHost: " + (row.host || "") + "\r\n\r\n" + (r.body || ""));
    for (const line of reqText.split(/\r?\n/)) yaml += "      " + line + "\n";
    yaml += "\n    matchers:\n";
    yaml += "      - type: status\n        status:\n          - 200\n";
    return yaml;
  }

  if (kind === "burp-raw") {
    // Just the on-the-wire bytes (with the Host header preserved). Paste
    // into Burp's Repeater "Raw" tab; many other proxies accept it too.
    let txt = (raw || "").trimEnd();
    // Burp expects an empty line before body; if user is on a request
    // that has no body, make sure we still end with one.
    if (!txt.endsWith("\r\n\r\n") && !txt.endsWith("\n\n")) txt += "\r\n\r\n";
    return txt;
  }

  return "(unknown format)";
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
    "graphql-parse", "grpc-frame", "cbor-decode", "saml-decode",
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
        // JWT can be a JWS (3 parts) or JWE (5 parts).
        const trimmed = input.trim();
        const parts = trimmed.split(".");
        if (parts.length !== 3 && parts.length !== 5) {
          throw new Error("not a JWT (need 3 segments for JWS or 5 for JWE)");
        }
        const decodeB64 = (p) => {
          let s = p.replace(/-/g, "+").replace(/_/g, "/");
          while (s.length % 4) s += "=";
          return decodeURIComponent(escape(atob(s)));
        };
        const parseJson = (p) => {
          const txt = decodeB64(p);
          try { return [JSON.parse(txt), JSON.stringify(JSON.parse(txt), null, 2)]; }
          catch { return [null, txt]; }
        };

        const [headerObj, headerStr] = parseJson(parts[0]);
        const out = ["// header", headerStr];
        const findings = [];

        // Security annotations on the header.
        if (headerObj) {
          if (headerObj.alg === "none" || headerObj.alg === "None" || headerObj.alg === "NONE") {
            findings.push("[!] alg=none -- if upstream accepts this, signature isn't checked");
          }
          if (headerObj.alg && headerObj.alg.toLowerCase().startsWith("hs") && parts.length === 3) {
            findings.push("[i] HMAC algorithm -- brute-forceable if shared secret is weak");
          }
          if (headerObj.alg && /^rs|^es|^ps/i.test(headerObj.alg)) {
            findings.push("[i] asymmetric algorithm -- check for alg-confusion (HS256 + public key)");
          }
          if (headerObj.kid) findings.push("[i] kid=\"" + headerObj.kid + "\" -- check for SQLi / path traversal in key lookup");
          if (headerObj.jku) findings.push("[!] jku=\"" + headerObj.jku + "\" -- can the server be pointed at attacker-hosted JWKS?");
          if (headerObj.x5u) findings.push("[!] x5u=\"" + headerObj.x5u + "\" -- can the server be pointed at attacker-hosted cert?");
        }

        if (parts.length === 5) {
          // JWE: header.encryptedKey.iv.ciphertext.tag
          out.push("\n// JWE (encrypted) -- payload not readable without key");
          out.push("encrypted_key: " + parts[1].slice(0, 32) + (parts[1].length > 32 ? "..." : ""));
          out.push("iv: " + parts[2]);
          out.push("ciphertext: " + parts[3].slice(0, 64) + (parts[3].length > 64 ? "..." : ""));
          out.push("tag: " + parts[4]);
        } else {
          const [payloadObj, payloadStr] = parseJson(parts[1]);
          out.push("\n// payload", payloadStr);
          if (payloadObj) {
            const now = Math.floor(Date.now() / 1000);
            const fmt = (epoch) => new Date(epoch * 1000).toISOString();
            if (payloadObj.exp) {
              const delta = payloadObj.exp - now;
              if (delta < 0) findings.push("[!] expired (exp=" + fmt(payloadObj.exp) + ", " + (-delta) + "s ago)");
              else           findings.push("[i] expires " + fmt(payloadObj.exp) + " (in " + delta + "s)");
            } else {
              findings.push("[!] no exp claim -- token never expires");
            }
            if (payloadObj.iat) findings.push("[i] issued " + fmt(payloadObj.iat));
            if (payloadObj.nbf) findings.push("[i] not-before " + fmt(payloadObj.nbf));
            if (payloadObj.iss) findings.push("[i] iss=\"" + payloadObj.iss + "\"");
            if (payloadObj.aud) findings.push("[i] aud=" + JSON.stringify(payloadObj.aud));
            if (payloadObj.sub) findings.push("[i] sub=\"" + payloadObj.sub + "\"");
            const interesting = ["admin", "role", "roles", "scope", "scopes",
                                 "permissions", "is_admin", "isAdmin", "groups"];
            for (const k of interesting) {
              if (k in payloadObj) findings.push("[i] " + k + "=" + JSON.stringify(payloadObj[k]) + " -- try tampering");
            }
          }
          out.push("\n// signature (raw, b64url)\n" + parts[2]);
        }

        if (findings.length) {
          out.push("\n// notes");
          for (const f of findings) out.push(f);
        }
        return out.join("\n");
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
      case "graphql-parse": {
        // Pretty-print a GraphQL operation. Pulls operation type/name
        // out, indents braces, flags introspection queries.
        const txt = String(input || "").trim();
        // Quick parse: find operation type keyword + operation name.
        const m = txt.match(/^\s*(query|mutation|subscription)\s*([A-Za-z_][A-Za-z0-9_]*)?/i);
        const opType = m ? m[1] : "(anonymous query)";
        const opName = m && m[2] ? m[2] : "";
        const out = ["// operation: " + opType + (opName ? " " + opName : "")];
        if (txt.includes("__schema") || txt.includes("__type")) {
          out.push("// [!] introspection query -- prod servers usually disable this");
        }
        // Cheap indent: insert newline + 2-space indent after { and before }
        let depth = 0;
        let formatted = "";
        for (const c of txt) {
          if (c === "{") {
            formatted += " {\n" + "  ".repeat(++depth);
          } else if (c === "}") {
            depth = Math.max(0, depth - 1);
            formatted += "\n" + "  ".repeat(depth) + "}";
          } else if (c === "\n") {
            formatted += "\n" + "  ".repeat(depth);
          } else {
            formatted += c;
          }
        }
        out.push("", formatted.trim());
        return out.join("\n");
      }
      case "grpc-frame": {
        // gRPC = 5-byte length-prefix + protobuf payload. Walk the buffer
        // showing each frame's (compressed-flag, length, payload-hex-preview).
        // Input is interpreted as base64 if it looks like b64, else raw bytes.
        let bytes;
        const probe = String(input || "");
        if (/^[A-Za-z0-9+/=\s]+$/.test(probe.replace(/\s/g, ""))) {
          try {
            const bin = atob(probe.replace(/\s/g, ""));
            bytes = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
          } catch (_e) {
            bytes = new Uint8Array(probe.length);
            for (let i = 0; i < probe.length; i++) bytes[i] = probe.charCodeAt(i) & 0xff;
          }
        } else {
          bytes = new Uint8Array(probe.length);
          for (let i = 0; i < probe.length; i++) bytes[i] = probe.charCodeAt(i) & 0xff;
        }
        const out = [];
        let off = 0, frame = 0;
        while (off + 5 <= bytes.length) {
          const compressed = bytes[off];
          const len = (bytes[off+1] << 24) | (bytes[off+2] << 16)
                    | (bytes[off+3] << 8)  |  bytes[off+4];
          const payload = bytes.slice(off + 5, off + 5 + len);
          const hex = Array.from(payload.slice(0, 64))
                          .map(b => b.toString(16).padStart(2, "0")).join(" ");
          out.push("// frame " + frame + ": compressed=" + compressed + ", len=" + len);
          out.push(hex + (payload.length > 64 ? " ..." : ""));
          out.push("");
          off += 5 + len;
          frame++;
          if (frame > 100) { out.push("// truncated after 100 frames"); break; }
        }
        if (off < bytes.length) {
          out.push("// trailing " + (bytes.length - off) + " bytes (partial frame)");
        }
        return out.join("\n");
      }
      case "cbor-decode": {
        // RFC 8949 CBOR decoder, partial. Handles major types 0/1/2/3/4/5
        // for inspecting WebAuthn / COSE payloads. No tag handling.
        const decode = (bytes, off) => {
          if (off >= bytes.length) return [null, off];
          const ib = bytes[off++];
          const mt = ib >> 5, ai = ib & 0x1f;
          const read = (len) => {
            let n = 0; for (let i = 0; i < len; i++) n = n * 256 + bytes[off++];
            return n;
          };
          let n = ai;
          if (ai >= 24 && ai <= 27) n = read([1,2,4,8][ai-24]);
          if (mt === 0) return [n, off];                       // uint
          if (mt === 1) return [-1 - n, off];                  // negint
          if (mt === 2) {                                       // bytes
            const b = bytes.slice(off, off + n); off += n;
            return ["bytes(" + n + "):" +
                    Array.from(b.slice(0,32)).map(x=>x.toString(16).padStart(2,"0")).join(""), off];
          }
          if (mt === 3) {                                       // text
            const t = new TextDecoder().decode(bytes.slice(off, off+n));
            off += n; return [t, off];
          }
          if (mt === 4) {                                       // array
            const arr = []; for (let i = 0; i < n; i++) { const [v, no] = decode(bytes, off); arr.push(v); off = no; }
            return [arr, off];
          }
          if (mt === 5) {                                       // map
            const obj = {}; for (let i = 0; i < n; i++) {
              const [k, ko] = decode(bytes, off); off = ko;
              const [v, vo] = decode(bytes, off); off = vo;
              obj[String(k)] = v;
            }
            return [obj, off];
          }
          return ["(unsupported major=" + mt + ")", off];
        };
        const txt = String(input || "");
        let bytes;
        if (/^[0-9a-fA-F\s]+$/.test(txt.trim())) {
          const h = txt.replace(/\s/g, "");
          bytes = new Uint8Array(h.length / 2);
          for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(h.substr(i*2, 2), 16);
        } else {
          let bin;
          try { bin = atob(txt.replace(/\s/g, "")); }
          catch (_e) { bin = txt; }
          bytes = new Uint8Array(bin.length);
          for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i) & 0xff;
        }
        const [val, off] = decode(bytes, 0);
        return JSON.stringify(val, null, 2) +
               (off < bytes.length ? "\n\n// trailing " + (bytes.length - off) + " bytes" : "");
      }
      case "saml-decode": {
        // SAML responses are URL-encoded base64-encoded deflate-compressed
        // XML (sometimes just b64-encoded XML, for POST binding). Try the
        // simpler path first; fall through to a raw b64-decode.
        let raw = decodeURIComponent(String(input || "").trim());
        // base64 -> bytes
        let b64 = raw.replace(/-/g, "+").replace(/_/g, "/");
        while (b64.length % 4) b64 += "=";
        let bin;
        try { bin = atob(b64); } catch (_e) { return "// not base64: " + raw.slice(0, 200); }
        // Heuristic: if it starts with "<", it's already XML.
        if (bin.charCodeAt(0) === 0x3c) {
          // pretty-print: insert newlines between tags
          return bin.replace(/></g, ">\n<");
        }
        // Otherwise it's likely deflate-compressed (Redirect binding).
        // We don't ship a deflate impl in pure JS here -- show the
        // b64-decoded bytes as hex so the user can run it through a
        // separate inflate step.
        return "// looks like deflate-compressed SAML; b64-decoded hex:\n" +
               Array.from(bin).map(c => c.charCodeAt(0).toString(16).padStart(2,"0"))
                               .join(" ").slice(0, 2048);
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
