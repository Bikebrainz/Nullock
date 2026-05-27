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

function HistoryTable({ rows, selectedId, onSelect, hostFilter, statusClass, methodFilter, search }) {
  const filtered = React.useMemo(() => rows.filter(r => {
    if (hostFilter && !r.host.includes(hostFilter)) return false;
    if (search) {
      const s = search.toLowerCase();
      // Search across every column we display so the box behaves the way
      // people expect: typing "401" matches status, "json" matches mime,
      // "POST" matches method, etc.
      const blob = [
        r.url, r.path, r.host, r.method, r.mime,
        String(r.status || ""), String(r.params || ""),
        r.ip || "",
      ].join(" ").toLowerCase();
      if (!blob.includes(s)) return false;
    }
    if (statusClass !== "all") {
      const sc = Math.floor(r.status / 100) + "xx";
      if (sc !== statusClass) return false;
    }
    if (methodFilter !== "ALL" && r.method !== methodFilter) return false;
    return true;
  }), [rows, hostFilter, statusClass, methodFilter, search]);

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

function FilterBar({ hostFilter, setHostFilter, statusClass, setStatusClass, methodFilter, setMethodFilter, search, setSearch, hidden, onClearFilters, onSelectHost, selectedHost }) {
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
          placeholder="search url or path…"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
      </div>
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
          <textarea className="txt readonly" value={renderView(req, reqTab)} readOnly />
        </div>
        <div style={{ display:"flex", flexDirection:"column", minHeight: 0 }}>
          <div className="detail-tabs">
            {["raw", "headers", "body", "preview", "hex"].map(t => (
              <button key={t} className={respTab === t ? "on" : ""} onClick={() => setRespTab(t)}>
                RES · {t}
              </button>
            ))}
          </div>
          <textarea className="txt readonly" value={renderView(resp, respTab)} readOnly />
        </div>
      </div>
    </div>
  );
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
          onClearFilters={() => dispatch({ type: "set", payload: {
            hostFilter: "", statusClass: "all", methodFilter: "ALL", search: "", selectedHost: null
          }})}
          selectedHost={selectedHost}
          onSelectHost={h => dispatch({ type: "set", payload: { selectedHost: h }})}
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
