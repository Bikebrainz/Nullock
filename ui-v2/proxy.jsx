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

// Host glob -> RegExp (same convention as the backend scope matcher: '*' is
// the only wildcard, everything else is literal).
function globToRegex(glob) {
  const esc = glob.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp("^" + esc + "$", "i");
}
function hostInScope(host, scope) {
  if (!scope || !scope.in || scope.in.length === 0) return true; // no allowlist = everything in scope
  return scope.in.some(g => globToRegex(g).test(host));
}

// #267/#371: MIME class bucketing over the raw Content-Type string a row
// carries (r.mime, e.g. "application/json", "text/html; ..." already
// stripped of the charset by the backend). "all" always matches.
const MIME_CATEGORIES = ["all", "html", "script", "xml", "css", "json", "images", "other"];
function mimeCategory(mime) {
  const m = (mime || "").toLowerCase();
  if (!m) return "other";
  if (m.includes("html")) return "html";
  if (m.includes("javascript") || m.includes("ecmascript")) return "script";
  if (m.includes("json")) return "json";
  if (m.includes("xml")) return "xml";
  if (m.includes("css")) return "css";
  if (m.startsWith("image/")) return "images";
  return "other";
}

// #371: comma-separated extension list derived from the row's path, e.g.
// ".js, .png" -- matched against the path's trailing ".ext" (case-insensitive).
function pathExtension(path) {
  const clean = (path || "").split(/[?#]/)[0];
  const m = /\.([a-zA-Z0-9]{1,8})$/.exec(clean);
  return m ? m[1].toLowerCase() : "";
}
function parseExtList(text) {
  return (text || "").split(",").map(s => s.trim().replace(/^\./, "").toLowerCase()).filter(Boolean);
}
function extFilterMatch(path, extList, hideMode) {
  if (extList.length === 0) return true;
  const ext = pathExtension(path);
  const hit = extList.includes(ext);
  return hideMode ? !hit : hit;
}

// #371: a leading "-" negates a search term (Burp's site-map negative-search
// convention). Returns { term, negate }.
function parseSearchTerm(raw) {
  if (raw && raw.startsWith("-") && raw.length > 1) return { term: raw.slice(1), negate: true };
  return { term: raw || "", negate: false };
}

// #299: HTTP history annotations (Burp's per-item highlight colour + comment).
// No backend model field exists for this yet (ProxyModel::Entry carries only
// id/request/response), so this is a client-side-only layer, persisted to
// localStorage keyed by row id so it survives a reload of this browser tab --
// an honest partial vs. Burp's project-file persistence, but the same core
// triage workflow (flag a row, filter back to it) works end to end.
const ANNOTATION_COLORS = [
  { key: "red",    hex: "#b8433a" },
  { key: "orange", hex: "#c07a2e" },
  { key: "yellow", hex: "#b8a92e" },
  { key: "green",  hex: "#4a9d5c" },
  { key: "cyan",   hex: "#3a9ba8" },
  { key: "blue",   hex: "#3d6fb0" },
  { key: "purple", hex: "#8358b0" },
  { key: "pink",   hex: "#b0559a" },
  { key: "gray",   hex: "#6b6b6b" },
];
const ANNOTATIONS_STORAGE_KEY = "nl.history.annotations.v1";
function loadAnnotations() {
  try {
    const raw = window.localStorage.getItem(ANNOTATIONS_STORAGE_KEY);
    const parsed = raw ? JSON.parse(raw) : {};
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch (e) { return {}; }
}
function saveAnnotations(map) {
  try { window.localStorage.setItem(ANNOTATIONS_STORAGE_KEY, JSON.stringify(map)); } catch (e) { /* storage unavailable -- keep working in-memory */ }
}
function annotationColorHex(key) {
  const c = ANNOTATION_COLORS.find(c => c.key === key);
  return c ? c.hex : null;
}

// Target Analyzer: attack-surface sizing over a site-map scope (Burp's
// "counts of static vs dynamic URLs, unique parameter names, and per-URL
// entry points"). Computed entirely client-side from the HTTP history rows
// already in state -- no backend endpoint exists for this, and none is
// needed: r.path already carries the full path+query (control_server.cpp's
// history-row builder maps both "url" and "path" to ProxyModel::UrlRole,
// which is request.path verbatim). The one honest gap: only query-string
// parameter names are visible here, since request bodies aren't held
// client-side -- form/JSON body parameter names aren't counted.
const STATIC_URL_EXTS = new Set([
  "js", "css", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp",
  "woff", "woff2", "ttf", "eot", "otf", "map",
  "mp4", "webm", "mp3", "wav", "pdf", "zip",
]);
function classifyUrlKind(path) {
  const raw = path || "";
  const hasQuery = raw.split("?")[1] ? raw.split("?")[1].length > 0 : false;
  if (hasQuery) return "dynamic";
  const ext = pathExtension(raw);
  return STATIC_URL_EXTS.has(ext) ? "static" : "dynamic";
}
function queryParamNames(path) {
  const raw = path || "";
  const qIdx = raw.indexOf("?");
  if (qIdx === -1) return [];
  const qs = raw.slice(qIdx + 1).split("#")[0];
  if (!qs) return [];
  const names = [];
  for (const pair of qs.split("&")) {
    if (!pair) continue;
    const eq = pair.indexOf("=");
    const rawName = eq === -1 ? pair : pair.slice(0, eq);
    if (!rawName) continue;
    let name;
    try { name = decodeURIComponent(rawName.replace(/\+/g, " ")); } catch (e) { name = rawName; }
    names.push(name);
  }
  return names;
}
function analyzeTargetSurface(rows) {
  const byPath = new Map();
  for (const r of (rows || [])) {
    const rawPath = r.path || "/";
    const clean = rawPath.split(/[?#]/)[0] || "/";
    let ep = byPath.get(clean);
    if (!ep) { ep = { path: clean, methods: new Set(), paramNames: new Set(), dynamic: false }; byPath.set(clean, ep); }
    ep.methods.add(r.method);
    if (classifyUrlKind(rawPath) === "dynamic") ep.dynamic = true;
    for (const name of queryParamNames(rawPath)) ep.paramNames.add(name);
  }
  const paramNameCounts = new Map();
  for (const ep of byPath.values()) {
    for (const name of ep.paramNames) paramNameCounts.set(name, (paramNameCounts.get(name) || 0) + 1);
  }
  const entryPoints = Array.from(byPath.values())
    .map(ep => ({
      path: ep.path,
      methods: Array.from(ep.methods).sort(),
      paramNames: Array.from(ep.paramNames).sort(),
      kind: ep.dynamic ? "dynamic" : "static",
    }))
    .sort((a, b) => a.path.localeCompare(b.path));
  const paramNames = Array.from(paramNameCounts.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
  return {
    totalUrls: entryPoints.length,
    staticCount: entryPoints.filter(e => e.kind === "static").length,
    dynamicCount: entryPoints.filter(e => e.kind === "dynamic").length,
    entryPoints,
    paramNames,
  };
}

function MethodCell({ m }) {
  let cls = "meth " + m.replace("↑", "").replace("↓", "");
  if (m === "WS↑") cls = "meth WS";
  if (m === "WS↓") cls = "meth WSdown";
  return <span className={cls}>{m}</span>;
}

function HistoryTable({ rows, selectedId, onSelect, hostFilter, statusClass, methodFilter, search, deepHits, deepMinId, paramsOnly, hideNotFound, inScopeOnly, scope, mimeFilter, extList, extHide, caseSensitive, onRowContextMenu, annotations, annotatedOnly }) {
  const filtered = React.useMemo(() => rows.filter(r => {
    if (hostFilter && !r.host.includes(hostFilter)) return false;
    if (paramsOnly && !(r.params > 0)) return false;
    if (hideNotFound && r.status === 404) return false;
    if (inScopeOnly && !hostInScope(r.host, scope)) return false;
    if (mimeFilter && mimeFilter !== "all" && mimeCategory(r.mime) !== mimeFilter) return false;
    if (extList && extList.length > 0 && !extFilterMatch(r.path, extList, extHide)) return false;
    if (annotatedOnly && !(annotations && annotations[r.id])) return false;
    if (search) {
      const { term, negate } = parseSearchTerm(search);
      const s = caseSensitive ? term : term.toLowerCase();
      // Search across every column we display so the box behaves the way
      // people expect: typing "401" matches status, "json" matches mime,
      // "POST" matches method, etc. When deep search is on, also keep
      // rows whose request/response *bodies* matched on the server.
      const rawBlob = [
        r.url, r.path, r.host, r.method, r.mime,
        String(r.status || ""), String(r.params || ""),
        r.ip || "",
      ].join(" ");
      const blob = caseSensitive ? rawBlob : rawBlob.toLowerCase();
      const localHit = s ? blob.includes(s) : true;
      const deepHit  = deepHits ? deepHits.has(r.id) : false;
      const matched = negate ? !(s ? blob.includes(s) : false) : (localHit || deepHit);
      if (!matched) {
        // Never hide a row the server did not actually scan. On a truncated
        // body scan, rows with id < deepMinId were not examined, so their
        // absence from the hit set means "unknown", not "no match" -- keep
        // them visible rather than silently hiding matching traffic. This
        // exception does not apply to negative search, which only ever
        // looks at locally-available columns.
        const unscanned = !negate && deepHits && deepMinId != null && r.id < deepMinId;
        if (!unscanned) return false;
      }
    }
    if (statusClass !== "all") {
      const sc = Math.floor(r.status / 100) + "xx";
      if (sc !== statusClass) return false;
    }
    if (methodFilter !== "ALL" && r.method !== methodFilter) return false;
    return true;
  }), [rows, hostFilter, statusClass, methodFilter, search, deepHits, deepMinId, paramsOnly, hideNotFound, inScopeOnly, scope, mimeFilter, extList, extHide, caseSensitive, annotations, annotatedOnly]);

  return (
    <div style={{ height: "100%", overflow: "auto" }}>
      <table className="tbl">
        <colgroup>
          <col style={{ width: 18 }} />
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
            <th></th>
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
          {filtered.map(r => {
            const note = annotations && annotations[r.id];
            const rowStyle = note && note.color
              ? { boxShadow: "inset 3px 0 0 " + annotationColorHex(note.color) }
              : undefined;
            return (
            <tr
              key={r.id}
              className={selectedId === r.id ? "sel" : ""}
              style={rowStyle}
              onClick={() => onSelect(r)}
              onContextMenu={onRowContextMenu ? (e => { e.preventDefault(); onRowContextMenu(r.host, e, r.id); }) : undefined}
            >
              <td>{note && note.comment ? <span title={note.comment} style={{ cursor: "help" }}>💬</span> : null}</td>
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
            );
          })}
          {filtered.length === 0 && (
            <tr><td colSpan={12} style={{ textAlign: "center", color: "var(--dim)", height: 80 }}>
              ╌╌  no rows match filters  ╌╌
            </td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function FilterBar({ hostFilter, setHostFilter, statusClass, setStatusClass, methodFilter, setMethodFilter, search, setSearch, hidden, onClearFilters, onSelectHost, selectedHost, deepSearch, setDeepSearch, deepCount, deepTruncated, paramsOnly, setParamsOnly, hideNotFound, setHideNotFound, inScopeOnly, setInScopeOnly, mimeFilter, setMimeFilter, extText, setExtText, extHide, setExtHide, caseSensitive, setCaseSensitive, annotatedOnly, setAnnotatedOnly }) {
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
      {setMimeFilter && (
        <select
          className="fld"
          style={{ flex: "0 0 90px", paddingRight: 8 }}
          value={mimeFilter}
          title="Filter by MIME class"
          onChange={e => setMimeFilter(e.target.value)}
        >
          {MIME_CATEGORIES.map(c => <option key={c} value={c}>{c === "all" ? "ALL MIME" : c.toUpperCase()}</option>)}
        </select>
      )}
      <div className="fld" style={{ flex: 1 }}>
        <span className="pre">/</span>
        <input
          placeholder={deepSearch ? "regex search (body too)… (-neg to negate)" : "search url or path… (-neg to negate)"}
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        {search && <span style={{ cursor:"pointer", color:"var(--dim)" }} onClick={() => setSearch("")}>×</span>}
      </div>
      {setExtText && (
        <div className="fld" style={{ flex: "0 0 140px" }}>
          <span className="pre">EXT</span>
          <input
            placeholder="js,png,…"
            value={extText}
            onChange={e => setExtText(e.target.value)}
          />
        </div>
      )}
      {setExtHide && (
        <button
          onClick={() => setExtHide(!extHide)}
          title={extHide ? "Hiding rows whose extension matches EXT" : "Showing only rows whose extension matches EXT"}
          style={{
            background: extHide ? "var(--accent)" : "transparent",
            color: extHide ? "var(--bg)" : "var(--accent)",
            border: "1px solid var(--accent)", padding: "3px 10px",
            fontSize: "10px", fontFamily: "var(--ff-mono)", cursor: "pointer",
            textTransform: "uppercase", letterSpacing: "0.06em",
            height: 22,
          }}>
          {extHide ? "EXT: HIDE" : "EXT: SHOW"}
        </button>
      )}
      {setCaseSensitive && (
        <button
          onClick={() => setCaseSensitive(!caseSensitive)}
          title="Case-sensitive search"
          style={{
            background: caseSensitive ? "var(--accent)" : "transparent",
            color: caseSensitive ? "var(--bg)" : "var(--accent)",
            border: "1px solid var(--accent)", padding: "3px 10px",
            fontSize: "10px", fontFamily: "var(--ff-mono)", cursor: "pointer",
            textTransform: "uppercase", letterSpacing: "0.06em",
            height: 22,
          }}>
          Aa
        </button>
      )}
      <button
        onClick={() => setDeepSearch && setDeepSearch(!deepSearch)}
        title={deepTruncated
          ? "Body search hit its time budget before scanning the whole history — showing the most recent matches. Narrow the query for full coverage."
          : "Also search through request and response bodies (regex)"}
        style={{
          background: deepSearch ? "var(--accent)" : "transparent",
          color: deepSearch ? "var(--bg)" : "var(--accent)",
          border: "1px solid var(--accent)", padding: "3px 10px",
          fontSize: "10px", fontFamily: "var(--ff-mono)", cursor: "pointer",
          textTransform: "uppercase", letterSpacing: "0.06em",
          height: 22,
        }}>
        DEEP{deepSearch && deepCount !== null ? " · " + deepCount + (deepTruncated ? "+" : "") : ""}
      </button>
      {[
        ["IN-SCOPE", inScopeOnly, setInScopeOnly, "Show only rows whose host matches an in-scope glob"],
        ["PARAMS", paramsOnly, setParamsOnly, "Show only rows with query/body parameters"],
        ["HIDE 404", hideNotFound, setHideNotFound, "Hide rows with a 404 Not Found status"],
        ["ANNOTATED", annotatedOnly, setAnnotatedOnly, "Show only rows with a highlight colour or comment"],
      ].map(([label, on, setOn, title]) => (
        <button
          key={label}
          onClick={() => setOn(!on)}
          title={title}
          style={{
            background: on ? "var(--accent)" : "transparent",
            color: on ? "var(--bg)" : "var(--accent)",
            border: "1px solid var(--accent)", padding: "3px 10px",
            fontSize: "10px", fontFamily: "var(--ff-mono)", cursor: "pointer",
            textTransform: "uppercase", letterSpacing: "0.06em",
            height: 22,
          }}>{label}</button>
      ))}
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

// Site map hierarchical tree (protocol://host:port -> directory -> file):
// groups a host's leaves (already deduped per method+path by leavesFor) into
// nested directory nodes by splitting each leaf's pathname (query string
// stripped) on "/". Pure and unit-testable independent of React -- the
// grouping/leaf-count logic is proven without a DOM.
function buildSiteMapTree(leaves) {
  const root = { name: "", fullPath: "", children: new Map(), leaves: [] };
  for (const leaf of leaves) {
    const pathname = (leaf.path || "/").split("?")[0] || "/";
    const segs = pathname.split("/").filter(Boolean);
    let node = root;
    let acc = "";
    for (let i = 0; i < segs.length - 1; i++) {
      acc += "/" + segs[i];
      let child = node.children.get(segs[i]);
      if (!child) {
        child = { name: segs[i], fullPath: acc, children: new Map(), leaves: [] };
        node.children.set(segs[i], child);
      }
      node = child;
    }
    node.leaves.push(leaf);
  }
  return root;
}

function siteMapTreeLeafCount(node) {
  let n = node.leaves.length;
  for (const child of node.children.values()) n += siteMapTreeLeafCount(child);
  return n;
}

function SiteMap({ entries, rows, selectedOrigin, selectedRowId, onSelect, onSelectLeaf, totalRows, onRowContextMenu, annotations, annotatedOnly }) {
  // #370: Burp's tree lets you click a leaf node straight to its editor, but
  // the backend's /api/snapshot sitemap block is host-only (no per-path
  // field, control_server.cpp:1446-1459). Rather than a backend change, this
  // derives per-host path leaves client-side from the HTTP history rows
  // already in state -- when two rows share a host+method+path, the most
  // recent (highest id) one is the leaf's target, mirroring how Burp's tree
  // node opens the latest request/response pair for that URL.
  //
  // Tree roots (`entries`, computed by the caller from `rows`) are likewise
  // keyed by full origin (scheme://host[:port]), not bare host -- the
  // backend's SiteMapModel entry is {host,count,anyTls} with no port field
  // (site_map_model.hpp:40-44), which merges e.g. an app on :443 and an
  // admin panel on :8443 into one node with an OR'd TLS flag. `rows` already
  // carries host/port/tls per request, so this closes the same gap the same
  // way -- client-side derivation, no backend change.
  const [expanded, setExpanded] = React.useState(() => new Set());
  const toggleExpand = (origin, e) => {
    e.stopPropagation();
    setExpanded(prev => {
      const next = new Set(prev);
      if (next.has(origin)) next.delete(origin); else next.add(origin);
      return next;
    });
  };

  // Directory-node expand state, keyed by "<origin>|<folder fullPath>" so
  // the same folder name under two different hosts doesn't collide.
  const [expandedFolders, setExpandedFolders] = React.useState(() => new Set());
  const toggleFolder = (key, e) => {
    e.stopPropagation();
    setExpandedFolders(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  };

  // Recursively renders a tree node's child directories (each an expandable
  // folder row scoping the HTTP History table -- and, with Deep Search on,
  // the search results -- to that branch when clicked) followed by its own
  // leaves. depth 1 = directly under the host row, matching the indent the
  // flat leaf list already used before folders existed.
  const renderTreeNode = (node, entry, depth) => {
    const folders = Array.from(node.children.values()).sort((a, b) => a.name.localeCompare(b.name));
    const leaves = node.leaves.slice().sort((a, b) => a.path.localeCompare(b.path));
    const pad = 12 + depth * 14;
    return (
      <React.Fragment>
        {folders.map(folder => {
          const key = entry.origin + "|" + folder.fullPath;
          const isOpen = expandedFolders.has(key);
          const isSel = selectedOrigin != null && selectedOrigin.host === entry.host
            && selectedOrigin.port === entry.port && selectedOrigin.tls === entry.tls
            && selectedOrigin.branch === folder.fullPath;
          return (
            <React.Fragment key={key}>
              <div
                className={"sm-folder " + (isSel ? "sel" : "")}
                style={{ paddingLeft: pad }}
                title={folder.fullPath}
                onClick={() => onSelect(entry, folder.fullPath)}
                onContextMenu={onRowContextMenu ? (ev => { ev.preventDefault(); onRowContextMenu(entry.host, ev, undefined, folder.fullPath); }) : undefined}
              >
                <span className="sm-twisty" onClick={ev => toggleFolder(key, ev)} title={isOpen ? "collapse" : "expand"}>{isOpen ? "▾" : "▸"}</span>
                <span className="sm-folder-name">📁 {folder.name}</span>
                <span className="sm-count">{siteMapTreeLeafCount(folder)}</span>
              </div>
              {isOpen && renderTreeNode(folder, entry, depth + 1)}
            </React.Fragment>
          );
        })}
        {leaves.map(r => {
          const note = annotations && annotations[r.id];
          const leafStyle = { paddingLeft: pad };
          if (note && note.color) leafStyle.boxShadow = "inset 3px 0 0 " + annotationColorHex(note.color);
          const unrequested = r.status === 0;
          const titleBase = unrequested ? (r.method + " " + r.path + " — not yet sent") : (r.method + " " + r.path);
          return (
            <div
              key={r.id}
              className={"sm-leaf " + (selectedRowId === r.id ? "sel" : "") + (unrequested ? " unrequested" : "")}
              title={note && note.comment ? (titleBase + " — " + note.comment) : titleBase}
              style={leafStyle}
              onClick={() => onSelectLeaf(entry, r.id)}
              onContextMenu={onRowContextMenu ? (ev => { ev.preventDefault(); onRowContextMenu(entry.host, ev, r.id); }) : undefined}
            >
              <span className="sm-leaf-note">{note && note.comment ? "💬" : ""}</span>
              <span className="sm-leaf-method">{r.method}</span>
              <span className="sm-leaf-path">{r.path || "/"}</span>
              <span className="sm-leaf-status">{unrequested ? "not sent" : r.status}</span>
            </div>
          );
        })}
      </React.Fragment>
    );
  };

  // #394: manual "add to site map" for an unrequested item -- Burp lets you
  // hand-add a URL that's never actually been sent; Nullock's only route was
  // "import a whole OpenAPI spec". Reuses that same synthetic-entry endpoint
  // with a one-path, one-op spec so a single URL lands as its own status-0
  // "not yet sent" row without needing a dedicated backend endpoint.
  const [addUrlText, setAddUrlText] = React.useState("");
  const [addUrlBusy, setAddUrlBusy] = React.useState(false);
  const [addUrlErr, setAddUrlErr]   = React.useState("");
  const addUrlToMap = async () => {
    const raw = addUrlText.trim();
    if (!raw) return;
    let u;
    try { u = new URL(raw); } catch (e) { setAddUrlErr("invalid URL"); return; }
    if (u.protocol !== "http:" && u.protocol !== "https:") { setAddUrlErr("http/https only"); return; }
    setAddUrlBusy(true); setAddUrlErr("");
    try {
      const origin = u.protocol + "//" + u.host;
      const path = (u.pathname || "/") + u.search;
      const r = await NL.actions.addUrlToSiteMap(origin, path, "GET");
      if (r && r.ok === false) setAddUrlErr(r.error || "import failed");
      else setAddUrlText("");
    } catch (e) { setAddUrlErr(String(e && e.message ? e.message : e)); }
    finally { setAddUrlBusy(false); }
  };
  const leavesFor = (entry) => {
    const byKey = new Map();
    for (const r of rows) {
      if (r.host !== entry.host) continue;
      const port = r.port || (r.tls ? 443 : 80);
      if (port !== entry.port || !!r.tls !== entry.tls) continue;
      const key = r.method + " " + r.path;
      const prev = byKey.get(key);
      if (!prev || r.id > prev.id) byKey.set(key, r);
    }
    const leaves = Array.from(byKey.values()).sort((a, b) => a.path.localeCompare(b.path));
    return annotatedOnly ? leaves.filter(r => annotations && annotations[r.id]) : leaves;
  };

  return (
    <div className="pane" style={{ height: "100%" }}>
      <div className="pane-head">
        <span className="ph-corner">▸</span>
        <span>SITE MAP</span>
        <span className="ph-count">{entries.length} HOSTS · {totalRows} REQ</span>
      </div>
      <div className="sm-add-row" title="Hand-add an item to the site map without sending it -- lands as an unrequested (greyed) node, same as Burp's manual mapping">
        <input
          className="sm-add-input"
          value={addUrlText}
          onChange={e => setAddUrlText(e.target.value)}
          onKeyDown={e => { if (e.key === "Enter") addUrlToMap(); }}
          placeholder="add URL to map by hand…"
          spellCheck={false}
        />
        <button className="sm-add-btn" disabled={addUrlBusy || !addUrlText.trim()} onClick={addUrlToMap}>+ ADD</button>
      </div>
      {addUrlErr && <div className="sm-add-err">{addUrlErr}</div>}
      <div className="pane-body">
        <div
          className={"sm-row " + (selectedOrigin == null ? "sel" : "")}
          onClick={() => onSelect(null)}
        >
          <span style={{ color: "var(--accent)" }}>◆</span>
          <span className="sm-host">all hosts</span>
          <span className="sm-count">{totalRows}</span>
        </div>
        {selectedOrigin && selectedOrigin.branch && (
          <div className="sm-scope-banner" title="History table (and Deep Search results) are scoped to this branch">
            <span>▸ branch: {selectedOrigin.branch}</span>
            <span className="sm-scope-clear" onClick={() => onSelect(selectedOrigin)}>✕ clear</span>
          </div>
        )}
        {entries.map(e => {
          const isOpen = expanded.has(e.origin);
          const isSel = selectedOrigin != null && selectedOrigin.host === e.host
            && selectedOrigin.port === e.port && selectedOrigin.tls === e.tls
            && !selectedOrigin.branch;
          return (
            <React.Fragment key={e.origin}>
              <div
                className={"sm-row " + (isSel ? "sel" : "")}
                onClick={() => onSelect(e)}
                onContextMenu={onRowContextMenu ? (ev => { ev.preventDefault(); onRowContextMenu(e.host, ev); }) : undefined}
              >
                <span className={"sm-tls" + (e.tls ? "" : " off")}>◉</span>
                <span className="sm-host" title={e.origin}>
                  <span className="sm-twisty" onClick={ev => toggleExpand(e.origin, ev)} title={isOpen ? "collapse" : "expand URLs"}>{isOpen ? "▾" : "▸"}</span>
                  {e.origin}
                </span>
                <span className="sm-count">{e.count}</span>
              </div>
              {isOpen && renderTreeNode(buildSiteMapTree(leavesFor(e)), e, 1)}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
}

function DetailPane({ row, onSendRepeater, onSendIntruder, onSendComparer, onSendDecoder, onSendSequencer }) {
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
  const [reqSel, setReqSel] = React.useState(null);
  const [respSel, setRespSel] = React.useState(null);
  const [overlay, setOverlay] = React.useState(null); // { title, body } | null
  const [copyMenuOpen, setCopyMenuOpen] = React.useState(false);
  const [cmpMenuOpen, setCmpMenuOpen] = React.useState(false);
  const [decMenuOpen, setDecMenuOpen] = React.useState(false);
  const [authzOpen, setAuthzOpen] = React.useState(false);

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

  const req = NL.requestRawById(row.id);
  const resp = NL.responseRawById(row.id);

  // Pull either the user's text selection or the entire textarea contents.
  // Clicking a codec button with no selection runs it against the whole
  // pane -- handy for "decode this whole base64 body".
  const grabFrom = (ref) => {
    const el = ref.current;
    if (!el) return "";
    const sel = el.value.substring(el.selectionStart, el.selectionEnd);
    return sel || el.value;
  };

  // Burp's Inspector "Selection" widget (#362): length + first byte's
  // decimal/hex value, fed into the docked RepeaterInspectorPanel below.
  // Reuses tabs.jsx's repeaterSelectionStats -- both files load into the
  // same global scope, tabs.jsx after proxy.jsx, but this only runs from
  // event handlers (never at module-eval time), so the load order is fine.
  const onReqSelect = () => {
    const el = reqRef.current;
    if (el) setReqSel(repeaterSelectionStats(el.value, el.selectionStart, el.selectionEnd));
  };
  const onRespSelect = () => {
    const el = respRef.current;
    if (el) setRespSel(repeaterSelectionStats(el.value, el.selectionStart, el.selectionEnd));
  };

  // #167 "Send to Sequencer": unlike Comparer/Decoder (whole request/
  // response), Sequencer analyzes a small token corpus, so this requires an
  // actual selection -- prefers the response since that's where session/
  // CSRF/reset tokens usually live, falls back to the request selection.
  const sendSelectionToSequencer = () => {
    const ref = respSel ? respRef : reqSel ? reqRef : null;
    if (!ref || !ref.current) return;
    const el = ref.current;
    const t = el.value.substring(el.selectionStart, el.selectionEnd);
    if (t && onSendSequencer) onSendSequencer(t);
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
        <button onClick={sendSelectionToSequencer} disabled={!reqSel && !respSel}
                title="Send the selected text (a token) to Sequencer -- select a value in the request or response first">↦ SEQUENCER</button>
        <div style={{ position: "relative", display: "inline-block" }}>
          <button onClick={() => setCmpMenuOpen(o => !o)} title="Send to Comparer">↦ COMPARER ▾</button>
          {cmpMenuOpen && (
            <div onClick={(e) => e.stopPropagation()}
                 style={{
                   position: "absolute", top: "100%", right: 0, zIndex: 30,
                   background: "var(--pane)", border: "1px solid var(--accent)",
                   boxShadow: "0 8px 24px rgba(0,0,0,0.4)",
                   fontFamily: "var(--ff-mono)", fontSize: "11px",
                   minWidth: 140, marginTop: 4,
                 }}>
              <div onClick={() => { onSendComparer("request", "#" + row.id + " request", req); setCmpMenuOpen(false); }}
                   style={{ padding: "6px 10px", cursor: "pointer", borderBottom: "1px solid var(--line-soft)", color: "var(--text)" }}>
                request
              </div>
              <div onClick={() => { onSendComparer("response", "#" + row.id + " response", resp); setCmpMenuOpen(false); }}
                   style={{ padding: "6px 10px", cursor: "pointer", color: "var(--text)" }}>
                response
              </div>
            </div>
          )}
        </div>
        <div style={{ position: "relative", display: "inline-block" }}>
          <button onClick={() => setDecMenuOpen(o => !o)} title="Send to Decoder">↦ DECODER ▾</button>
          {decMenuOpen && (
            <div onClick={(e) => e.stopPropagation()}
                 style={{
                   position: "absolute", top: "100%", right: 0, zIndex: 30,
                   background: "var(--pane)", border: "1px solid var(--accent)",
                   boxShadow: "0 8px 24px rgba(0,0,0,0.4)",
                   fontFamily: "var(--ff-mono)", fontSize: "11px",
                   minWidth: 140, marginTop: 4,
                 }}>
              <div onClick={() => { onSendDecoder("#" + row.id + " request", req); setDecMenuOpen(false); }}
                   style={{ padding: "6px 10px", cursor: "pointer", borderBottom: "1px solid var(--line-soft)", color: "var(--text)" }}>
                request
              </div>
              <div onClick={() => { onSendDecoder("#" + row.id + " response", resp); setDecMenuOpen(false); }}
                   style={{ padding: "6px 10px", cursor: "pointer", color: "var(--text)" }}>
                response
              </div>
            </div>
          )}
        </div>
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
        <button onClick={async () => {
          try {
            const r = await NL.actions.csrfPoc(row.id);
            if (!r.ok) { alert("CSRF PoC failed: " + (r.error || "unknown")); return; }
            setOverlay({
              title: "CSRF POC · " + r.method + " " + r.url,
              body: r.html,
              note: r.note,
              downloadName: "csrf-poc-row-" + row.id + ".html",
            });
          } catch (e) {
            alert("CSRF PoC error: " + e);
          }
        }} title="Generate an auto-submitting CSRF proof-of-concept HTML page for this request (CWE-352)">⚔ CSRF POC</button>
        <button onClick={() => setAuthzOpen(true)}
                title="Replay this request as multiple identities and flag divergent responses (BOLA / horizontal / vertical privilege, CWE-863)">⚖ AUTHZ TEST</button>
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
            {["raw", "headers", "body", "hex", "inspector"].map(t => (
              <button key={t} className={reqTab === t ? "on" : ""} onClick={() => setReqTab(t)}>
                REQ · {t}
              </button>
            ))}
          </div>
          {reqTab === "inspector" ? (
            <RepeaterInspectorPanel raw={req} kind="request" sel={reqSel} />
          ) : (
            <React.Fragment>
              <CodecBar onRun={(name) => {
                const input = grabFrom(reqRef);
                setOverlay({ title: "REQ · " + name, body: runCodec(name, input) });
              }} />
              <textarea ref={reqRef} className="txt readonly" value={renderView(req, reqTab)} readOnly
                        onSelect={onReqSelect} onMouseUp={onReqSelect} onKeyUp={onReqSelect} />
              <RepeaterSelectionReadout sel={reqSel} />
            </React.Fragment>
          )}
        </div>
        <div style={{ display:"flex", flexDirection:"column", minHeight: 0 }}>
          <div className="detail-tabs">
            {["raw", "headers", "body", "preview", "hex", "inspector"].map(t => (
              <button key={t} className={respTab === t ? "on" : ""} onClick={() => setRespTab(t)}>
                RES · {t}
              </button>
            ))}
          </div>
          {respTab === "inspector" ? (
            <RepeaterInspectorPanel raw={resp} kind="response" sel={respSel} />
          ) : (
            <React.Fragment>
              <CodecBar onRun={(name) => {
                const input = grabFrom(respRef);
                setOverlay({ title: "RES · " + name, body: runCodec(name, input) });
              }} />
              <textarea ref={respRef} className="txt readonly" value={renderView(resp, respTab)} readOnly
                        onSelect={onRespSelect} onMouseUp={onRespSelect} onKeyUp={onRespSelect} />
              <RepeaterSelectionReadout sel={respSel} />
            </React.Fragment>
          )}
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
      {authzOpen && (
        <AuthzTestOverlay rowId={row.id} onClose={() => setAuthzOpen(false)} />
      )}
    </div>
  );
}

// Parse "Header: value" lines (one per line) into a plain object, skipping
// blank lines and lines with no ':'. Shared by the Authz Test identity
// editor -- each identity's overlay headers are typed as raw header text.
function parseHeaderLines(text) {
  const headers = {};
  (text || "").split(/\r?\n/).forEach((line) => {
    const idx = line.indexOf(":");
    if (idx <= 0) return;
    const k = line.slice(0, idx).trim();
    const v = line.slice(idx + 1).trim();
    if (k) headers[k] = v;
  });
  return headers;
}

// Multi-identity authz replay (Burp Auth Analyzer equivalent). Lets the
// user define N identities as name + raw "Header: value" lines, replays
// the captured row as each, and shows per-identity status/size plus a
// divergence flag (server also files an authz-divergence finding when
// divergent, which shows up in Issues independently of this modal).
function AuthzTestOverlay({ rowId, onClose }) {
  const [identities, setIdentities] = React.useState([
    { id: 1, name: "user-a", headersText: "Cookie: session=" },
    { id: 2, name: "user-b", headersText: "Cookie: session=" },
  ]);
  const [nextId, setNextId] = React.useState(3);
  const [result, setResult] = React.useState(null); // { ok, divergent, results, row } | null
  const [error, setError] = React.useState(null);
  const [running, setRunning] = React.useState(false);

  React.useEffect(() => {
    const onKey = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const setField = (id, field, value) => {
    setIdentities((prev) => prev.map((it) => (it.id === id ? { ...it, [field]: value } : it)));
  };
  const addIdentity = () => {
    setIdentities((prev) => [...prev, { id: nextId, name: "identity-" + nextId, headersText: "" }]);
    setNextId((n) => n + 1);
  };
  const removeIdentity = (id) => {
    setIdentities((prev) => prev.filter((it) => it.id !== id));
  };

  const run = async () => {
    setError(null);
    setResult(null);
    const payload = identities
      .map((it) => ({ name: it.name.trim(), headers: parseHeaderLines(it.headersText) }))
      .filter((it) => it.name);
    if (payload.length === 0) { setError("At least one named identity is required."); return; }
    setRunning(true);
    try {
      const r = await NL.actions.authzTest(rowId, payload);
      if (!r.ok) setError(r.error || "authz-test failed");
      else setResult(r);
    } catch (e) {
      setError(String(e));
    } finally {
      setRunning(false);
    }
  };

  const btn = {
    background: "transparent", color: "var(--accent)",
    border: "1px solid var(--accent)", padding: "2px 8px",
    fontSize: "10px", fontFamily: "var(--ff-mono)", cursor: "pointer",
  };

  return (
    <div onClick={onClose}
         style={{
           position: "fixed", inset: 0, background: "rgba(0,0,0,0.55)",
           display: "grid", placeItems: "center", zIndex: 50,
         }}>
      <div onClick={(e) => e.stopPropagation()}
           style={{
             background: "var(--pane)", border: "1px solid var(--accent)",
             width: "min(80vw, 760px)", maxHeight: "80vh", overflow: "auto",
             display: "flex", flexDirection: "column",
             boxShadow: "0 0 0 1px var(--line), 0 12px 40px rgba(0,0,0,0.5)",
           }}>
        <div style={{
          display: "flex", alignItems: "center", gap: 8, padding: "8px 12px",
          borderBottom: "1px solid var(--line)",
          color: "var(--accent)", fontSize: "11px",
          textTransform: "uppercase", letterSpacing: "0.06em",
        }}>
          <span style={{ flex: 1 }}>⚖ AUTHZ TEST · row #{rowId}</span>
          <button onClick={onClose} style={{ ...btn, borderColor: "var(--line)", color: "var(--dim)" }}>CLOSE</button>
        </div>
        <div style={{ padding: "10px 12px", color: "var(--dim)", fontSize: "11px", borderBottom: "1px solid var(--line-soft)" }}>
          Replays this request once per identity below, overlaying each identity's headers
          onto the captured request (unlisted headers pass through unchanged). A divergent
          status code or body size across identities suggests a BOLA / horizontal / vertical
          privilege issue and is also filed as a finding in Issues.
        </div>
        <div style={{ padding: "10px 12px", display: "flex", flexDirection: "column", gap: 10 }}>
          {identities.map((it) => (
            <div key={it.id} style={{ border: "1px solid var(--line-soft)", padding: 8 }}>
              <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 6 }}>
                <input value={it.name}
                       onChange={(e) => setField(it.id, "name", e.target.value)}
                       placeholder="identity name"
                       style={{
                         flex: 1, background: "var(--bg-deep)", color: "var(--text)",
                         border: "1px solid var(--line)", padding: "3px 6px",
                         fontFamily: "var(--ff-mono)", fontSize: "11px",
                       }} />
                <button onClick={() => removeIdentity(it.id)} style={btn}>REMOVE</button>
              </div>
              <textarea value={it.headersText}
                        onChange={(e) => setField(it.id, "headersText", e.target.value)}
                        placeholder={"Header: value\\nAuthorization: Bearer ..."}
                        style={{
                          width: "100%", minHeight: 50, background: "var(--bg-deep)",
                          color: "var(--text)", border: "1px solid var(--line)",
                          padding: 6, fontFamily: "var(--ff-mono)", fontSize: "11px",
                          resize: "vertical", boxSizing: "border-box",
                        }} />
            </div>
          ))}
          <div>
            <button onClick={addIdentity} style={btn}>+ ADD IDENTITY</button>
          </div>
          <div>
            <button onClick={run} disabled={running}
                    style={{ ...btn, opacity: running ? 0.5 : 1 }}>
              {running ? "RUNNING…" : "▸ RUN"}
            </button>
          </div>
          {error && (
            <div style={{ color: "var(--err, #e05555)", fontSize: "11px" }}>{error}</div>
          )}
          {result && (
            <div>
              <div style={{
                marginBottom: 6, fontSize: "11px",
                color: result.divergent ? "var(--err, #e05555)" : "var(--ok, #55c07a)",
              }}>
                {result.divergent
                  ? "⚠ DIVERGENT — responses differ across identities (finding filed in Issues)"
                  : "✓ consistent — same status/size across all identities"}
              </div>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "11px" }}>
                <thead>
                  <tr style={{ color: "var(--dim)", textAlign: "left" }}>
                    <th style={{ padding: "4px 6px" }}>identity</th>
                    <th style={{ padding: "4px 6px" }}>status</th>
                    <th style={{ padding: "4px 6px" }}>body size</th>
                    <th style={{ padding: "4px 6px" }}>error</th>
                  </tr>
                </thead>
                <tbody>
                  {(result.results || []).map((r, i) => (
                    <tr key={i} style={{ borderTop: "1px solid var(--line-soft)" }}>
                      <td style={{ padding: "4px 6px", color: "var(--text)" }}>{r.identity}</td>
                      <td style={{ padding: "4px 6px" }}>{r.ok ? r.status : "—"}</td>
                      <td style={{ padding: "4px 6px" }}>{r.ok ? r.bodySize : "—"}</td>
                      <td style={{ padding: "4px 6px", color: "var(--dim)" }}>{r.error || ""}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ===================== WS REPEATER (WebSocket message injection) =====
// #270: the backend (WsRepeater + POST /api/ws/send + GET /api/ws/sessions)
// is complete but had zero front-end callers -- the only way to inject a
// frame into a live WebSocket tunnel was to hand-craft a curl POST. This
// overlay lists live sessions (polled while open) and lets the operator
// pick a direction/opcode, edit a payload, and queue it onto the tunnel's
// relay thread, with a one-click resend of the last frame sent.
const WS_OPCODES = [
  { v: 0x1, label: "0x1 text" },
  { v: 0x2, label: "0x2 binary (base64)" },
  { v: 0x8, label: "0x8 close" },
  { v: 0x9, label: "0x9 ping" },
  { v: 0xA, label: "0xA pong" },
];

function WsRepeaterOverlay({ onClose }) {
  const [sessions, setSessions] = React.useState([]);
  const [sessionId, setSessionId] = React.useState(null);
  const [direction, setDirection] = React.useState("up");
  const [opcode, setOpcode] = React.useState(0x1);
  const [payload, setPayload] = React.useState("");
  const [lastSent, setLastSent] = React.useState(null); // {sessionId,direction,opcode,payload} | null
  const [result, setResult] = React.useState(null); // {ok,queued} | null
  const [error, setError] = React.useState(null);
  const [sending, setSending] = React.useState(false);

  const refresh = React.useCallback(async () => {
    try {
      const r = await NL.actions.wsSessions();
      const list = r.sessions || [];
      setSessions(list);
      setSessionId(id => (id != null && list.some(s => s.id === id)) ? id : (list[0] ? list[0].id : null));
    } catch (e) { /* transient poll failure, keep last-known list */ }
  }, []);

  React.useEffect(() => {
    refresh();
    const t = setInterval(refresh, 2000);
    const onKey = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => { clearInterval(t); window.removeEventListener("keydown", onKey); };
  }, [refresh, onClose]);

  const send = async (overrides) => {
    const req = Object.assign({ sessionId, direction, opcode, payload }, overrides || {});
    if (req.sessionId == null) { setError("No live WebSocket session -- open one via the intercepting proxy first."); return; }
    setError(null);
    setSending(true);
    try {
      // The endpoint's "ok" mirrors "queued" by design (a closed session is
      // an expected, non-exceptional outcome) -- render it via the result
      // block below, not as an error state. `error` here is reserved for
      // actual transport/parse failures (network drop, malformed JSON).
      const r = await NL.actions.wsSend(req.sessionId, req.direction, req.opcode, req.payload);
      setResult(r);
      if (r && r.queued) setLastSent(req);
    } catch (e) {
      setError(String(e));
    } finally {
      setSending(false);
    }
  };

  const btn = {
    background: "transparent", color: "var(--accent)",
    border: "1px solid var(--accent)", padding: "2px 8px",
    fontSize: "10px", fontFamily: "var(--ff-mono)", cursor: "pointer",
  };
  const field = {
    background: "var(--bg-deep)", color: "var(--text)",
    border: "1px solid var(--line)", padding: "3px 6px",
    fontFamily: "var(--ff-mono)", fontSize: "11px",
  };

  return (
    <div onClick={onClose}
         style={{
           position: "fixed", inset: 0, background: "rgba(0,0,0,0.55)",
           display: "grid", placeItems: "center", zIndex: 50,
         }}>
      <div onClick={(e) => e.stopPropagation()}
           style={{
             background: "var(--pane)", border: "1px solid var(--accent)",
             width: "min(80vw, 720px)", maxHeight: "80vh", overflow: "auto",
             display: "flex", flexDirection: "column",
             boxShadow: "0 0 0 1px var(--line), 0 12px 40px rgba(0,0,0,0.5)",
           }}>
        <div style={{
          display: "flex", alignItems: "center", gap: 8, padding: "8px 12px",
          borderBottom: "1px solid var(--line)",
          color: "var(--accent)", fontSize: "11px",
          textTransform: "uppercase", letterSpacing: "0.06em",
        }}>
          <span style={{ flex: 1 }}>⇄ WS REPEATER</span>
          <button onClick={onClose} style={{ ...btn, borderColor: "var(--line)", color: "var(--dim)" }}>CLOSE</button>
        </div>
        <div style={{ padding: "10px 12px", color: "var(--dim)", fontSize: "11px", borderBottom: "1px solid var(--line-soft)" }}>
          Injects a frame directly onto a live WebSocket tunnel the MITM proxy is currently
          relaying (TLS-MITM leg only). Sessions list refreshes every 2s -- open/keep a
          WebSocket connection through the proxy to see one here.
        </div>
        <div style={{ padding: "10px 12px", display: "flex", flexDirection: "column", gap: 10 }}>
          <div>
            <div style={{ color: "var(--dim)", fontSize: "10px", marginBottom: 4 }}>LIVE SESSIONS ({sessions.length})</div>
            <select value={sessionId == null ? "" : sessionId}
                    onChange={(e) => setSessionId(e.target.value === "" ? null : Number(e.target.value))}
                    style={{ ...field, width: "100%" }}>
              {sessions.length === 0 && <option value="">— none open —</option>}
              {sessions.map(s => (
                <option key={s.id} value={s.id}>
                  #{s.id} {s.host}:{s.port} — ↑{s.framesUp} ↓{s.framesDown}
                </option>
              ))}
            </select>
          </div>
          <div style={{ display: "flex", gap: 10 }}>
            <div style={{ flex: 1 }}>
              <div style={{ color: "var(--dim)", fontSize: "10px", marginBottom: 4 }}>DIRECTION</div>
              <select value={direction} onChange={(e) => setDirection(e.target.value)} style={{ ...field, width: "100%" }}>
                <option value="up">↑ up (client → server)</option>
                <option value="down">↓ down (server → client)</option>
              </select>
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ color: "var(--dim)", fontSize: "10px", marginBottom: 4 }}>OPCODE</div>
              <select value={opcode} onChange={(e) => setOpcode(Number(e.target.value))} style={{ ...field, width: "100%" }}>
                {WS_OPCODES.map(o => <option key={o.v} value={o.v}>{o.label}</option>)}
              </select>
            </div>
          </div>
          <div>
            <div style={{ color: "var(--dim)", fontSize: "10px", marginBottom: 4 }}>
              PAYLOAD {opcode === 0x2 ? "(base64-encoded bytes)" : "(text)"}
            </div>
            <textarea value={payload} onChange={(e) => setPayload(e.target.value)}
                      placeholder={opcode === 0x2 ? "base64…" : "frame payload…"}
                      style={{ width: "100%", minHeight: 80, resize: "vertical", boxSizing: "border-box", ...field }} />
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button onClick={() => send()} disabled={sending || sessionId == null}
                    style={{ ...btn, opacity: (sending || sessionId == null) ? 0.5 : 1 }}>
              {sending ? "SENDING…" : "▸ SEND"}
            </button>
            <button onClick={() => send(lastSent)} disabled={sending || !lastSent}
                    style={{ ...btn, opacity: (sending || !lastSent) ? 0.5 : 1 }}>
              ↻ RESEND LAST
            </button>
          </div>
          {error && <div style={{ color: "var(--err, #e05555)", fontSize: "11px" }}>{error}</div>}
          {result && !error && (
            <div style={{ color: result.queued ? "var(--ok, #55c07a)" : "var(--err, #e05555)", fontSize: "11px" }}>
              {result.queued
                ? "✓ queued — handed to the relay thread (delivery to the wire isn't observable here)"
                : "✗ not queued — session closed before this frame reached it"}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ===================== H2 FRAME LOG (HTTP/2 frame-level visibility) ===
// #277: H2EventLog captures every h2 frame on both MITM legs (client and
// upstream) but had zero front-end callers -- API-only, "Burp has no frame
// log at all" per the parity plan. This overlay shows the per-stream
// summary table (GET /api/h2/streams) plus a live-tailing raw frame feed
// (GET /api/h2/events?since=<cursor ms>), polled while open.
function H2FrameLogOverlay({ onClose }) {
  const [streams, setStreams] = React.useState([]);
  const [events, setEvents] = React.useState([]);
  const [autoPoll, setAutoPoll] = React.useState(true);
  const [error, setError] = React.useState(null);
  const sinceRef = React.useRef(0);

  const refresh = React.useCallback(async () => {
    try {
      const [sr, er] = await Promise.all([
        NL.actions.h2Streams(),
        NL.actions.h2Events(sinceRef.current),
      ]);
      setStreams(sr.streams || []);
      const fresh = er.events || [];
      if (fresh.length) {
        sinceRef.current = fresh.reduce((m, e) => Math.max(m, e.ts), sinceRef.current);
        setEvents(prev => [...fresh, ...prev].slice(0, 500));
      }
      setError(null);
    } catch (e) { setError(String(e)); }
  }, []);

  React.useEffect(() => {
    refresh();
    const onKey = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [refresh, onClose]);

  React.useEffect(() => {
    if (!autoPoll) return undefined;
    const t = setInterval(refresh, 2000);
    return () => clearInterval(t);
  }, [autoPoll, refresh]);

  const btn = {
    background: "transparent", color: "var(--accent)",
    border: "1px solid var(--accent)", padding: "2px 8px",
    fontSize: "10px", fontFamily: "var(--ff-mono)", cursor: "pointer",
  };
  const cellStyle = { padding: "3px 6px", borderBottom: "1px solid var(--line-soft)" };

  return (
    <div onClick={onClose}
         style={{
           position: "fixed", inset: 0, background: "rgba(0,0,0,0.55)",
           display: "grid", placeItems: "center", zIndex: 50,
         }}>
      <div onClick={(e) => e.stopPropagation()}
           style={{
             background: "var(--pane)", border: "1px solid var(--accent)",
             width: "min(90vw, 900px)", maxHeight: "85vh", overflow: "auto",
             display: "flex", flexDirection: "column",
             boxShadow: "0 0 0 1px var(--line), 0 12px 40px rgba(0,0,0,0.5)",
           }}>
        <div style={{
          display: "flex", alignItems: "center", gap: 8, padding: "8px 12px",
          borderBottom: "1px solid var(--line)",
          color: "var(--accent)", fontSize: "11px",
          textTransform: "uppercase", letterSpacing: "0.06em",
        }}>
          <span style={{ flex: 1 }}>⇅ H2 FRAME LOG</span>
          <label style={{ color: "var(--dim)", fontSize: "10px", display: "flex", alignItems: "center", gap: 4, cursor: "pointer" }}>
            <input type="checkbox" checked={autoPoll} onChange={(e) => setAutoPoll(e.target.checked)} />
            auto (2s)
          </label>
          <button onClick={refresh} style={{ ...btn, borderColor: "var(--line)", color: "var(--dim)" }}>REFRESH</button>
          <button onClick={onClose} style={{ ...btn, borderColor: "var(--line)", color: "var(--dim)" }}>CLOSE</button>
        </div>
        <div style={{ padding: "10px 12px", color: "var(--dim)", fontSize: "11px", borderBottom: "1px solid var(--line-soft)" }}>
          Per-stream summary and a raw frame-level feed captured on either MITM leg
          (client or upstream) of any HTTP/2 connection the proxy negotiated via ALPN.
        </div>
        {error && <div style={{ padding: "6px 12px", color: "var(--err, #e05555)", fontSize: "11px" }}>{error}</div>}
        <div style={{ padding: "8px 12px 4px", color: "var(--dim)", fontSize: "10px" }}>STREAMS ({streams.length})</div>
        <div style={{ overflowX: "auto", padding: "0 12px" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontFamily: "var(--ff-mono)", fontSize: "11px" }}>
            <thead>
              <tr style={{ color: "var(--dim)", textAlign: "left" }}>
                <th style={cellStyle}>conn</th>
                <th style={cellStyle}>stream</th>
                <th style={cellStyle}>method</th>
                <th style={cellStyle}>path</th>
                <th style={cellStyle}>status</th>
                <th style={cellStyle}>bytes in/out</th>
                <th style={cellStyle}>frames in/out</th>
                <th style={cellStyle}>state</th>
              </tr>
            </thead>
            <tbody>
              {streams.length === 0 && (
                <tr><td colSpan={8} style={{ ...cellStyle, color: "var(--dim)" }}>— no HTTP/2 streams captured yet —</td></tr>
              )}
              {streams.map(s => (
                <tr key={s.conn + ":" + s.streamId}>
                  <td style={cellStyle}>{s.conn}</td>
                  <td style={cellStyle}>{s.streamId}</td>
                  <td style={cellStyle}>{s.method || ""}</td>
                  <td style={{ ...cellStyle, maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.path || ""}</td>
                  <td style={cellStyle}>{s.status || ""}</td>
                  <td style={cellStyle}>{s.bytesIn}/{s.bytesOut}</td>
                  <td style={cellStyle}>{s.framesIn}/{s.framesOut}</td>
                  <td style={cellStyle}>{s.closed ? "closed" : "open"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div style={{ padding: "10px 12px 4px", color: "var(--dim)", fontSize: "10px" }}>FRAMES ({events.length}, newest first)</div>
        <div style={{ overflowX: "auto", padding: "0 12px 10px" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontFamily: "var(--ff-mono)", fontSize: "11px" }}>
            <thead>
              <tr style={{ color: "var(--dim)", textAlign: "left" }}>
                <th style={cellStyle}>ts</th>
                <th style={cellStyle}>conn</th>
                <th style={cellStyle}>type</th>
                <th style={cellStyle}>flags</th>
                <th style={cellStyle}>stream</th>
                <th style={cellStyle}>bytes</th>
                <th style={cellStyle}>error</th>
              </tr>
            </thead>
            <tbody>
              {events.length === 0 && (
                <tr><td colSpan={7} style={{ ...cellStyle, color: "var(--dim)" }}>— no frames yet —</td></tr>
              )}
              {events.map((e, i) => (
                <tr key={e.ts + ":" + e.conn + ":" + e.streamId + ":" + i}>
                  <td style={cellStyle}>{new Date(e.ts).toLocaleTimeString()}</td>
                  <td style={cellStyle}>{e.conn}</td>
                  <td style={cellStyle}>{e.type}</td>
                  <td style={cellStyle}>{e.flags}</td>
                  <td style={cellStyle}>{e.streamId}</td>
                  <td style={cellStyle}>{e.bytes}</td>
                  <td style={cellStyle}>{e.errorCode ? e.errorCode : ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// #268: SQLite-backed history search at engagement scale. The in-UI free-text
// search (FilterBar) only ever sees NL.rows, the bounded in-memory window --
// once a row is evicted from that window it becomes invisible to the box even
// though the SQLite index (and /api/history/find) still has it. This overlay
// is the missing "find a row you don't already have on screen" tool: it hits
// the DB-indexed endpoint directly with structured filters, then opens the
// found row's full raw request/response via the same eviction-safe cold-fetch
// path (NL.requestRawById/responseRawById) DetailPane already relies on.
//
// Pure: turns the form's string fields into the /api/history/find JSON body.
// Blank fields are omitted rather than sent as "" or NaN (the backend drops
// unreadable numeric filters, but there is no reason to even send them).
// `nowMs` is threaded in rather than read from Date.now() so this stays a
// pure, unit-testable function.
function buildHistoryFindFilters(f, nowMs) {
  const filters = {};
  if (f.method && f.method.trim()) filters.method = f.method.trim();
  if (f.host   && f.host.trim())   filters.host   = f.host.trim();
  if (f.path   && f.path.trim())   filters.path   = f.path.trim();
  const num = (s) => {
    if (s == null || String(s).trim() === "") return null;
    const n = Number(s);
    return Number.isFinite(n) ? n : null;
  };
  const status  = num(f.status);  if (status  != null) filters.status  = status;
  const minSize = num(f.minSize); if (minSize != null) filters.minSize = minSize;
  const maxSize = num(f.maxSize); if (maxSize != null) filters.maxSize = maxSize;
  const sinceMins = num(f.sinceMins);
  if (sinceMins != null) filters.sinceMs = nowMs - sinceMins * 60000;
  const limit = num(f.limit);
  filters.limit = limit != null && limit > 0 ? limit : 200;
  return filters;
}

function TargetAnalyzerOverlay({ rows, scopeLabel, onClose }) {
  const result = React.useMemo(() => analyzeTargetSurface(rows), [rows]);

  React.useEffect(() => {
    const onKey = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const btn = {
    background: "transparent", color: "var(--accent)",
    border: "1px solid var(--accent)", padding: "2px 8px",
    fontSize: "10px", fontFamily: "var(--ff-mono)", cursor: "pointer",
  };
  const dimBtn = { ...btn, borderColor: "var(--line)", color: "var(--dim)" };
  const cellStyle = { padding: "3px 6px", borderBottom: "1px solid var(--line-soft)" };
  const statBox = { padding: 8, textAlign: "center" };

  return (
    <div onClick={onClose}
         style={{
           position: "fixed", inset: 0, background: "rgba(0,0,0,0.55)",
           display: "grid", placeItems: "center", zIndex: 50,
         }}>
      <div onClick={(e) => e.stopPropagation()}
           style={{
             background: "var(--pane)", border: "1px solid var(--accent)",
             width: "min(94vw, 900px)", maxHeight: "88vh", overflow: "auto",
             display: "flex", flexDirection: "column",
             boxShadow: "0 0 0 1px var(--line), 0 12px 40px rgba(0,0,0,0.5)",
           }}>
        <div style={{
          display: "flex", alignItems: "center", gap: 8, padding: "8px 12px",
          borderBottom: "1px solid var(--line)",
          color: "var(--accent)", fontSize: "11px",
          textTransform: "uppercase", letterSpacing: "0.06em",
        }}>
          <span style={{ flex: 1 }}>◆ ANALYZE TARGET — {scopeLabel}</span>
          <button onClick={onClose} style={dimBtn}>CLOSE</button>
        </div>
        <div style={{ padding: "10px 12px", color: "var(--dim)", fontSize: "11px", borderBottom: "1px solid var(--line-soft)" }}>
          Attack-surface sizing computed client-side from the HTTP history already captured for
          this scope — static/dynamic classification is a URL-shape heuristic (extension +
          query string). Parameter names only cover the query string: request bodies aren't held
          client-side, so form/JSON body parameter names aren't counted here.
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 8, padding: "10px 12px", borderBottom: "1px solid var(--line-soft)" }}>
          <div className="pane" style={statBox}>
            <div style={{ fontSize: 20, color: "var(--accent)" }}>{result.totalUrls}</div>
            <div style={{ fontSize: 10, color: "var(--dim)" }}>UNIQUE URLS</div>
          </div>
          <div className="pane" style={statBox}>
            <div style={{ fontSize: 20, color: "var(--accent)" }}>{result.dynamicCount}</div>
            <div style={{ fontSize: 10, color: "var(--dim)" }}>DYNAMIC</div>
          </div>
          <div className="pane" style={statBox}>
            <div style={{ fontSize: 20, color: "var(--accent)" }}>{result.staticCount}</div>
            <div style={{ fontSize: 10, color: "var(--dim)" }}>STATIC</div>
          </div>
        </div>
        <div style={{ padding: "8px 12px 4px", color: "var(--dim)", fontSize: "10px" }}>
          {result.paramNames.length} unique query parameter name{result.paramNames.length === 1 ? "" : "s"}
        </div>
        <div style={{ padding: "0 12px 8px", display: "flex", flexWrap: "wrap", gap: 4 }}>
          {result.paramNames.map(p => (
            <span key={p.name} title={p.count + " entry point" + (p.count === 1 ? "" : "s")}
                  style={{ border: "1px solid var(--line)", padding: "2px 6px", fontSize: "10px", fontFamily: "var(--ff-mono)" }}>
              {p.name} <span style={{ color: "var(--dim)" }}>×{p.count}</span>
            </span>
          ))}
          {result.paramNames.length === 0 && <span style={{ fontSize: 11, color: "var(--dim)" }}>none seen</span>}
        </div>
        <div style={{ overflowX: "auto", padding: "0 12px 12px" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontFamily: "var(--ff-mono)", fontSize: "11px" }}>
            <thead>
              <tr style={{ color: "var(--dim)", textAlign: "left" }}>
                <th style={cellStyle}>path</th>
                <th style={cellStyle}>kind</th>
                <th style={cellStyle}>methods</th>
                <th style={cellStyle}>params</th>
              </tr>
            </thead>
            <tbody>
              {result.entryPoints.map(ep => (
                <tr key={ep.path}>
                  <td style={cellStyle}>{ep.path}</td>
                  <td style={cellStyle}>{ep.kind}</td>
                  <td style={cellStyle}>{ep.methods.join(", ")}</td>
                  <td style={cellStyle}>{ep.paramNames.join(", ") || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function DbSearchOverlay({ onClose }) {
  const [f, setF] = React.useState({ method: "", host: "", path: "", status: "", minSize: "", maxSize: "", sinceMins: "", limit: "200" });
  const [rows, setRows] = React.useState(null); // null = not searched yet
  const [count, setCount] = React.useState(0);
  const [error, setError] = React.useState(null);
  const [busy, setBusy] = React.useState(false);
  const [openId, setOpenId] = React.useState(null);
  const [view, setView] = React.useState("text"); // text | hex

  const setField = (k) => (e) => setF(prev => ({ ...prev, [k]: e.target.value }));

  const runSearch = async (e) => {
    if (e) e.preventDefault();
    setBusy(true); setError(null);
    try {
      const filters = buildHistoryFindFilters(f, Date.now());
      const res = await NL.actions.historyFind(filters);
      setRows(res.rows || []);
      setCount(res.count || 0);
      setOpenId(null);
    } catch (err) {
      setError(String(err));
      setRows([]);
      setCount(0);
    } finally {
      setBusy(false);
    }
  };

  React.useEffect(() => {
    const onKey = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const btn = {
    background: "transparent", color: "var(--accent)",
    border: "1px solid var(--accent)", padding: "2px 8px",
    fontSize: "10px", fontFamily: "var(--ff-mono)", cursor: "pointer",
  };
  const dimBtn = { ...btn, borderColor: "var(--line)", color: "var(--dim)" };
  const cellStyle = { padding: "3px 6px", borderBottom: "1px solid var(--line-soft)" };
  const inputStyle = {
    background: "var(--bg)", color: "var(--text)", border: "1px solid var(--line)",
    padding: "3px 6px", fontSize: "11px", fontFamily: "var(--ff-mono)", width: "100%",
  };

  const openRow = openId != null ? rows.find(r => r.id === openId) : null;
  const reqText  = openRow ? NL.requestRawById(openRow.id)  : "";
  const respText = openRow ? NL.responseRawById(openRow.id) : "";

  return (
    <div onClick={onClose}
         style={{
           position: "fixed", inset: 0, background: "rgba(0,0,0,0.55)",
           display: "grid", placeItems: "center", zIndex: 50,
         }}>
      <div onClick={(e) => e.stopPropagation()}
           style={{
             background: "var(--pane)", border: "1px solid var(--accent)",
             width: "min(94vw, 980px)", maxHeight: "88vh", overflow: "auto",
             display: "flex", flexDirection: "column",
             boxShadow: "0 0 0 1px var(--line), 0 12px 40px rgba(0,0,0,0.5)",
           }}>
        <div style={{
          display: "flex", alignItems: "center", gap: 8, padding: "8px 12px",
          borderBottom: "1px solid var(--line)",
          color: "var(--accent)", fontSize: "11px",
          textTransform: "uppercase", letterSpacing: "0.06em",
        }}>
          <span style={{ flex: 1 }}>⌕ DB SEARCH</span>
          <button onClick={onClose} style={dimBtn}>CLOSE</button>
        </div>
        <div style={{ padding: "10px 12px", color: "var(--dim)", fontSize: "11px", borderBottom: "1px solid var(--line-soft)" }}>
          Queries the SQLite-backed history index directly (/api/history/find), so it finds
          rows the bounded HTTP HISTORY window and its free-text search can no longer see,
          across every request captured this engagement. Host/Path accept SQL LIKE patterns
          (% = any run of characters).
        </div>
        <form onSubmit={runSearch} style={{ padding: "10px 12px", borderBottom: "1px solid var(--line-soft)", display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8 }}>
          <label style={{ display: "grid", gap: 2, fontSize: "10px", color: "var(--dim)" }}>METHOD
            <input style={inputStyle} placeholder="GET" value={f.method} onChange={setField("method")} />
          </label>
          <label style={{ display: "grid", gap: 2, fontSize: "10px", color: "var(--dim)" }}>HOST
            <input style={inputStyle} placeholder="%.example.com" value={f.host} onChange={setField("host")} />
          </label>
          <label style={{ display: "grid", gap: 2, fontSize: "10px", color: "var(--dim)" }}>PATH
            <input style={inputStyle} placeholder="/api/%" value={f.path} onChange={setField("path")} />
          </label>
          <label style={{ display: "grid", gap: 2, fontSize: "10px", color: "var(--dim)" }}>STATUS
            <input style={inputStyle} placeholder="200" value={f.status} onChange={setField("status")} />
          </label>
          <label style={{ display: "grid", gap: 2, fontSize: "10px", color: "var(--dim)" }}>MIN SIZE (bytes)
            <input style={inputStyle} value={f.minSize} onChange={setField("minSize")} />
          </label>
          <label style={{ display: "grid", gap: 2, fontSize: "10px", color: "var(--dim)" }}>MAX SIZE (bytes)
            <input style={inputStyle} value={f.maxSize} onChange={setField("maxSize")} />
          </label>
          <label style={{ display: "grid", gap: 2, fontSize: "10px", color: "var(--dim)" }}>SINCE (minutes ago)
            <input style={inputStyle} value={f.sinceMins} onChange={setField("sinceMins")} />
          </label>
          <label style={{ display: "grid", gap: 2, fontSize: "10px", color: "var(--dim)" }}>LIMIT (max 5000)
            <input style={inputStyle} value={f.limit} onChange={setField("limit")} />
          </label>
          <div style={{ gridColumn: "1 / -1", display: "flex", gap: 8 }}>
            <button type="submit" style={btn} disabled={busy}>{busy ? "SEARCHING…" : "SEARCH"}</button>
            <button type="button" style={dimBtn} onClick={() => { setF({ method: "", host: "", path: "", status: "", minSize: "", maxSize: "", sinceMins: "", limit: "200" }); setRows(null); setCount(0); setOpenId(null); }}>CLEAR</button>
          </div>
        </form>
        {error && <div style={{ padding: "6px 12px", color: "var(--err, #e05555)", fontSize: "11px" }}>{error}</div>}
        {rows != null && (
          <div style={{ padding: "8px 12px 4px", color: "var(--dim)", fontSize: "10px" }}>
            {rows.length} row{rows.length === 1 ? "" : "s"} returned{count > rows.length ? " (server reported " + count + ")" : ""}
          </div>
        )}
        {rows != null && (
          <div style={{ overflowX: "auto", padding: "0 12px" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontFamily: "var(--ff-mono)", fontSize: "11px" }}>
              <thead>
                <tr style={{ color: "var(--dim)", textAlign: "left" }}>
                  <th style={cellStyle}>#</th>
                  <th style={cellStyle}>method</th>
                  <th style={cellStyle}>status</th>
                  <th style={cellStyle}>host</th>
                  <th style={cellStyle}>path</th>
                  <th style={cellStyle}>size</th>
                  <th style={cellStyle}>mime</th>
                  <th style={cellStyle}>captured</th>
                </tr>
              </thead>
              <tbody>
                {rows.length === 0 && (
                  <tr><td colSpan={8} style={{ ...cellStyle, color: "var(--dim)" }}>— no matching rows —</td></tr>
                )}
                {rows.map(r => (
                  <tr key={r.id}
                      className={openId === r.id ? "sel" : ""}
                      style={{ cursor: "pointer" }}
                      onClick={() => { setOpenId(openId === r.id ? null : r.id); setView("text"); }}>
                    <td style={cellStyle}>{r.id.toString().padStart(3, "0")}</td>
                    <td style={cellStyle}><MethodCell m={r.method} /></td>
                    <td style={cellStyle}><span className={"status " + statusKind(r.status)}>{r.status || "—"}</span></td>
                    <td style={cellStyle}><span className={"tls-dot " + (r.tls ? "" : "off")} />{r.host}</td>
                    <td style={{ ...cellStyle, maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.path}</td>
                    <td style={cellStyle}>{fmtSize(r.size)}</td>
                    <td style={cellStyle}>{r.mime}</td>
                    <td style={cellStyle}>{new Date(Number(r.ts)).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {openRow && (
          <div style={{ padding: "10px 12px 12px", borderTop: "1px solid var(--line-soft)" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
              <span style={{ color: "var(--dim)", fontSize: "10px" }}>
                #{openRow.id.toString().padStart(3, "0")} — full captured request/response (fetched from the history index, works even if this row scrolled out of the live table)
              </span>
              <span style={{ flex: 1 }} />
              <button style={view === "text" ? btn : dimBtn} onClick={() => setView("text")}>TEXT</button>
              <button style={view === "hex" ? btn : dimBtn} onClick={() => setView("hex")}>HEX</button>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 }}>
              <div>
                <div style={{ color: "var(--dim)", fontSize: "10px", marginBottom: 2 }}>REQUEST</div>
                <textarea readOnly value={view === "hex" ? toHexDump(reqText) : reqText}
                          style={{ width: "100%", height: 220, resize: "vertical", background: "var(--bg)", color: "var(--text)", border: "1px solid var(--line)", fontFamily: "var(--ff-mono)", fontSize: "11px", padding: 6 }} />
              </div>
              <div>
                <div style={{ color: "var(--dim)", fontSize: "10px", marginBottom: 2 }}>RESPONSE</div>
                <textarea readOnly value={view === "hex" ? toHexDump(respText) : respText}
                          style={{ width: "100%", height: 220, resize: "vertical", background: "var(--bg)", color: "var(--text)", border: "1px solid var(--line)", fontFamily: "var(--ff-mono)", fontSize: "11px", padding: 6 }} />
              </div>
            </div>
          </div>
        )}
      </div>
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
  let path = row.url || "/";

  if (!raw) { out.fullUrl = proto + "://" + (row.host || "") + portStr + path; return out; }
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
  // Callers that only have host/port/tls (no captured `row.url`, e.g. an
  // Intercept-held message) fall back to the request line's own target so
  // the URL isn't just the host root.
  if (!row.url && fp.length >= 2 && fp[1]) path = fp[1];
  out.fullUrl = proto + "://" + (row.host || "") + portStr + path;
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
// Line-count cap mirroring the backend Comparer's kMaxTokens (compare.cpp) --
// an uncapped n*m Int32Array table on a large response would hang/OOM the tab.
const DIFF_MAX_LINES = 2000;

function diffLines(aText, bText) {
  let A = aText.split("\n");
  let B = bText.split("\n");
  let truncated = false;
  if (A.length > DIFF_MAX_LINES) { A = A.slice(0, DIFF_MAX_LINES); truncated = true; }
  if (B.length > DIFF_MAX_LINES) { B = B.slice(0, DIFF_MAX_LINES); truncated = true; }
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
  out.truncated = truncated;
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
  const reqA  = idA != null ? (NL.requestRawById(idA)  || "") : "";
  const reqB  = idB != null ? (NL.requestRawById(idB)  || "") : "";
  const respA = idA != null ? (NL.responseRawById(idA) || "") : "";
  const respB = idB != null ? (NL.responseRawById(idB) || "") : "";
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
          {rows.truncated &&
            <span title={"Diff clipped to the first " + DIFF_MAX_LINES + " lines per side"}
                  style={{
                    color: "var(--warn, #e0a030)", border: "1px solid var(--warn, #e0a030)",
                    padding: "1px 6px", fontSize: "10px", marginLeft: 8,
                    textTransform: "uppercase", letterSpacing: "0.04em",
                  }}>truncated</span>}
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
function CodecOverlay({ title, body, note, downloadName, onClose }) {
  React.useEffect(() => {
    const onKey = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  const copy = () => { try { navigator.clipboard?.writeText(body); } catch {} };
  const download = () => {
    try {
      const blob = new Blob([body], { type: "text/html" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = downloadName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch {}
  };
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
          {downloadName && (
            <button onClick={download} style={{
              background: "transparent", color: "var(--accent)",
              border: "1px solid var(--accent)", padding: "2px 8px",
              fontSize: "10px", fontFamily: "var(--ff-mono)", cursor: "pointer",
            }}>DOWNLOAD</button>
          )}
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
        {note && (
          <div style={{
            padding: "6px 12px", borderBottom: "1px solid var(--line-soft)",
            color: "var(--dim)", fontSize: "11px",
          }}>{note}</div>
        )}
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

// Re-indent an XML/HTML fragment with no DOM dependency (works identically
// in a browser and under plain Node for testing). Regex-based: split on
// adjacent tag boundaries, then walk lines tracking a nesting depth so
// closing tags dedent before they print and self-closing/void/inline
// open-close tags don't affect depth at all.
const VOID_TAGS = /^<(area|base|br|col|embed|hr|img|input|link|meta|param|source|track|wbr)\b[^>]*>$/i;
function prettyPrintMarkup(text) {
  const xml = String(text).replace(/></g, ">\n<").trim();
  if (!xml) return "";
  const lines = xml.split("\n");
  let depth = 0;
  const out = [];
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) continue;
    const isClosing = /^<\//.test(line);
    if (isClosing) depth = Math.max(0, depth - 1);
    out.push("  ".repeat(depth) + line);
    if (isClosing) continue;
    const selfClosing = /\/>$/.test(line) || /^<[?!]/.test(line);
    const openCloseSame = /^<([a-zA-Z][\w:-]*)\b[^>]*>.*<\/\1>$/.test(line);
    if (!selfClosing && !VOID_TAGS.test(line) && !openCloseSame && /^<[a-zA-Z]/.test(line)) {
      depth++;
    }
  }
  return out.join("\n");
}

// Split a raw HTTP message into {firstLine, headers, body} and render
// according to the selected view tab. 'raw' = original, 'headers' =
// status/request line + header block, 'body' = body only, 'preview' =
// pretty-print JSON/XML/HTML or just the body, 'hex' = canonical hex dump.
function renderView(raw, view) {
  if (!raw || view === "raw") return raw || "";
  const splitIdx = raw.indexOf("\n\n");
  const headers = splitIdx >= 0 ? raw.slice(0, splitIdx) : raw;
  const body    = splitIdx >= 0 ? raw.slice(splitIdx + 2) : "";

  if (view === "headers") return headers;
  if (view === "body")    return body || "(no body)";
  if (view === "preview") {
    // Try JSON pretty-print first, then XML/HTML re-indentation; fall back
    // to the body as-is.
    const t = (body || "").trim();
    if (t.startsWith("{") || t.startsWith("[")) {
      try { return JSON.stringify(JSON.parse(t), null, 2); } catch (e) {}
    }
    if (t.startsWith("<")) {
      try { return prettyPrintMarkup(t); } catch (e) {}
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

function ProxyTab({ state, dispatch, showSitemap, onSwitchTab }) {
  const { rows, selectedRowId, hostFilter, statusClass, methodFilter, search, selectedHost, selectedOrigin, scope } = state;
  // #495: grouped by full origin (scheme://host[:port]), not NL.sitemap's
  // bare-host entries -- see the SiteMap component's own comment for why.
  const sitemapEntries = React.useMemo(() => {
    const byOrigin = new Map();
    for (const r of rows) {
      const tls = !!r.tls;
      const port = r.port || (tls ? 443 : 80);
      const key = (tls ? "https" : "http") + "://" + r.host + ":" + port;
      let e = byOrigin.get(key);
      if (!e) {
        const hostPort = (port === 80 || port === 443) ? "" : ":" + port;
        e = { host: r.host, port, tls, origin: (tls ? "https" : "http") + "://" + r.host + hostPort, count: 0 };
        byOrigin.set(key, e);
      }
      e.count++;
    }
    return Array.from(byOrigin.values()).sort((a, b) => a.origin.localeCompare(b.origin));
  }, [rows]);
  // Rows scoped to the selected origin node -- exact host+port+tls match,
  // stricter than the host-substring hostFilter/selectedHost text filter.
  const originRows = selectedOrigin
    ? rows.filter(r => r.host === selectedOrigin.host
        && (r.port || (r.tls ? 443 : 80)) === selectedOrigin.port
        && !!r.tls === selectedOrigin.tls
        && (!selectedOrigin.branch
            || r.path.split("?")[0] === selectedOrigin.branch
            || r.path.split("?")[0].startsWith(selectedOrigin.branch + "/")))
    : rows;

  // #392: site-map / history filter chips (in-scope / parameterized / hide-404).
  const [paramsOnly, setParamsOnly] = React.useState(false);
  const [hideNotFound, setHideNotFound] = React.useState(false);
  const [inScopeOnly, setInScopeOnly] = React.useState(false);

  // #267/#371: MIME class, extension show/hide, and case-sensitivity, on top
  // of the existing free-text search (which now also supports a leading "-"
  // to negate, handled inside HistoryTable/parseSearchTerm).
  const [mimeFilter, setMimeFilter] = React.useState("all");
  const [extText, setExtText] = React.useState("");
  const [extHide, setExtHide] = React.useState(false);
  const [caseSensitive, setCaseSensitive] = React.useState(false);
  const extList = React.useMemo(() => parseExtList(extText), [extText]);

  // #398: right-click add/remove scope, on any site-map or history row.
  const [wsRepeaterOpen, setWsRepeaterOpen] = React.useState(false);
  const [h2LogOpen, setH2LogOpen] = React.useState(false);
  const [dbSearchOpen, setDbSearchOpen] = React.useState(false);
  const [analyzerOpen, setAnalyzerOpen] = React.useState(false);

  const [ctxMenu, setCtxMenu] = React.useState(null); // {x,y,host,rowId?,branch?} | null
  const openRowMenu = (host, e, rowId, branch) => setCtxMenu({ x: e.clientX, y: e.clientY, host, rowId, branch });
  const closeRowMenu = () => setCtxMenu(null);
  const hostIsInScope = ctxMenu ? (scope.in || []).includes(ctxMenu.host) : false;

  // #372: "Copy URLs" / "Copy links" from a site-map context menu -- scoped
  // to a single row (rowId set), a directory branch (branch set), or the
  // whole host (neither set), matching how "Delete branch"/"Save selected
  // items" would scope in Burp. Client-side only: derives URLs from the
  // HTTP history rows already in state, same source SiteMap's own tree uses.
  const ctxMenuTargetUrls = () => {
    if (!ctxMenu) return [];
    let target = rows.filter(r => r.host === ctxMenu.host);
    if (ctxMenu.branch) {
      target = target.filter(r => {
        const p = (r.path || "/").split("?")[0];
        return p === ctxMenu.branch || p.startsWith(ctxMenu.branch + "/");
      });
    }
    if (ctxMenu.rowId != null) target = target.filter(r => r.id === ctxMenu.rowId);
    const urls = target.map(r => {
      const proto = r.tls ? "https" : "http";
      const port = r.port || (r.tls ? 443 : 80);
      const portStr = (port === 80 || port === 443) ? "" : ":" + port;
      return proto + "://" + r.host + portStr + (r.path || "/");
    });
    return Array.from(new Set(urls));
  };
  const copyCtxMenuUrls = async (asLinks) => {
    const urls = ctxMenuTargetUrls();
    if (urls.length) {
      try {
        if (asLinks && navigator.clipboard && navigator.clipboard.write && typeof ClipboardItem !== "undefined") {
          const esc = s => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
          const html = urls.map(u => `<a href="${esc(u)}">${esc(u)}</a>`).join("<br>");
          await navigator.clipboard.write([new ClipboardItem({
            "text/html": new Blob([html], { type: "text/html" }),
            "text/plain": new Blob([urls.join("\n")], { type: "text/plain" }),
          })]);
        } else {
          await navigator.clipboard.writeText(urls.join("\n"));
        }
      } catch (e) { /* clipboard denied/unsupported -- silently no-op like the existing COPY AS copy() */ }
    }
    closeRowMenu();
  };

  // #299: highlight colour + comment per history row (client-side, localStorage-persisted).
  const [annotations, setAnnotations] = React.useState(loadAnnotations);
  const [annotatedOnly, setAnnotatedOnly] = React.useState(false);
  const setRowColor = (id, color) => setAnnotations(prev => {
    const cur = prev[id] || {};
    const next = { ...prev, [id]: { ...cur, color } };
    if (!next[id].color && !next[id].comment) delete next[id];
    saveAnnotations(next);
    return next;
  });
  const setRowComment = (id, comment) => setAnnotations(prev => {
    const cur = prev[id] || {};
    const next = { ...prev, [id]: { ...cur, comment } };
    if (!next[id].color && !next[id].comment) delete next[id];
    saveAnnotations(next);
    return next;
  });
  const clearRowAnnotation = (id) => setAnnotations(prev => {
    if (!(id in prev)) return prev;
    const next = { ...prev };
    delete next[id];
    saveAnnotations(next);
    return next;
  });
  const ctxRowNote = ctxMenu && ctxMenu.rowId != null ? annotations[ctxMenu.rowId] : null;

  // Deep search: when enabled, the search box query is also run against
  // request and response bodies via /api/search. We debounce by 250ms so
  // typing doesn't fire a scan on every keystroke. deepHits is a Set of
  // row ids -- if it's non-null and the row id isn't in it, the row hides.
  const [deepSearch, setDeepSearch] = React.useState(false);
  const [deepHits, setDeepHits]     = React.useState(null);  // null = no body filter
  const [deepCount, setDeepCount]   = React.useState(null);  // last hit count
  const [deepTruncated, setDeepTruncated] = React.useState(false); // scan incomplete
  const [deepMinId, setDeepMinId]   = React.useState(null);  // oldest id server scanned
  React.useEffect(() => {
    if (!deepSearch || !search) {
      setDeepHits(null); setDeepCount(null); setDeepTruncated(false); setDeepMinId(null);
      return;
    }
    let cancelled = false;
    const t = setTimeout(async () => {
      try {
        const res = await NL.actions.search(search, "both", 500);
        if (cancelled) return;
        const ids = new Set((res.hits || []).map(h => h.id));
        setDeepHits(ids);
        setDeepCount(res.count || 0);
        setDeepTruncated(!!res.truncated);
        // scannedMinId < 0 (or absent) means "nothing scanned" -> treat as no
        // lower bound so the filter falls back to the local-column match only.
        setDeepMinId(typeof res.scannedMinId === "number" && res.scannedMinId >= 0
                       ? res.scannedMinId : null);
      } catch (e) {
        if (!cancelled) {
          setDeepHits(new Set()); setDeepCount(0);
          setDeepTruncated(false); setDeepMinId(null);
        }
      }
    }, 250);
    return () => { cancelled = true; clearTimeout(t); };
  }, [deepSearch, search]);

  // visibleHost feeds the table filter as hostFilter, but when sitemap selects a host we want exact match
  const tableHostFilter = selectedHost || hostFilter;
  const selectedRow = rows.find(r => r.id === selectedRowId) || null;

  // count hidden -- mirrors HistoryTable's own filter predicate so the
  // "shown / total" header stays in sync with what the table actually renders.
  // originRows is already exact-scoped when a site-map origin node is
  // selected, so the substring hostFilter/selectedHost check is skipped then
  // (it would otherwise just re-match the same host, harmlessly, but drop
  // the port/tls precision originRows already applied).
  const shown = originRows.filter(r => {
    if (!selectedOrigin && tableHostFilter && !r.host.includes(tableHostFilter)) return false;
    if (statusClass !== "all" && (Math.floor(r.status / 100) + "xx") !== statusClass) return false;
    if (methodFilter !== "ALL" && r.method !== methodFilter) return false;
    if (search) {
      const { term, negate } = parseSearchTerm(search);
      const s = caseSensitive ? term : term.toLowerCase();
      const hay = caseSensitive ? r.url : r.url.toLowerCase();
      const hit = s ? hay.includes(s) : true;
      if (negate ? hit : !hit) return false;
    }
    if (paramsOnly && !(r.params > 0)) return false;
    if (hideNotFound && r.status === 404) return false;
    if (inScopeOnly && !hostInScope(r.host, scope)) return false;
    if (mimeFilter !== "all" && mimeCategory(r.mime) !== mimeFilter) return false;
    if (extList.length > 0 && !extFilterMatch(r.path, extList, extHide)) return false;
    if (annotatedOnly && !annotations[r.id]) return false;
    return true;
  }).length;
  const hidden = rows.length - shown;

  // minmax(0, 1fr), NOT 1fr: a bare 1fr track is minmax(auto, 1fr), whose `auto`
  // minimum grows to the pane's content -- a long URL in the history table then
  // pushed the pane (and the whole shell) wider than the viewport. minmax(0, 1fr)
  // lets the pane shrink to the available space so the table ellipsizes instead.
  const columns = showSitemap
    ? "minmax(220px, 280px) 1px minmax(0, 1fr)"
    : "minmax(0, 1fr)";

  return (
    <div className="tab-body" style={{ gridTemplateColumns: columns }}>
      {showSitemap && (
        <SiteMap
          entries={sitemapEntries}
          rows={rows}
          selectedOrigin={selectedOrigin}
          selectedRowId={selectedRowId}
          onSelect={(e, branch) => dispatch({ type: "set", payload: { selectedHost: e ? e.host : null, selectedOrigin: e ? { ...e, branch: branch || null } : null } })}
          onSelectLeaf={(e, id) => dispatch({ type: "set", payload: { selectedHost: e.host, selectedOrigin: e, selectedRowId: id } })}
          totalRows={rows.length}
          onRowContextMenu={openRowMenu}
          annotations={annotations}
          annotatedOnly={annotatedOnly}
        />
      )}
      {showSitemap && <div className="divider-v" />}
      <div className="pane" style={{ display: "grid", gridTemplateRows: "auto auto 1fr 1fr", minHeight: 0 }}>
        <div className="pane-head">
          <span className="ph-corner">▸</span>
          <span>HTTP HISTORY</span>
          <span className="ph-count">{shown} / {rows.length}</span>
          <button onClick={() => setWsRepeaterOpen(true)} title="Inject a frame into a live WebSocket tunnel">⇄ WS REPEATER</button>
          <button onClick={() => setH2LogOpen(true)} title="View HTTP/2 stream summary and raw frame log">⇅ H2 FRAME LOG</button>
          <button onClick={() => setDbSearchOpen(true)} title="Search the full SQLite-backed history index, beyond the on-screen window">⌕ DB SEARCH</button>
          <button onClick={() => setAnalyzerOpen(true)} title="Attack-surface sizing: static/dynamic URL counts, query-parameter names, and per-URL entry points for the current site-map scope">◆ ANALYZE TARGET</button>
        </div>
        {wsRepeaterOpen && <WsRepeaterOverlay onClose={() => setWsRepeaterOpen(false)} />}
        {h2LogOpen && <H2FrameLogOverlay onClose={() => setH2LogOpen(false)} />}
        {dbSearchOpen && <DbSearchOverlay onClose={() => setDbSearchOpen(false)} />}
        {analyzerOpen && (
          <TargetAnalyzerOverlay
            rows={originRows}
            scopeLabel={selectedOrigin ? (selectedOrigin.origin + (selectedOrigin.branch || "")) : "all hosts"}
            onClose={() => setAnalyzerOpen(false)}
          />
        )}
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
          onClearFilters={() => { setDeepSearch(false); setDeepHits(null); setDeepCount(null); setDeepTruncated(false); setDeepMinId(null); setMimeFilter("all"); setExtText(""); setExtHide(false); setCaseSensitive(false); dispatch({ type: "set", payload: {
            hostFilter: "", statusClass: "all", methodFilter: "ALL", search: "", selectedHost: null, selectedOrigin: null
          }}); }}
          selectedHost={selectedHost}
          onSelectHost={h => dispatch({ type: "set", payload: { selectedHost: h }})}
          deepSearch={deepSearch}
          setDeepSearch={setDeepSearch}
          deepCount={deepCount}
          deepTruncated={deepTruncated}
          paramsOnly={paramsOnly}
          setParamsOnly={setParamsOnly}
          hideNotFound={hideNotFound}
          setHideNotFound={setHideNotFound}
          inScopeOnly={inScopeOnly}
          setInScopeOnly={setInScopeOnly}
          mimeFilter={mimeFilter}
          setMimeFilter={setMimeFilter}
          extText={extText}
          setExtText={setExtText}
          extHide={extHide}
          setExtHide={setExtHide}
          caseSensitive={caseSensitive}
          setCaseSensitive={setCaseSensitive}
          annotatedOnly={annotatedOnly}
          setAnnotatedOnly={setAnnotatedOnly}
        />
        <div style={{ minHeight: 0, borderBottom: "1px solid var(--line)" }}>
          <HistoryTable
            rows={originRows}
            selectedId={selectedRowId}
            onSelect={r => dispatch({ type: "set", payload: { selectedRowId: r.id }})}
            hostFilter={selectedOrigin ? "" : tableHostFilter}
            statusClass={statusClass}
            methodFilter={methodFilter}
            search={search}
            deepHits={deepSearch ? deepHits : null}
            deepMinId={deepSearch ? deepMinId : null}
            paramsOnly={paramsOnly}
            hideNotFound={hideNotFound}
            inScopeOnly={inScopeOnly}
            scope={scope}
            mimeFilter={mimeFilter}
            extList={extList}
            extHide={extHide}
            caseSensitive={caseSensitive}
            onRowContextMenu={openRowMenu}
            annotations={annotations}
            annotatedOnly={annotatedOnly}
          />
        </div>
        <DetailPane
          row={selectedRow}
          onSendRepeater={() => dispatch({ type: "send-to-repeater", row: selectedRow })}
          onSendIntruder={() => dispatch({ type: "send-to-intruder", row: selectedRow })}
          onSendComparer={(kind, label, text) => {
            dispatch({ type: "comparer-add", label, text });
            if (onSwitchTab) onSwitchTab("comparer");
          }}
          onSendDecoder={(label, text) => {
            dispatch({ type: "send-to-decoder", label, text });
            if (onSwitchTab) onSwitchTab("decoder");
          }}
          onSendSequencer={(text) => {
            dispatch({ type: "sequencer-add-token", text });
            if (onSwitchTab) onSwitchTab("sequencer");
          }}
        />
      </div>
      {ctxMenu && (
        <React.Fragment>
          <div style={{ position: "fixed", inset: 0, zIndex: 999 }} onClick={closeRowMenu} onContextMenu={e => { e.preventDefault(); closeRowMenu(); }} />
          <div className="pane" style={{
            position: "fixed", left: ctxMenu.x, top: ctxMenu.y, zIndex: 1000,
            minWidth: 220, boxShadow: "0 4px 20px rgba(0,0,0,0.4)",
          }}>
            <div className="pane-head" style={{ background: "var(--pane)" }}>
              <span className="ph-corner">▸</span>
              <span title={ctxMenu.host} style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{ctxMenu.host}</span>
            </div>
            <div
              className="btn"
              style={{ display: "block", width: "100%", textAlign: "left", opacity: hostIsInScope ? 0.4 : 1, cursor: hostIsInScope ? "default" : "pointer" }}
              onClick={() => { if (!hostIsInScope) { dispatch({ type: "scope-add-in", value: ctxMenu.host }); } closeRowMenu(); }}
            >+ ADD TO SCOPE</div>
            <div
              className="btn"
              style={{ display: "block", width: "100%", textAlign: "left", opacity: hostIsInScope ? 1 : 0.4, cursor: hostIsInScope ? "pointer" : "default" }}
              onClick={() => {
                if (hostIsInScope) {
                  const idx = (scope.in || []).indexOf(ctxMenu.host);
                  if (idx !== -1) dispatch({ type: "scope-remove-in", index: idx });
                }
                closeRowMenu();
              }}
            >− REMOVE FROM SCOPE</div>
            <div style={{ borderTop: "1px solid var(--line)" }} />
            <div
              className="btn"
              style={{ display: "block", width: "100%", textAlign: "left" }}
              title={ctxMenu.rowId != null ? "Copy this URL" : (ctxMenu.branch ? "Copy every URL under this branch" : "Copy every URL under this host")}
              onClick={() => copyCtxMenuUrls(false)}
            >📋 COPY URLS</div>
            <div
              className="btn"
              style={{ display: "block", width: "100%", textAlign: "left" }}
              title="Copy as clickable HTML links (pastes into rich-text tools/tickets)"
              onClick={() => copyCtxMenuUrls(true)}
            >🔗 COPY LINKS</div>
            {ctxMenu.rowId != null && (
              <React.Fragment>
                <div style={{ borderTop: "1px solid var(--line)", padding: "6px 10px", fontSize: "var(--fz-xs)", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.08em" }}>
                  Highlight
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 6, padding: "0 10px 8px" }}>
                  {ANNOTATION_COLORS.map(c => (
                    <span
                      key={c.key}
                      title={c.key}
                      onClick={() => { setRowColor(ctxMenu.rowId, c.key); closeRowMenu(); }}
                      style={{
                        width: 16, height: 16, borderRadius: 3, cursor: "pointer",
                        background: c.hex,
                        outline: ctxRowNote && ctxRowNote.color === c.key ? "2px solid var(--text)" : "1px solid rgba(0,0,0,0.3)",
                      }}
                    />
                  ))}
                  <span
                    title="no highlight"
                    onClick={() => { setRowColor(ctxMenu.rowId, null); closeRowMenu(); }}
                    style={{
                      width: 16, height: 16, borderRadius: 3, cursor: "pointer",
                      background: "transparent", border: "1px dashed var(--dim)",
                    }}
                  >×</span>
                </div>
                <div
                  className="btn"
                  style={{ display: "block", width: "100%", textAlign: "left" }}
                  onClick={() => {
                    const cur = ctxRowNote && ctxRowNote.comment ? ctxRowNote.comment : "";
                    const next = window.prompt("Comment for this row:", cur);
                    if (next !== null) setRowComment(ctxMenu.rowId, next.trim());
                    closeRowMenu();
                  }}
                >{ctxRowNote && ctxRowNote.comment ? "✎ EDIT COMMENT" : "✎ ADD COMMENT"}</div>
                {ctxRowNote && (ctxRowNote.color || ctxRowNote.comment) && (
                  <div
                    className="btn"
                    style={{ display: "block", width: "100%", textAlign: "left" }}
                    onClick={() => { clearRowAnnotation(ctxMenu.rowId); closeRowMenu(); }}
                  >⊘ CLEAR ANNOTATION</div>
                )}
              </React.Fragment>
            )}
          </div>
        </React.Fragment>
      )}
    </div>
  );
}

Object.assign(window, { ProxyTab });
