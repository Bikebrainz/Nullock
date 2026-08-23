// Main app: state, dispatch, tab routing, Tweaks panel.

const TABS = [
  { id: "proxy",     label: "PROXY" },
  { id: "scope",     label: "SCOPE" },
  { id: "rules",     label: "RULES" },
  { id: "issues",    label: "ISSUES" },
  { id: "scans",     label: "SCANS" },
  { id: "recon",     label: "RECON" },
  { id: "payloads",  label: "PAYLOADS" },
  { id: "decoder",   label: "DECODER" },
  { id: "comparer",  label: "COMPARER" },
  { id: "inspector", label: "INSPECTOR" },
  { id: "probe",     label: "PROBE" },
  { id: "sequencer", label: "SEQUENCER" },
  { id: "tests",     label: "TESTS" },
  { id: "discover",  label: "DISCOVER" },
  { id: "labs",      label: "LABS" },
  { id: "collaborator", label: "COLLABORATOR" },
  { id: "reporting", label: "REPORTING" },
  { id: "processor", label: "PROCESSOR" },
  { id: "stats",     label: "STATS" },
  { id: "sessions",  label: "SESSIONS" },
  { id: "websockets", label: "WEBSOCKETS" },
  { id: "repeater",  label: "REPEATER" },
  { id: "intercept", label: "INTERCEPT" },
  { id: "intruder",  label: "INTRUDER" },
  { id: "settings",  label: "SETTINGS" },
];

// fire-and-forget side-effect helper; safe before NL.actions exists.
const act = (fn, ...args) => { if (window.NL && NL.actions && NL.actions[fn]) NL.actions[fn](...args); };

function reducer(state, action) {
  switch (action.type) {
    case "set":
      return { ...state, ...action.payload };
    case "switch-tab":
      return { ...state, tab: action.tab };

    // Snapshot poll arrived from real-data.js -- merge fresh server state
    // into the slices that aren't already a live React-owned local copy.
    case "nl-snapshot": {
      if (!window.NL) return state;
      return {
        ...state,
        rows: NL.rows || state.rows,
        scope: NL.scope || state.scope,
        intercepted: NL.intercepted || state.intercepted,
        intercept: NL.interceptEnabled !== undefined ? NL.interceptEnabled : state.intercept,
        interceptResponses: NL.interceptResponsesEnabled !== undefined ? NL.interceptResponsesEnabled : state.interceptResponses,
        interceptAutoContentLength: NL.interceptAutoContentLength !== undefined ? NL.interceptAutoContentLength : state.interceptAutoContentLength,
        repeater: NL.repeater ? { ...state.repeater, ...NL.repeater } : state.repeater,
        intruder: NL.intruder ? { ...state.intruder, ...NL.intruder } : state.intruder,
        proxyOn: NL.bootInfo && NL.bootInfo.proxyOn !== undefined ? NL.bootInfo.proxyOn : state.proxyOn,
        logOutOfScope: NL.bootInfo && NL.bootInfo.logOutOfScope !== undefined ? NL.bootInfo.logOutOfScope : state.logOutOfScope,
      };
    }

    case "send-to-repeater": {
      if (!action.row) return state;
      const row = action.row;
      const req = NL.requestRawById(row.id);
      // Spawn a *new* tab on the backend so we don't trample whatever the
      // user has open. The snapshot poll will fill in the populated tab
      // shortly; show the row's content optimistically in the meantime.
      act("repeaterTabAddFromHistory", row.id - 1);
      return {
        ...state,
        tab: "repeater",
        repeater: {
          ...state.repeater,
          host: row.host,
          port: row.tls ? 443 : 80,
          tls: row.tls,
          request: req,
          response: "",
          statusLine: "ready · loaded from #" + row.id.toString().padStart(3,"0"),
        },
      };
    }
    // Comparer: a client-only item list (no backend persistence, same as
    // Decoder). Items are added here from other tools' "Send to Comparer"
    // buttons or pasted/loaded directly in the Comparer tab; selA/selB pick
    // which two items the diff runs against.
    case "comparer-add": {
      const items = state.comparer.items;
      const nextId = items.length ? Math.max(...items.map(i => i.id)) + 1 : 1;
      const item = { id: nextId, label: action.label || ("item " + nextId), text: action.text || "" };
      return { ...state, comparer: { ...state.comparer, items: [...items, item] } };
    }
    case "comparer-remove": {
      const items = state.comparer.items.filter(i => i.id !== action.id);
      const selA = state.comparer.selA === action.id ? null : state.comparer.selA;
      const selB = state.comparer.selB === action.id ? null : state.comparer.selB;
      return { ...state, comparer: { items, selA, selB } };
    }
    case "comparer-clear":
      return { ...state, comparer: { items: [], selA: null, selB: null } };
    // Sequencer: append one captured token (#167 "Send to Sequencer" from
    // Proxy history / Repeater). Blank/whitespace-only selections are
    // dropped rather than polluting the corpus with empty samples.
    case "sequencer-add-token": {
      const text = (action.text || "").trim();
      if (!text) return state;
      return { ...state, sequencer: { tokens: [...state.sequencer.tokens, text] } };
    }
    case "sequencer-clear-tokens":
      return { ...state, sequencer: { tokens: [] } };
    case "comparer-select": {
      const key = action.slot === "B" ? "selB" : "selA";
      return { ...state, comparer: { ...state.comparer, [key]: action.id } };
    }

    // Decoder: a "Send to Decoder" action from Proxy/Repeater/Intercept
    // (#323). No backend round-trip -- the Decoder tab is client-only, so
    // this just hands the text off via a bumped seedNonce.
    case "send-to-decoder": {
      return {
        ...state,
        decoder: {
          seedText: action.text || "",
          seedLabel: action.label || "",
          seedNonce: (state.decoder.seedNonce || 0) + 1,
        },
      };
    }

    case "send-to-intruder": {
      if (!action.row) return state;
      const row = action.row;
      const req = NL.requestRawById(row.id);
      let tmpl = req;
      if (req.includes("=")) {
        tmpl = req.replace(/(=)([^&\s\n]*)$/m, "$1§payload§");
      }
      act("intruderSet", { host: row.host, port: row.tls ? 443 : 80, tls: row.tls, template: tmpl });
      return {
        ...state,
        tab: "intruder",
        intruder: {
          ...state.intruder,
          host: row.host,
          port: row.tls ? 443 : 80,
          tls: row.tls,
          template: tmpl,
        },
      };
    }

    case "repeater-set":
      act("repeaterSet", action.payload);
      return { ...state, repeater: { ...state.repeater, ...action.payload } };
    case "repeater-send":
      act("repeaterSend");
      return { ...state, repeater: { ...state.repeater, statusLine: "sending…" } };
    case "repeater-clear":
      act("repeaterClear");
      return { ...state, repeater: { ...state.repeater, request: "", response: "", statusLine: "—" } };

    case "intruder-set":
      act("intruderSet", action.payload);
      return { ...state, intruder: { ...state.intruder, ...action.payload } };
    case "intruder-clear":
      act("intruderClear");
      return { ...state, intruder: { ...state.intruder, running: false, results: state.intruder.payloads.map(() => ({ status: null, size: 0, ms: 0, err: "" })) } };
    case "intruder-start":
      // make sure the backend has the latest template + payloads before kick-off
      act("intruderSet", {
        host: state.intruder.host,
        port: state.intruder.port,
        tls: state.intruder.tls,
        template: state.intruder.template,
        payloads: state.intruder.payloads,
      });
      act("intruderStart");
      return { ...state, intruder: { ...state.intruder, running: true } };
    case "intruder-stop":
      act("intruderStop");
      return { ...state, intruder: { ...state.intruder, running: false } };
    case "intruder-tick":
      // No-op when bound to real data; results come from the snapshot poll.
      return state;

    case "intercept-toggle":
      act("toggleIntercept");
      return { ...state, intercept: !state.intercept };
    case "intercept-responses-toggle":
      act("toggleInterceptResponses");
      return { ...state, interceptResponses: !state.interceptResponses };
    case "intercept-autocl-toggle": {
      const next = !state.interceptAutoContentLength;
      act("interceptSetAutoContentLength", next);
      return { ...state, interceptAutoContentLength: next };
    }
    case "log-out-of-scope-toggle": {
      const next = !state.logOutOfScope;
      act("setLogOutOfScope", next);
      return { ...state, logOutOfScope: next };
    }
    case "intercept-forward": {
      const current = state.intercepted[0];
      act("interceptForward", current ? current.text : "");
      return { ...state, intercepted: state.intercepted.slice(1) };
    }
    case "intercept-forward-hold-response": {
      const current = state.intercepted[0];
      act("interceptForwardHoldResponse", current ? current.text : "");
      return { ...state, intercepted: state.intercepted.slice(1) };
    }
    case "intercept-drop":
      act("interceptDrop");
      return { ...state, intercepted: state.intercepted.slice(1) };
    case "intercept-forward-all":
      act("interceptForwardAll");
      return { ...state, intercepted: [] };

    // Intercept action menu: send the currently-held raw text straight into
    // another tool without waiting for it to land in proxy history first
    // (it may still be held, so there's no history row id to key off yet).
    case "send-to-repeater-raw": {
      const { host, port, tls, text } = action;
      act("repeaterTabAdd", "");
      act("repeaterSet", { host, port, tls, request: text });
      return {
        ...state,
        tab: "repeater",
        repeater: { ...state.repeater, host, port, tls, request: text, response: "", statusLine: "ready · sent from intercept" },
      };
    }
    case "send-to-intruder-raw": {
      const { host, port, tls, text } = action;
      let tmpl = text;
      if (text.includes("=")) {
        tmpl = text.replace(/(=)([^&\s\n]*)$/m, "$1§payload§");
      }
      act("intruderSet", { host, port, tls, template: tmpl });
      return {
        ...state,
        tab: "intruder",
        intruder: { ...state.intruder, host, port, tls, template: tmpl },
      };
    }

    case "scope-add-in":
      if (state.scope.in.includes(action.value)) return state;
      act("scopeAddIn", action.value);
      return { ...state, scope: { ...state.scope, in: [...state.scope.in, action.value] } };
    case "scope-remove-in": {
      const glob = state.scope.in[action.index];
      act("scopeRemoveIn", glob);
      return { ...state, scope: { ...state.scope, in: state.scope.in.filter((_, i) => i !== action.index) } };
    }
    case "scope-add-out":
      if (state.scope.out.includes(action.value)) return state;
      act("scopeAddOut", action.value);
      return { ...state, scope: { ...state.scope, out: [...state.scope.out, action.value] } };
    case "scope-remove-out": {
      const glob = state.scope.out[action.index];
      act("scopeRemoveOut", glob);
      return { ...state, scope: { ...state.scope, out: state.scope.out.filter((_, i) => i !== action.index) } };
    }
    case "scope-set-notes":
      act("scopeSetNotes", action.value);
      return { ...state, scope: { ...state.scope, notes: action.value } };

    case "clear-history":
      act("clearHistory");
      return { ...state, rows: [], selectedRowId: null };
    case "toggle-power":
      act("toggleProxy");
      return { ...state, proxyOn: !state.proxyOn };

    default:
      return state;
  }
}

const TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
  "theme": "cyber",
  "density": "default",
  "showSitemap": true,
  "fontFamily": "JetBrains Mono",
  "accent": "default",
  "scanlines": true,
  "bootSplash": true
}/*EDITMODE-END*/;

const FONT_STACKS = {
  "JetBrains Mono": '"JetBrains Mono", "IBM Plex Mono", ui-monospace, monospace',
  "IBM Plex Mono":  '"IBM Plex Mono", "JetBrains Mono", ui-monospace, monospace',
  "Fira Code":      '"Fira Code", "JetBrains Mono", ui-monospace, monospace',
  "Geist Mono":     '"Geist Mono", "JetBrains Mono", ui-monospace, monospace',
};

const ACCENT_PRESETS = {
  default:   null,
  mint:      "oklch(0.84 0.17 165)",
  cyan:      "oklch(0.85 0.15 215)",
  magenta:   "oklch(0.74 0.20 320)",
  amber:     "oklch(0.83 0.18 75)",
  red:       "oklch(0.74 0.20 25)",
};

// Settings tab: diagnostics + housekeeping panel that pulls everything
// out of NL.bootInfo and surfaces the housekeeping actions in one place.
// Extension marketplace.
//
// This is the one surface in the app that can cause the proxy to execute code it
// did not ship with, so the interaction is built around ONE idea: the user
// should know what they are agreeing to before it lands, not after.
//
// Two things are deliberate here and should not be "simplified" later:
//
//   1. Install is TWO STEPS for anything that can rewrite traffic. The first
//      call is sent with confirmMutating:false. The server refuses and replies
//      needsConfirmation:true along with the permissions it read out of the
//      DOWNLOADED script -- not out of the catalog, which is untrusted text from
//      the network. Only then do we show the confirm panel and re-send. Passing
//      confirmMutating:true up front would delete the entire consent gate while
//      leaving all the code that looks like one.
//
//   2. Nothing here auto-installs, auto-updates, or fetches on mount. The
//      catalog is only pulled when the user asks. An "update available" badge is
//      information, never an action taken on their behalf.
function Marketplace({ Card, Btn }) {
  const [state, setState] = React.useState({ status: "idle", items: [], error: "" });
  const [busy, setBusy]   = React.useState("");     // id currently installing
  const [confirm, setConfirm] = React.useState(null); // { id, name, permissions, warnings }
  const [note, setNote]   = React.useState("");
  const [query, setQuery] = React.useState("");
  const [category, setCategory] = React.useState("all");
  const [detailId, setDetailId] = React.useState(null);

  const load = React.useCallback(async () => {
    setState(s => ({ ...s, status: "loading", error: "" }));
    try {
      const r = await NL.actions.marketplaceCatalog();
      if (!r.ok) {
        setState({ status: "error", items: [], error: r.error || "catalog fetch failed" });
        return;
      }
      setState({ status: "ready", items: r.extensions || [], error: "",
                 updated: r.updated, trustedHosts: r.trustedHosts || [] });
    } catch (e) {
      setState({ status: "error", items: [], error: String(e) });
    }
  }, []);

  const doInstall = React.useCallback(async (id, confirmed) => {
    setBusy(id); setNote("");
    try {
      const r = await NL.actions.marketplaceInstall(id, confirmed);
      if (!r.ok && r.needsConfirmation) {
        // Not an error -- the server is asking. Show what it actually found in
        // the bytes it downloaded and verified.
        const item = state.items.find(x => x.id === id) || {};
        setConfirm({ id, name: item.name || id,
                     permissions: r.permissions || [], warnings: r.warnings || [] });
        return;
      }
      setConfirm(null);
      setNote(r.ok ? ("installed " + id + " (sha256 " + String(r.sha256).slice(0, 12) + "…)")
                   : ("install failed: " + (r.error || "unknown error")));
      if (r.ok) load();
    } catch (e) {
      setNote("install failed: " + String(e));
    } finally { setBusy(""); }
  }, [state.items, load]);

  const doUninstall = React.useCallback(async (id) => {
    setBusy(id); setNote("");
    try {
      const r = await NL.actions.marketplaceUninstall(id);
      setNote(r.ok ? ("removed " + id) : ("remove failed: " + (r.error || "")));
      if (r.ok) load();
    } finally { setBusy(""); }
  }, [load]);

  const badge = (text, color) => (
    <span style={{
      fontSize: "9.5px", textTransform: "uppercase", letterSpacing: "0.06em",
      border: "1px solid " + color, color, padding: "1px 5px", borderRadius: 2,
      fontFamily: "var(--ff-mono)", whiteSpace: "nowrap",
    }}>{text}</span>
  );

  const stateBadge = (s) => {
    if (s === "installed")        return badge("installed", "var(--ok, #4ea36b)");
    if (s === "update-available") return badge("update", "var(--warn, #d0a03a)");
    if (s === "local")            return badge("local", "var(--dim)");
    return null;
  };

  // Categories present in the live catalog, "all" first -- mirrors the
  // published marketplace site's chip filter (docs/marketplace/index.html).
  const categories = React.useMemo(() => {
    const s = [];
    state.items.forEach(x => (x.categories || []).forEach(c => { if (s.indexOf(c) < 0) s.push(c); }));
    s.sort();
    return ["all", ...s];
  }, [state.items]);

  const visibleItems = React.useMemo(() => {
    const q = query.trim().toLowerCase();
    return state.items.filter(x => {
      if (category !== "all" && (x.categories || []).indexOf(category) < 0) return false;
      if (!q) return true;
      const hay = (x.name + " " + x.summary + " " + x.author + " " + (x.categories || []).join(" ")).toLowerCase();
      return hay.indexOf(q) >= 0;
    });
  }, [state.items, query, category]);

  const detail = detailId ? state.items.find(x => x.id === detailId) : null;

  return (
    <Card
      title={"Marketplace" + (state.items.length ? " (" + state.items.length + ")" : "")}
      action={<Btn label={state.status === "loading" ? "Loading…" : "Fetch catalog"}
                   onClick={load} />}
    >
      {state.status === "idle" && (
        <div style={{ fontSize: "11.5px", color: "var(--dim)" }}>
          Browse and install Nullock extensions. Nothing is fetched until you ask.
        </div>
      )}

      {state.status === "error" && (
        <div style={{ fontSize: "11.5px", color: "var(--err)", fontFamily: "var(--ff-mono)" }}>
          {state.error}
        </div>
      )}

      {note && (
        <div style={{ fontSize: "11px", color: "var(--dim)", fontFamily: "var(--ff-mono)" }}>
          {note}
        </div>
      )}

      {/* The consent panel. Everything shown here was read out of the verified
          bytes on disk-to-be, so it is what will actually take effect. */}
      {confirm && (
        <div style={{
          border: "1px solid var(--warn, #d0a03a)", padding: "10px 12px",
          borderRadius: 3, display: "flex", flexDirection: "column", gap: 6,
        }}>
          <div style={{ fontSize: "11px", color: "var(--warn, #d0a03a)",
                        textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600 }}>
            {confirm.name} wants to modify your traffic
          </div>
          <div style={{ fontSize: "11.5px", color: "var(--text-2)" }}>
            This extension runs inside the proxy and can rewrite requests and
            responses as they pass through — including headers that carry your
            session cookies and tokens.
          </div>
          <div style={{ fontSize: "11px", fontFamily: "var(--ff-mono)", color: "var(--text)" }}>
            Requests: {confirm.permissions.join(", ") || "(none)"}
          </div>
          {confirm.warnings.map((w, i) => (
            <div key={i} style={{ fontSize: "11px", color: "var(--warn, #d0a03a)" }}>• {w}</div>
          ))}
          <div style={{ display: "flex", gap: 8, marginTop: 2 }}>
            <Btn label="Install anyway" onClick={() => doInstall(confirm.id, true)} />
            <Btn label="Cancel" onClick={() => setConfirm(null)} danger />
          </div>
        </div>
      )}

      {/* The detail panel -- everything here comes straight off the merged
          catalog entry already in state; nothing new is fetched. */}
      {detail && (
        <div style={{
          border: "1px solid var(--accent)", padding: "10px 12px",
          borderRadius: 3, display: "flex", flexDirection: "column", gap: 6,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontSize: "12.5px", color: "var(--text)", fontWeight: 600, flex: 1 }}>
              {detail.name} <span style={{ color: "var(--dim)", fontWeight: 400 }}>v{detail.version}</span>
            </span>
            <Btn label="Close" onClick={() => setDetailId(null)} />
          </div>
          <div style={{ fontSize: "11px", color: "var(--dim)", fontFamily: "var(--ff-mono)" }}>
            by {detail.author || "unknown"}
          </div>
          <div style={{ fontSize: "11.5px", color: "var(--text-2)" }}>{detail.summary}</div>
          <div style={{ fontSize: "10.5px", color: "var(--dim)", fontFamily: "var(--ff-mono)" }}>
            {(detail.categories || []).join(" · ")}
          </div>
          <div style={{ fontSize: "11px", fontFamily: "var(--ff-mono)", color: "var(--text)" }}>
            Permissions: {(detail.permissions || []).join(", ") || "(none — observe-only)"}
          </div>
          {detail.minVersion && (
            <div style={{ fontSize: "11px", fontFamily: "var(--ff-mono)",
                          color: detail.compatible === false ? "var(--err)" : "var(--dim)" }}>
              Requires Nullock ≥ {detail.minVersion}
              {detail.compatible === false ? " — " + (detail.incompatReason || "incompatible with this build") : ""}
            </div>
          )}
          <div style={{ fontSize: "10.5px", color: "var(--dim)", fontFamily: "var(--ff-mono)", wordBreak: "break-all" }}>
            sha256 {detail.sha256}
          </div>
          <div style={{ display: "flex", gap: 8, marginTop: 2, flexWrap: "wrap" }}>
            <a href={"https://bikebrainz.github.io/Nullock/marketplace/e/" + encodeURIComponent(detail.id) + ".html"}
               target="_blank" rel="noopener noreferrer"
               style={{ fontSize: "11px", color: "var(--accent)", fontFamily: "var(--ff-mono)",
                        textTransform: "uppercase", letterSpacing: "0.05em" }}>
              Full description &amp; source ↗
            </a>
            <a href={"https://raw.githubusercontent.com/Bikebrainz/Nullock/Nullock/extensions/" + encodeURIComponent(detail.id) + ".js"}
               target="_blank" rel="noopener noreferrer"
               style={{ fontSize: "11px", color: "var(--accent)", fontFamily: "var(--ff-mono)",
                        textTransform: "uppercase", letterSpacing: "0.05em" }}>
              View raw source ↗
            </a>
            <a href={"https://github.com/Bikebrainz/Nullock/issues/new?title=" +
                     encodeURIComponent("extension: " + detail.id + " — ")}
               target="_blank" rel="noopener noreferrer"
               style={{ fontSize: "11px", color: "var(--dim)", fontFamily: "var(--ff-mono)",
                        textTransform: "uppercase", letterSpacing: "0.05em" }}>
              Report a bug ↗
            </a>
          </div>
        </div>
      )}

      {state.items.length > 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <input
            placeholder="filter by name, summary, author, category…"
            value={query}
            onChange={e => setQuery(e.target.value)}
            style={{
              background: "var(--bg-deep)", color: "var(--text)",
              border: "1px solid var(--line)", padding: "4px 8px",
              fontSize: "11.5px", fontFamily: "var(--ff-mono)",
            }} />
          <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
            {categories.map(c => (
              <span key={c}
                    onClick={() => setCategory(c)}
                    style={{
                      fontSize: "10px", padding: "2px 7px", borderRadius: 10,
                      border: "1px solid " + (category === c ? "var(--accent)" : "var(--line)"),
                      color: category === c ? "var(--accent)" : "var(--dim)",
                      fontFamily: "var(--ff-mono)", cursor: "pointer",
                      textTransform: "uppercase", letterSpacing: "0.04em",
                    }}>{c}</span>
            ))}
          </div>
          <div style={{ fontSize: "10px", color: "var(--dim)", fontFamily: "var(--ff-mono)" }}>
            {visibleItems.length === state.items.length
              ? visibleItems.length + " extensions"
              : visibleItems.length + " of " + state.items.length + " extensions"}
          </div>
        </div>
      )}

      {state.items.length > 0 && visibleItems.length === 0 && (
        <div style={{ fontSize: "11.5px", color: "var(--dim)" }}>
          No extensions match this filter.
        </div>
      )}

      {visibleItems.map(x => (
        <div key={x.id} style={{
          borderTop: "1px solid var(--line-soft)", paddingTop: 8, marginTop: 2,
          display: "flex", flexDirection: "column", gap: 4,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontSize: "12px", color: "var(--text)", fontWeight: 600 }}>
              {x.name}
            </span>
            <span style={{ fontSize: "10.5px", color: "var(--dim)", fontFamily: "var(--ff-mono)" }}>
              {x.version}
              {x.state === "update-available" && x.installedVersion
                ? " (have " + x.installedVersion + ")" : ""}
            </span>
            {stateBadge(x.state)}
            {x.compatible === false && (
              <span title={x.incompatReason || "incompatible with this build"}>
                {badge("incompatible", "var(--err)")}
              </span>
            )}
            {(x.permissions || []).length > 0 && badge("modifies traffic", "var(--warn, #d0a03a)")}
            <span style={{ flex: 1 }} />
            <Btn label="Details" onClick={() => setDetailId(detailId === x.id ? null : x.id)} />
            {x.state === "not-installed" && (
              <Btn label={busy === x.id ? "…" : "Install"} onClick={() => doInstall(x.id, false)}
                   disabled={x.compatible === false} title={x.compatible === false ? x.incompatReason : undefined} />
            )}
            {x.state === "update-available" && (
              <Btn label={busy === x.id ? "…" : "Update"} onClick={() => doInstall(x.id, false)}
                   disabled={x.compatible === false} title={x.compatible === false ? x.incompatReason : undefined} />
            )}
            {(x.state === "installed" || x.state === "update-available" || x.state === "local") && (
              <Btn label="Remove" onClick={() => doUninstall(x.id)} danger />
            )}
          </div>
          <div style={{ fontSize: "11.5px", color: "var(--text-2)" }}>{x.summary}</div>
          <div style={{ fontSize: "10.5px", color: "var(--dim)", fontFamily: "var(--ff-mono)" }}>
            {(x.categories || []).join(" · ")}
            {x.sha256 ? "  sha256 " + String(x.sha256).slice(0, 16) + "…" : ""}
          </div>
        </div>
      ))}

      {state.status === "ready" && (
        <div style={{ fontSize: "10.5px", color: "var(--dim)", marginTop: 4 }}>
          Downloads are restricted to https on {(state.trustedHosts || []).join(", ")} and
          every file is checked against the sha256 the catalog pins before it is written.
        </div>
      )}
    </Card>
  );
}

function SettingsTab() {
  const [, force] = React.useReducer(x => x + 1, 0);
  React.useEffect(() => {
    const onUpdate = () => force();
    window.addEventListener("nl-update", onUpdate);
    return () => window.removeEventListener("nl-update", onUpdate);
  }, []);

  // Project switcher state (lives here so hooks ordering is stable).
  const [projects, setProjects]   = React.useState([]);
  const [newProject, setNewProject] = React.useState("");
  const refreshProjects = React.useCallback(async () => {
    try {
      const r = await NL.actions.projectList();
      setProjects(r.projects || []);
    } catch {}
  }, []);
  React.useEffect(() => { refreshProjects(); }, [refreshProjects]);

  // Project templates (Burp: New project from template) -- prefills scope
  // + notes on a freshly-created project from templates/projects/*.json.
  const [templates, setTemplates]   = React.useState([]);
  const [templateId, setTemplateId] = React.useState("");

  // Export HAR defaults to redacting auth material (Authorization/Cookie/
  // etc) server-side; this lets a user opt into a full, unredacted export
  // when handing a HAR to a colleague who needs to reproduce the bug.
  const [harUnredacted, setHarUnredacted] = React.useState(false);

  // Reload themes from disk -- picks up user-added/edited JSON theme files
  // in the themes dir without an app restart.
  const [themesReloaded, setThemesReloaded] = React.useState(false);
  const reloadThemes = async () => {
    try {
      await NL.actions.reloadThemes();
      setThemesReloaded(true);
      setTimeout(() => setThemesReloaded(false), 1500);
    } catch {}
  };

  const refreshTemplates = React.useCallback(async () => {
    try {
      const r = await NL.actions.projectTemplates();
      setTemplates(r.templates || []);
    } catch {}
  }, []);
  React.useEffect(() => { refreshTemplates(); }, [refreshTemplates]);
  const createFromTemplate = async () => {
    const n = newProject.trim();
    if (!n) { alert("Enter a project name above first."); return; }
    if (!templateId) return;
    const r = await NL.actions.projectCreateFromTemplate(templateId, n);
    if (r && r.ok === false) {
      alert("Could not create from template: " + (r.error || "unknown error"));
      return;
    }
    setNewProject(""); setTemplateId("");
    await refreshProjects();
  };

  const b = (window.NL && NL.bootInfo) || {};
  const scope = (window.NL && NL.scope) || { in: [], out: [], notes: "" };
  const rowCount = (window.NL && NL.rows) ? NL.rows.length : 0;
  const blocked = b.mitmBlocked || [];
  const acceptInvalidHosts0 = b.acceptInvalidUpstreamHosts || [];
  const acceptedInvalidCerts = b.acceptedInvalidCerts || [];
  const extLog = b.extensionsLog || [];
  // Every .js present (loaded OR disabled) with its persisted enabled state --
  // control_server.cpp bootInfo.extensionAll -- so the Installed list can
  // render Burp's per-extension Loaded checkbox without losing disabled scripts.
  const extAll = b.extensionAll || [];
  const [extAllList, setExtAllList] = React.useState(extAll);
  React.useEffect(() => { setExtAllList(extAll); }, [JSON.stringify(extAll)]);
  const toggleExtensionEnabled = async (name, next) => {
    setExtAllList(list => list.map(e => e.name === name ? { ...e, enabled: next } : e));
    try {
      const r = await NL.actions.setExtensionEnabled(name, next);
      if (r && typeof r.enabled === "boolean")
        setExtAllList(list => list.map(e => e.name === name ? { ...e, enabled: r.enabled } : e));
    } catch {
      // revert on failure -- server state didn't change
      setExtAllList(list => list.map(e => e.name === name ? { ...e, enabled: !next } : e));
    }
  };

  const [mitmBlockedList, setMitmBlockedList] = React.useState(blocked);
  React.useEffect(() => { setMitmBlockedList(blocked); }, [blocked.join(",")]);
  const [newBypassHost, setNewBypassHost] = React.useState("");
  const addBypassHost = async () => {
    const h = newBypassHost.trim();
    if (!h) return;
    const r = await NL.actions.markMitmBlocked(h);
    if (r && Array.isArray(r.blocked)) setMitmBlockedList(r.blocked);
    setNewBypassHost("");
  };
  const removeBypassHost = async (h) => {
    const r = await NL.actions.unblockMitmHost(h);
    if (r && Array.isArray(r.blocked)) setMitmBlockedList(r.blocked);
  };

  const [acceptInvalidList, setAcceptInvalidList] = React.useState(acceptInvalidHosts0);
  React.useEffect(() => { setAcceptInvalidList(acceptInvalidHosts0); }, [acceptInvalidHosts0.join(",")]);
  const [newAcceptInvalidHost, setNewAcceptInvalidHost] = React.useState("");
  const addAcceptInvalidHost = async () => {
    const h = newAcceptInvalidHost.trim();
    if (!h) return;
    const r = await NL.actions.acceptInvalidHostAdd(h);
    if (r && Array.isArray(r.acceptInvalidUpstreamHosts)) setAcceptInvalidList(r.acceptInvalidUpstreamHosts);
    setNewAcceptInvalidHost("");
  };
  const removeAcceptInvalidHost = async (h) => {
    const r = await NL.actions.acceptInvalidHostRemove(h);
    if (r && Array.isArray(r.acceptInvalidUpstreamHosts)) setAcceptInvalidList(r.acceptInvalidUpstreamHosts);
  };

  const [installBusy, setInstallBusy] = React.useState(false);
  const [installMsg, setInstallMsg]   = React.useState("");
  const doInstallBuiltins = async () => {
    setInstallBusy(true); setInstallMsg("");
    try {
      const r = await NL.actions.installBuiltinExtensions();
      setInstallMsg(r && r.ok ? ("installed " + r.installed + " to " + r.destDir) : ("failed: " + ((r && r.error) || "unknown error")));
    } catch (e) {
      setInstallMsg("failed: " + String(e && e.message ? e.message : e));
    } finally {
      setInstallBusy(false);
    }
  };

  const copy = (text) => { try { navigator.clipboard?.writeText(text); } catch {} };

  const Card = ({ title, children, action }) => (
    <div style={{
      background: "var(--pane)", border: "1px solid var(--line)",
      padding: "12px 14px", borderRadius: 4, display: "flex",
      flexDirection: "column", gap: 6,
    }}>
      <div style={{
        display: "flex", justifyContent: "space-between", alignItems: "center",
        fontSize: "11px", color: "var(--accent)", textTransform: "uppercase",
        letterSpacing: "0.06em", fontWeight: 600,
      }}>
        <span>{title}</span>
        {action}
      </div>
      {children}
    </div>
  );

  const Row = ({ label, value, copyable, hint }) => (
    <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: "12px" }}>
      <span style={{ minWidth: 110, color: "var(--dim)" }}>{label}</span>
      <span style={{ flex: 1, fontFamily: "var(--ff-mono)", color: "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {value || (hint ? <span style={{ color: "var(--dim)" }}>{hint}</span> : "—")}
      </span>
      {copyable && value && (
        <button
          onClick={() => copy(value)}
          style={{
            background: "transparent", color: "var(--dim)", fontSize: "10px",
            border: "1px solid var(--line)", padding: "2px 6px", cursor: "pointer",
            fontFamily: "var(--ff-mono)",
          }}
        >COPY</button>
      )}
    </div>
  );

  const Btn = ({ label, onClick, danger, disabled, title }) => (
    <button
      onClick={onClick}
      disabled={disabled}
      title={title}
      style={{
        background: "transparent",
        color: disabled ? "var(--dim)" : danger ? "var(--err)" : "var(--accent)",
        border: "1px solid " + (disabled ? "var(--line)" : danger ? "var(--err)" : "var(--accent)"),
        padding: "4px 10px", fontSize: "11px",
        fontFamily: "var(--ff-mono)", cursor: disabled ? "not-allowed" : "pointer",
        letterSpacing: "0.05em", textTransform: "uppercase",
      }}
    >{label}</button>
  );

  return (
    <div style={{
      padding: 14, overflow: "auto", height: "100%",
      display: "grid",
      gridTemplateColumns: "repeat(auto-fit, minmax(380px, 1fr))",
      gap: 12, alignContent: "start",
    }}>
      <Card title="Proxy">
        <Row label="Status" value={b.proxyOn ? "LISTENING" : "STOPPED"} />
        <Row label="Bind" value={"127.0.0.1:" + (b.port || "—")} copyable />
        <Row label="Control UI" value={"127.0.0.1:" + (b.controlPort || "—")} copyable />
        <Row label="HTTP/2 hops" value={String(b.h2UpstreamCount || 0)} />
        <Row label="Filtered" value={String(b.filteredCount || 0)} />
        <Row label="Captured" value={String(rowCount)} />
        <div style={{ display: "flex", alignItems: "flex-start", gap: 8, fontSize: "12px" }}>
          <span style={{ minWidth: 110, color: "var(--dim)" }}>MITM bypass</span>
          <div style={{ flex: 1, display: "flex", flexWrap: "wrap", gap: 4 }}>
            {mitmBlockedList.length ? mitmBlockedList.map((h) => (
              <span key={h} style={{
                display: "inline-flex", alignItems: "center", gap: 4,
                border: "1px solid var(--line)", borderRadius: 3,
                padding: "1px 4px 1px 6px", fontFamily: "var(--ff-mono)", color: "var(--text)",
              }}>
                {h}
                <button
                  onClick={() => removeBypassHost(h)}
                  title={"Remove " + h + " from the pass-through list"}
                  style={{
                    background: "transparent", color: "var(--dim)", border: "none",
                    cursor: "pointer", fontFamily: "var(--ff-mono)", fontSize: "11px", padding: 0,
                  }}
                >×</button>
              </span>
            )) : <span style={{ color: "var(--dim)" }}>empty</span>}
          </div>
        </div>
        <div style={{ display: "flex", gap: 6, marginTop: 4 }}>
          <input
            value={newBypassHost}
            onChange={(e) => setNewBypassHost(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") addBypassHost(); }}
            placeholder="host to pre-add (blind-tunnel from first CONNECT)"
            style={{
              flex: 1, background: "var(--bg)", color: "var(--text)",
              border: "1px solid var(--line)", padding: "4px 6px", fontSize: "11px",
              fontFamily: "var(--ff-mono)",
            }}
          />
          <Btn label="Add" onClick={addBypassHost} disabled={!newBypassHost.trim()} />
        </div>
        <div style={{ display: "flex", gap: 6, marginTop: 4 }}>
          <Btn label={b.proxyOn ? "Stop proxy" : "Start proxy"} onClick={() => NL.actions.toggleProxy()} />
          <Btn label="Clear blocklist" onClick={() => NL.actions.clearMitmBlocked()} />
        </div>
      </Card>

      <Card title="CA & TLS">
        <Row label="OpenSSL" value={b.hasOpenssl ? "found" : "missing"} />
        <Row label="CA cert" value={b.caPath} copyable />
        <Row label="CA dir"  value={b.caDir} copyable />
        <Row label="Download" value={"http://127.0.0.1:" + (b.controlPort || 17777) + "/ca.pem"} copyable />
        <div style={{ display: "flex", gap: 6, marginTop: 4, flexWrap: "wrap" }}>
          <Btn label="Download .crt" onClick={() => {
            const url = "/ca.crt";
            const a = document.createElement("a");
            a.href = url; a.download = "nullock-ca.crt";
            document.body.appendChild(a); a.click(); a.remove();
          }} />
          <Btn label="Open CA folder" onClick={() => {
              // `Qt` is undeclared in a plain browser; a bare `Qt && ...` throws
              // ReferenceError (only `typeof` short-circuits safely).
              const u = "file:///" + (b.caDir || "");
              if (typeof Qt !== "undefined" && Qt.openUrlExternally) Qt.openUrlExternally(u);
              else window.open(u, "_blank");
          }} />
          <Btn label="Copy CA path" onClick={() => copy(b.caPath || "")} />
        </div>
        <div style={{ fontSize: "10.5px", color: "var(--dim)", marginTop: 4 }}>
          Install the CA in your browser's trust store so HTTPS MITM works without warnings.
          The download URL only works from this machine right now; for a phone, copy the .crt to it via AirDrop / USB / email.
        </div>

        <div style={{ display: "flex", alignItems: "flex-start", gap: 8, fontSize: "12px", marginTop: 8 }}>
          <span style={{ minWidth: 110, color: "var(--dim)" }}>Accept invalid</span>
          <div style={{ flex: 1, display: "flex", flexWrap: "wrap", gap: 4 }}>
            {acceptInvalidList.length ? acceptInvalidList.map((h) => (
              <span key={h} style={{
                display: "inline-flex", alignItems: "center", gap: 4,
                border: "1px solid var(--line)", borderRadius: 3,
                padding: "1px 4px 1px 6px", fontFamily: "var(--ff-mono)", color: "var(--text)",
              }}>
                {h}
                <button
                  onClick={() => removeAcceptInvalidHost(h)}
                  title={"Stop waiving invalid-cert errors for " + h}
                  style={{
                    background: "transparent", color: "var(--dim)", border: "none",
                    cursor: "pointer", fontFamily: "var(--ff-mono)", fontSize: "11px", padding: 0,
                  }}
                >×</button>
              </span>
            )) : <span style={{ color: "var(--dim)" }}>empty</span>}
          </div>
        </div>
        <div style={{ display: "flex", gap: 6, marginTop: 4 }}>
          <input
            value={newAcceptInvalidHost}
            onChange={(e) => setNewAcceptInvalidHost(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") addAcceptInvalidHost(); }}
            placeholder="host:port to MITM despite a self-signed/expired cert"
            style={{
              flex: 1, background: "var(--bg)", color: "var(--text)",
              border: "1px solid var(--line)", padding: "4px 6px", fontSize: "11px",
              fontFamily: "var(--ff-mono)",
            }}
          />
          <Btn label="Add" onClick={addAcceptInvalidHost} disabled={!newAcceptInvalidHost.trim()} />
        </div>
        <div style={{ fontSize: "10.5px", color: "var(--dim)", marginTop: 2 }}>
          Listed hosts keep interception working against lab/self-signed targets instead of
          permanently blocking the connection on a TLS handshake failure. Verification stays
          relaxed only for these hosts.
        </div>
        {acceptedInvalidCerts.length > 0 && (
          <div style={{ fontSize: "10.5px", fontFamily: "var(--ff-mono)", color: "var(--dim)", marginTop: 4, display: "grid", gap: 2 }}>
            <div style={{ color: "var(--text-2)" }}>Waived certs (exactly what was accepted):</div>
            {acceptedInvalidCerts.map((c, i) => (
              <div key={c.host + i} style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                <span style={{ color: "var(--text)" }}>{c.host}</span>
                <span>sha256 {String(c.sha256 || "").slice(0, 16)}…</span>
                <span>{c.ignoredErrors}</span>
                <span>{c.acceptedAt}</span>
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card title="Projects" action={<Btn label="Refresh" onClick={refreshProjects} />}>
        <div style={{ fontSize: "10.5px", color: "var(--dim)", marginBottom: 4 }}>
          Each project keeps its own scope, rules, and history.ndjson.
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 2, maxHeight: 200, overflow: "auto" }}>
          {projects.length === 0 && (
            <span style={{ color: "var(--dim)", fontSize: "11px" }}>(none yet)</span>
          )}
          {projects.map(name => {
            const isActive = name === b.project;
            return (
              <div key={name}
                   onClick={async () => {
                     if (isActive) return;
                     await NL.actions.projectOpen(name);
                     await refreshProjects();
                   }}
                   style={{
                     display: "flex", alignItems: "center", gap: 8,
                     padding: "4px 6px",
                     background: isActive ? "var(--bg-deep)" : "transparent",
                     color:      isActive ? "var(--accent)" : "var(--text)",
                     border: "1px solid " + (isActive ? "var(--accent)" : "var(--line-soft)"),
                     cursor: isActive ? "default" : "pointer",
                     fontFamily: "var(--ff-mono)", fontSize: "12px",
                   }}>
                <span style={{
                  width: 8, height: 8, borderRadius: 4,
                  background: isActive ? "var(--accent)" : "transparent",
                  border: "1px solid var(--accent)",
                }} />
                <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis" }}>{name}</span>
                {isActive && (
                  <span style={{ color: "var(--dim)", fontSize: "10px",
                                 textTransform: "uppercase", letterSpacing: "0.06em" }}>
                    active
                  </span>
                )}
              </div>
            );
          })}
        </div>
        <div style={{ display: "flex", gap: 6, marginTop: 6 }}>
          <input
            placeholder="new project name…"
            value={newProject}
            onChange={e => setNewProject(e.target.value)}
            onKeyDown={async (e) => {
              if (e.key !== "Enter") return;
              const n = newProject.trim();
              if (!n) return;
              const r = await NL.actions.projectCreate(n);
              if (r && r.ok === false) {
                alert("Could not create project (name may contain invalid chars).");
                return;
              }
              setNewProject("");
              await refreshProjects();
            }}
            style={{
              flex: 1, background: "var(--bg-deep)", color: "var(--text)",
              border: "1px solid var(--line)", padding: "4px 6px",
              fontSize: "12px", fontFamily: "var(--ff-mono)",
            }} />
          <Btn label="Create" onClick={async () => {
            const n = newProject.trim();
            if (!n) return;
            const r = await NL.actions.projectCreate(n);
            if (r && r.ok === false) {
              alert("Could not create project (name may contain invalid chars).");
              return;
            }
            setNewProject("");
            await refreshProjects();
          }} />
        </div>
        {templates.length > 0 && (
          <div style={{ display: "flex", gap: 6, marginTop: 6, alignItems: "center", flexWrap: "wrap" }}>
            <select value={templateId} onChange={e => setTemplateId(e.target.value)}
              style={{
                background: "var(--bg-deep)", color: "var(--text)",
                border: "1px solid var(--line)", padding: "4px 6px",
                fontSize: "12px", fontFamily: "var(--ff-mono)", minWidth: 180,
              }}>
              <option value="">-- or start from a template --</option>
              {templates.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
            </select>
            <Btn label="Create from template" disabled={!templateId} onClick={createFromTemplate} />
          </div>
        )}
        {templateId && (() => {
          const t = templates.find(x => x.id === templateId);
          return t && t.description ? (
            <div style={{ fontSize: "10.5px", color: "var(--dim)" }}>{t.description}</div>
          ) : null;
        })()}
      </Card>

      <Card title="Project">
        <Row label="Name" value={b.project} hint="default" />
        <Row label="Path" value={b.projectDir} copyable />
        <Row label="Scope (in)"  value={String((scope.in || []).length) + " globs"} />
        <Row label="Scope (out)" value={String((scope.out || []).length) + " globs"} />
        <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: "12px" }}>
          <span style={{ minWidth: 110, color: "var(--dim)" }}>Themes dir</span>
          <span style={{ flex: 1, fontFamily: "var(--ff-mono)", color: "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {(b.themesDir || (window.NL ? NL.themesDir : "")) || "—"}
          </span>
          <button
            onClick={() => copy(b.themesDir || (window.NL ? NL.themesDir : ""))}
            style={{
              background: "transparent", color: "var(--dim)", fontSize: "10px",
              border: "1px solid var(--line)", padding: "2px 6px", cursor: "pointer",
              fontFamily: "var(--ff-mono)",
            }}
          >COPY</button>
          <button
            onClick={reloadThemes}
            title="Rescan the themes dir for new/edited JSON theme files"
            style={{
              background: "transparent", color: themesReloaded ? "var(--accent)" : "var(--dim)",
              fontSize: "10px", border: "1px solid var(--line)", padding: "2px 6px",
              cursor: "pointer", fontFamily: "var(--ff-mono)",
            }}
          >{themesReloaded ? "✓ RELOADED" : "RELOAD"}</button>
        </div>
        <Row label="Notes" value={scope.notes ? scope.notes.split('\n')[0].slice(0, 60) : ""} hint="edit in Scope tab" />
        <div style={{ display: "flex", gap: 6, marginTop: 4, flexWrap: "wrap" }}>
          <Btn label="Export HAR" onClick={() => NL.actions.exportHar(harUnredacted ? { redact: false } : {})} />
          <label style={{
            display: "inline-flex", alignItems: "center", gap: 4,
            fontSize: "10.5px", color: "var(--dim)", cursor: "pointer",
          }}>
            <input type="checkbox" checked={harUnredacted}
              onChange={e => setHarUnredacted(e.target.checked)} />
            include unredacted auth material
          </label>
          <Btn label="Export Postman" onClick={() => {
            const a = document.createElement("a");
            a.href = "/api/export/postman";
            a.download = "nullock-collection.postman.json";
            document.body.appendChild(a); a.click(); a.remove();
          }} />
          <label style={{
            display: "inline-flex", alignItems: "center", gap: 4,
            background: "transparent", color: "var(--accent)",
            border: "1px solid var(--accent)", padding: "4px 10px",
            fontSize: "11px", fontFamily: "var(--ff-mono)", cursor: "pointer",
            letterSpacing: "0.05em", textTransform: "uppercase",
          }}>
            Import HAR
            <input
              type="file"
              accept=".har,application/json"
              style={{ display: "none" }}
              onChange={async (e) => {
                const f = e.target.files && e.target.files[0];
                if (!f) return;
                try {
                  const text = await f.text();
                  const har = JSON.parse(text);
                  const res = await NL.actions.importHar(har);
                  alert("Imported " + (res && res.imported >= 0 ? res.imported : 0)
                      + " entries from " + f.name);
                } catch (err) {
                  alert("HAR import failed: " + err);
                }
                e.target.value = "";
              }}
            />
          </label>
          <Btn label="Clear history" onClick={() => NL.actions.clearHistory()} danger />
        </div>
      </Card>

      <Marketplace Card={Card} Btn={Btn} />

      <Card
        title={"Extensions (" + extAllList.length + ")"}
        action={
          <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
            {installMsg && <span style={{ color: "var(--dim)", fontSize: "10.5px", textTransform: "none", letterSpacing: 0, fontWeight: 400 }}>{installMsg}</span>}
            <Btn label="Install bundled" onClick={doInstallBuiltins} disabled={installBusy}
                 title="Copy the extensions shipped with Nullock (extensions/*.js) into your extensions folder" />
            <Btn label="Reload" onClick={() => NL.actions.reloadExtensions()} />
          </div>
        }
      >
        <Row label="Folder" value={b.extensionsDir} copyable />
        {extAllList.length === 0 && <Row label="Loaded" value="" hint="none yet" />}
        {extAllList.length > 0 && (
          <div style={{ display: "flex", flexDirection: "column", gap: 3, marginTop: 2 }}>
            {extAllList.map(e => {
              const s = e.name;
              // What the DOWNLOADED/loaded script itself declared, not what the
              // catalog claims -- mirrors the marketplace confirm-panel's trust
              // model (bootInfo.extensionGrants, control_server.cpp:1240-1244).
              // A disabled script is never (re-)parsed, so it carries no grants --
              // show a plain "disabled" badge instead of a stale/absent trust one.
              const grants = (b.extensionGrants && b.extensionGrants[s]) || [];
              const mutates = grants.indexOf("modify-requests") >= 0 || grants.indexOf("modify-responses") >= 0;
              return (
                <div key={s} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: "11px" }}>
                  <input
                    type="checkbox"
                    checked={!!e.enabled}
                    onChange={() => toggleExtensionEnabled(s, !e.enabled)}
                    title={e.enabled ? "Loaded -- click to disable" : "Disabled -- click to load"}
                    style={{ cursor: "pointer", flexShrink: 0 }}
                  />
                  <span style={{ fontFamily: "var(--ff-mono)", color: e.enabled ? "var(--text)" : "var(--dim)", flex: 1,
                                 overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s}</span>
                  {e.enabled ? (
                    <span style={{
                      fontSize: "9.5px", textTransform: "uppercase", letterSpacing: "0.06em",
                      border: "1px solid " + (mutates ? "var(--warn, #d0a03a)" : "var(--dim)"),
                      color: mutates ? "var(--warn, #d0a03a)" : "var(--dim)",
                      padding: "1px 5px", borderRadius: 2, fontFamily: "var(--ff-mono)", whiteSpace: "nowrap",
                    }} title={grants.length ? grants.join(", ") : "no declared capabilities"}>
                      {mutates ? "modifies traffic" : "observe-only"}
                    </span>
                  ) : (
                    <span style={{
                      fontSize: "9.5px", textTransform: "uppercase", letterSpacing: "0.06em",
                      border: "1px solid var(--line)", color: "var(--dim)",
                      padding: "1px 5px", borderRadius: 2, fontFamily: "var(--ff-mono)", whiteSpace: "nowrap",
                    }}>disabled</span>
                  )}
                </div>
              );
            })}
          </div>
        )}
        <div style={{
          marginTop: 6, padding: 8, background: "var(--bg-deep)",
          border: "1px solid var(--line-soft)", borderRadius: 3,
          fontFamily: "var(--ff-mono)", fontSize: "10.5px",
          maxHeight: 160, overflow: "auto",
        }}>
          {extLog.length === 0
            ? <span style={{ color: "var(--dim)" }}>(extension log is empty)</span>
            : extLog.slice(-30).map((line, i) => (
                <div key={i} style={{ color: line.includes("[ext]") ? "var(--text-2)" : "var(--dim)" }}>
                  {line}
                </div>
              ))
          }
        </div>
      </Card>

      {(() => {
        // Browser setup card. The proxy may be bound on a different port
        // than the default 8080 if it was taken; pull the live value out
        // of bootInfo so the snippets always match reality.
        const host       = "127.0.0.1";
        const proxyPort  = b.port || 8888;
        const ctrlPort   = b.controlPort || 17777;
        const proxyAddr  = host + ":" + proxyPort;
        const pacUrl     = "http://" + host + ":" + ctrlPort + "/api/pac";
        const curlCmd    = "curl -x http://" + proxyAddr + " --cacert \""
                         + (b.caPath || "<ca-cert-path>") + "\" https://example.com";
        const psCmd      = "$env:HTTPS_PROXY = \"http://" + proxyAddr + "\"; "
                         + "$env:HTTP_PROXY = \"http://" + proxyAddr + "\"";
        const ffSetting  = "network.proxy.autoconfig_url = " + pacUrl;
        return (
          <Card title="Browser setup">
            <Row label="HTTP proxy" value={proxyAddr} copyable />
            <Row label="PAC URL"    value={pacUrl}    copyable />
            <div style={{ height: 4 }} />
            <div style={{ fontSize: "10.5px", color: "var(--dim)" }}>Quick snippets</div>
            <Row label="curl" value={curlCmd} copyable />
            <Row label="PowerShell" value={psCmd} copyable />
            <Row label="Firefox about:config" value={ffSetting} copyable />
            <div style={{
              marginTop: 6, padding: 8, background: "var(--bg-deep)",
              border: "1px solid var(--line-soft)", borderRadius: 3,
              fontSize: "10.5px", color: "var(--dim)", lineHeight: 1.5,
            }}>
              <div><b style={{ color: "var(--text-2)" }}>Chrome / Edge:</b> Settings &rarr; System &rarr; Open your computer's proxy settings &rarr; paste the PAC URL into "Automatic proxy setup". Or launch with <code style={{ color: "var(--text)" }}>--proxy-server={proxyAddr}</code>.</div>
              <div style={{ marginTop: 4 }}><b style={{ color: "var(--text-2)" }}>Firefox:</b> Settings &rarr; Network Settings &rarr; "Automatic proxy configuration URL" &rarr; paste PAC URL.</div>
              <div style={{ marginTop: 4 }}><b style={{ color: "var(--text-2)" }}>Don't forget:</b> import the CA cert (see "CA &amp; TLS" card) so HTTPS interception works without warnings.</div>
            </div>
            <div style={{ display: "flex", gap: 6, marginTop: 4, flexWrap: "wrap" }}>
              <Btn label="Open PAC" onClick={() => window.open(pacUrl, "_blank")} />
              <Btn label="Copy PAC URL" onClick={() => copy(pacUrl)} />
              <Btn label="Copy proxy" onClick={() => copy(proxyAddr)} />
            </div>
          </Card>
        );
      })()}
    </div>
  );
}

// Section enum mirrors Nullock::Proxy::MatchReplaceRule::Section.
const SECTION_LABEL = [
  "Request URL",      // 0 = ReqUrl
  "Request header",   // 1 = ReqHeader
  "Request body",     // 2 = ReqBody
  "Response header",  // 3 = RespHeader
  "Response body",    // 4 = RespBody
  "Response status",  // 5 = RespStatus
];

// Match & replace tab: list/add/edit/toggle rules that mutate requests
// or responses on the fly. Each rule has a section (URL / headers / body
// / status), an optional host glob, a regex find and a replace string.
// Disabled rules stay in the list but are skipped at runtime.
function RulesTab() {
  const [, force] = React.useReducer(x => x + 1, 0);
  React.useEffect(() => {
    const onUpdate = () => force();
    window.addEventListener("nl-update", onUpdate);
    return () => window.removeEventListener("nl-update", onUpdate);
  }, []);

  const rules    = (window.NL && NL.rules) ? NL.rules : [];
  const rulesHit = (window.NL && NL.rulesHit) || 0;
  const [draft, setDraft] = React.useState({
    enabled: true, name: "", hostGlob: "", section: 1,
    find: "", replace: "", caseInsensitive: true, comment: "",
  });
  const [editingIndex, setEditingIndex] = React.useState(-1);

  const setDraftK = (k, v) => setDraft(d => ({ ...d, [k]: v }));

  const reset = () => {
    setDraft({
      enabled: true, name: "", hostGlob: "", section: 1,
      find: "", replace: "", caseInsensitive: true, comment: "",
    });
    setEditingIndex(-1);
  };

  const submit = async () => {
    if (!draft.find) return;
    if (editingIndex >= 0) await NL.actions.ruleUpdate(editingIndex, draft);
    else                   await NL.actions.ruleAdd(draft);
    reset();
  };

  const startEdit = (i) => {
    setDraft({ ...rules[i] });
    setEditingIndex(i);
  };

  const Btn = ({ label, onClick, danger, primary, disabled, title }) => (
    <button
      onClick={onClick}
      disabled={disabled}
      title={title}
      style={{
        background: primary ? "var(--accent)" : "transparent",
        color: disabled ? "var(--dim)"
             : primary ? "var(--bg)"
             : danger ? "var(--err)"
             : "var(--accent)",
        border: "1px solid " + (disabled ? "var(--line)"
                              : danger ? "var(--err)"
                              : "var(--accent)"),
        padding: "4px 10px", fontSize: "11px",
        fontFamily: "var(--ff-mono)", cursor: disabled ? "not-allowed" : "pointer",
        letterSpacing: "0.05em", textTransform: "uppercase",
      }}
    >{label}</button>
  );

  const inputStyle = {
    background: "var(--bg-deep)", color: "var(--text)",
    border: "1px solid var(--line)", padding: "4px 6px",
    fontSize: "12px", fontFamily: "var(--ff-mono)",
  };

  return (
    <div style={{ padding: 14, overflow: "auto", height: "100%",
                  display: "flex", flexDirection: "column", gap: 12 }}>
      {/* HEADER */}
      <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}>
        <span style={{
          fontSize: "11px", color: "var(--accent)", textTransform: "uppercase",
          letterSpacing: "0.06em", fontWeight: 600,
        }}>Match &amp; Replace</span>
        <span style={{ color: "var(--dim)", fontSize: "11px" }}>
          {rules.length} rule{rules.length === 1 ? "" : "s"} · {rulesHit} substitution{rulesHit === 1 ? "" : "s"} since boot
        </span>
      </div>

      {/* RULE EDITOR */}
      <div style={{
        background: "var(--pane)", border: "1px solid var(--line)",
        padding: 12, borderRadius: 4, display: "grid",
        gridTemplateColumns: "120px 1fr 120px 1fr", gap: 8,
        alignItems: "center",
      }}>
        <label style={{ fontSize: "11px", color: "var(--dim)" }}>Name</label>
        <input style={inputStyle} value={draft.name}
               placeholder="csrf strip"
               onChange={e => setDraftK("name", e.target.value)} />
        <label style={{ fontSize: "11px", color: "var(--dim)" }}>Host glob</label>
        <input style={inputStyle} value={draft.hostGlob}
               placeholder="*.example.com (blank = all)"
               onChange={e => setDraftK("hostGlob", e.target.value)} />

        <label style={{ fontSize: "11px", color: "var(--dim)" }}>Section</label>
        <select style={inputStyle} value={draft.section}
                onChange={e => setDraftK("section", parseInt(e.target.value, 10))}>
          {SECTION_LABEL.map((l, i) => <option key={i} value={i}>{l}</option>)}
        </select>
        <label style={{ fontSize: "11px", color: "var(--dim)" }}>Flags</label>
        <label style={{ fontSize: "11px", color: "var(--text)", display: "flex", gap: 6, alignItems: "center" }}>
          <input type="checkbox" checked={draft.caseInsensitive}
                 onChange={e => setDraftK("caseInsensitive", e.target.checked)} />
          case-insensitive
          <span style={{ width: 18 }} />
          <input type="checkbox" checked={draft.enabled}
                 onChange={e => setDraftK("enabled", e.target.checked)} />
          enabled
        </label>

        <label style={{ fontSize: "11px", color: "var(--dim)" }}>Find (regex)</label>
        <input style={inputStyle} value={draft.find}
               placeholder='X-CSRF-Token: .*'
               onChange={e => setDraftK("find", e.target.value)} />
        <label style={{ fontSize: "11px", color: "var(--dim)" }}>Replace</label>
        <input style={inputStyle} value={draft.replace}
               placeholder='X-CSRF-Token: AAAA'
               onChange={e => setDraftK("replace", e.target.value)} />

        <label style={{ fontSize: "11px", color: "var(--dim)" }}>Comment</label>
        <input style={{ ...inputStyle, gridColumn: "2 / span 3" }}
               value={draft.comment}
               placeholder="why this rule exists (optional)"
               onChange={e => setDraftK("comment", e.target.value)} />

        <div style={{ gridColumn: "1 / span 4", display: "flex", gap: 6, marginTop: 4 }}>
          <Btn label={editingIndex >= 0 ? "Update rule" : "Add rule"}
               primary onClick={submit} disabled={!draft.find} />
          {editingIndex >= 0 && <Btn label="Cancel" onClick={reset} />}
          <span style={{ flex: 1 }} />
          <span style={{ color: "var(--dim)", fontSize: "11px" }}>
            Regex uses Qt's PCRE-flavored engine. Use \1, \2 for backreferences.
          </span>
        </div>
      </div>

      {/* RULE LIST */}
      <div style={{
        background: "var(--pane)", border: "1px solid var(--line)",
        borderRadius: 4, flex: 1, minHeight: 0, display: "flex", flexDirection: "column",
      }}>
        <div style={{
          display: "grid",
          gridTemplateColumns: "40px 40px 120px 110px 130px 1fr 1fr 190px",
          gap: 6, padding: "6px 10px", borderBottom: "1px solid var(--line)",
          fontSize: "10px", color: "var(--dim)", textTransform: "uppercase",
          letterSpacing: "0.06em",
        }}>
          <span>#</span><span>on</span><span>Name</span><span>Host</span>
          <span>Section</span><span>Find</span><span>Replace</span><span></span>
        </div>
        <div style={{ overflow: "auto", flex: 1 }}>
          {rules.length === 0 && (
            <div style={{ padding: 24, textAlign: "center", color: "var(--dim)", fontSize: "12px" }}>
              No rules yet. Add one above &mdash; for example,<br/>
              Find: <code>User-Agent: .*</code> Replace: <code>User-Agent: Nullock/1.0</code>
            </div>
          )}
          {rules.map((r, i) => (
            <div key={i} style={{
              display: "grid",
              gridTemplateColumns: "40px 40px 120px 110px 130px 1fr 1fr 190px",
              gap: 6, padding: "6px 10px", alignItems: "center",
              fontSize: "12px", fontFamily: "var(--ff-mono)",
              borderBottom: "1px solid var(--line-soft)",
              opacity: r.enabled ? 1 : 0.45,
              background: i === editingIndex ? "var(--accent-faint, rgba(255,255,255,0.04))" : "transparent",
            }}>
              <span style={{ color: "var(--dim)" }}>{i + 1}</span>
              <input type="checkbox" checked={r.enabled}
                     onChange={() => NL.actions.ruleToggle(i)} />
              <span style={{ color: "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {r.name || <span style={{ color: "var(--dim)" }}>(unnamed)</span>}
              </span>
              <span style={{ color: "var(--text-2)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {r.hostGlob || <span style={{ color: "var(--dim)" }}>*</span>}
              </span>
              <span style={{ color: "var(--accent)" }}>{SECTION_LABEL[r.section] || "?"}</span>
              <span style={{ color: "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                    title={r.find}>{r.find}</span>
              <span style={{ color: "var(--text-2)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                    title={r.replace}>{r.replace}</span>
              <span style={{ display: "flex", gap: 4, justifyContent: "flex-end" }}>
                <Btn label="▲" title="Move up" disabled={i === 0}
                     onClick={() => NL.actions.ruleMove(i, i - 1)} />
                <Btn label="▼" title="Move down" disabled={i === rules.length - 1}
                     onClick={() => NL.actions.ruleMove(i, i + 1)} />
                <Btn label="Edit" onClick={() => startEdit(i)} />
                <Btn label="Del"  onClick={() => { if (confirm("Delete rule \"" + (r.name || "(unnamed)") + "\"?")) NL.actions.ruleRemove(i); }} danger />
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// Passive scanner findings list. Each row is a single issue -- click to
// jump to the originating request in the Proxy tab. Group counts at the
// top, filter chips below, scrolling list.
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEVERITY_COLOR = {
  critical: "var(--err, #f88)",
  high:   "#ea580c",
  medium: "#d97706",
  low:    "#3f8f29",
  info:   "var(--dim)",
};

// Splits `text` into {s,hit} segments around every literal occurrence of
// `evidence`, so the issue-detail request/response view can highlight the
// exact bytes the passive scanner flagged instead of leaving the reader to
// hunt for them in a raw dump.
function highlightEvidence(text, evidence) {
  if (!text) return [];
  if (!evidence) return [{ s: text, hit: false }];
  if (text.indexOf(evidence) === -1) return [{ s: text, hit: false }];
  const segments = [];
  let cursor = 0, idx;
  while ((idx = text.indexOf(evidence, cursor)) !== -1) {
    if (idx > cursor) segments.push({ s: text.slice(cursor, idx), hit: false });
    segments.push({ s: text.slice(idx, idx + evidence.length), hit: true });
    cursor = idx + evidence.length;
  }
  if (cursor < text.length) segments.push({ s: text.slice(cursor), hit: false });
  return segments;
}

// Advisory / Request / Response body of a finding's inline detail pane.
// Advisory renders the enrichment fields FindingEnricher already attaches
// to every finding (cwe/owasp/cvss/compliance/fixSummary); Request/Response
// pull the same raw history bytes proxy.jsx's DetailPane uses, with the
// finding's evidence string highlighted inline where it appears.
function IssueDetailBody({ finding, tab }) {
  if (tab === "advisory") {
    const rows = [
      ["CWE", finding.cwe || "—"],
      ["OWASP", finding.owasp || "—"],
      ["CVSS", finding.cvssScore
        ? finding.cvssScore.toFixed(1) + (finding.cvssVector ? "  (" + finding.cvssVector + ")" : "")
        : "—"],
      ["Confidence", finding.confidence || "—"],
      ["Compliance", (finding.compliance && finding.compliance.length) ? finding.compliance.join(", ") : "—"],
    ];
    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        <div style={{ color: "var(--text)" }}>{finding.summary}</div>
        {rows.map(([k, v]) => (
          <div key={k} style={{ display: "grid", gridTemplateColumns: "90px 1fr", gap: 8 }}>
            <span style={{ color: "var(--dim)", textTransform: "uppercase", fontSize: "10px" }}>{k}</span>
            <span style={{ color: "var(--text-2)" }}>{v}</span>
          </div>
        ))}
        {finding.fixSummary && (
          <div>
            <div style={{ color: "var(--dim)", textTransform: "uppercase", fontSize: "10px", marginBottom: 2 }}>Fix</div>
            <div style={{ color: "var(--text)" }}>{finding.fixSummary}</div>
          </div>
        )}
        {finding.evidence && (
          <div>
            <div style={{ color: "var(--dim)", textTransform: "uppercase", fontSize: "10px", marginBottom: 2 }}>Evidence</div>
            <div style={{ color: "var(--text-2)", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{finding.evidence}</div>
          </div>
        )}
      </div>
    );
  }

  if (!finding.rowId) {
    return (
      <div style={{ color: "var(--dim)", fontStyle: "italic" }}>
        no associated request — this finding has no underlying HTTP transaction (extension-sourced)
      </div>
    );
  }

  const raw = tab === "request" ? NL.requestRawById(finding.rowId) : NL.responseRawById(finding.rowId);
  if (!raw) {
    return <div style={{ color: "var(--dim)", fontStyle: "italic" }}>no {tab} captured for row #{finding.rowId}</div>;
  }
  const segments = highlightEvidence(raw, finding.evidence);
  return (
    <pre style={{
      margin: 0, maxHeight: 260, overflow: "auto", whiteSpace: "pre-wrap",
      wordBreak: "break-all", color: "var(--text-2)", fontFamily: "var(--ff-mono)",
    }}>
      {segments.map((seg, i) => seg.hit
        ? <mark key={i} style={{ background: "var(--accent)", color: "var(--bg)" }}>{seg.s}</mark>
        : <React.Fragment key={i}>{seg.s}</React.Fragment>)}
    </pre>
  );
}

// AI-triage verdicts (/api/triage/finding) are client-only and, until now,
// lived solely in IssuesTab's React state -- switching to another tab
// unmounts it, silently discarding every verdict. Persist to localStorage
// (matching the WebSockets-comment / labs-completed pattern) keyed by the
// same finding identity the backend already uses for its own per-finding
// flags (FindingTriageLogic::findingKey: kind+U+001F+host+U+001F+url+U+001F+summary),
// not the ephemeral f.id, so a verdict survives a tab switch and a reload.
const TRIAGE_CACHE_KEY = "nl-triage-cache";
function findingIdentityKey(f) {
  return [f.kind, f.host, f.url, f.summary].map(x => x || "").join("");
}
function loadTriageCache() {
  try { return JSON.parse(localStorage.getItem(TRIAGE_CACHE_KEY) || "{}") || {}; }
  catch (e) { return {}; }
}
function saveTriageCacheEntry(key, value) {
  try {
    const cache = loadTriageCache();
    cache[key] = value;
    localStorage.setItem(TRIAGE_CACHE_KEY, JSON.stringify(cache));
  } catch (e) { /* storage unavailable/full -- verdict stays in-memory only */ }
}

function IssuesTab({ dispatch }) {
  const [, force] = React.useReducer(x => x + 1, 0);
  React.useEffect(() => {
    const onUpdate = () => force();
    window.addEventListener("nl-update", onUpdate);
    return () => window.removeEventListener("nl-update", onUpdate);
  }, []);

  const findings = (window.NL && NL.findings) ? NL.findings : [];
  const total    = (window.NL && NL.findingsCount) || findings.length;
  const [sevFilter,  setSevFilter]  = React.useState("all");
  const [kindFilter, setKindFilter] = React.useState("all");
  const [view, setView] = React.useState("flat"); // flat | grouped

  // Aggregate counts per severity and per kind for the filter chips.
  const sevCounts  = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const kindCounts = {};
  for (const f of findings) {
    sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1;
    kindCounts[f.kind]    = (kindCounts[f.kind]    || 0) + 1;
  }

  // Issue lifecycle (/api/findings/mark, /set-severity, /delete,
  // /suppress-kind -- all persisted per-project, applied server-side and
  // reflected back on every finding as falsePositive/deleted/suppressed).
  // Soft-deleted and muted-kind findings stay in NL.findings (so a restore
  // needs no re-scan) but are hidden from the default view, same as Burp
  // dropping a deleted issue from the live list while keeping it in state.
  const [showHidden, setShowHidden] = React.useState(false);
  const hiddenCount = findings.filter(f => f.deleted || f.suppressed).length;
  const doMarkFP = (f, e) => {
    e.stopPropagation();
    NL.actions.findingMark(f.id, !f.falsePositive);
  };
  const doToggleDelete = (f, e) => {
    e.stopPropagation();
    NL.actions.findingDelete(f.id, !f.deleted);
  };
  const doSetSeverity = (f, sev, e) => {
    e.stopPropagation();
    NL.actions.findingSetSeverity(f.id, sev);
  };
  const doSuppressKind = (kind, suppressed, e) => {
    e.stopPropagation();
    NL.actions.findingSuppressKind(kind, suppressed);
  };

  const visible = findings.filter(f =>
    (showHidden || (!f.deleted && !f.suppressed))
    && (sevFilter  === "all" || f.severity === sevFilter)
    && (kindFilter === "all" || f.kind     === kindFilter)
  ).sort((a, b) => {
    const sa = SEVERITY_ORDER[a.severity] ?? 5;
    const sb = SEVERITY_ORDER[b.severity] ?? 5;
    if (sa !== sb) return sa - sb;
    return b.id - a.id;  // newest first within same severity
  });

  // Findings grouped by kind+host (/api/findings/grouped) -- fetched lazily
  // when the GROUPED view is selected, refetched on demand via Refresh.
  const [grouped, setGrouped] = React.useState(null);
  const [groupedLoading, setGroupedLoading] = React.useState(false);
  const loadGrouped = React.useCallback(async () => {
    setGroupedLoading(true);
    try { setGrouped(await NL.actions.findingsGrouped()); }
    finally { setGroupedLoading(false); }
  }, []);
  const switchView = (v) => {
    setView(v);
    if (v === "grouped" && !grouped) loadGrouped();
  };

  // Scan-to-scan baseline delta (/api/baseline/*): save a snapshot of the
  // current findings, diff later to see what's NEW vs FIXED since.
  const [baselineStatus, setBaselineStatus] = React.useState(null);
  const [baselineDiff,   setBaselineDiff]   = React.useState(null);
  const [baselineBusy,   setBaselineBusy]   = React.useState(false);
  const refreshBaselineStatus = React.useCallback(async () => {
    setBaselineStatus(await NL.actions.baselineStatus());
  }, []);
  React.useEffect(() => { refreshBaselineStatus(); }, [refreshBaselineStatus]);
  const doBaselineSave = async () => {
    setBaselineBusy(true);
    try {
      const r = await NL.actions.baselineSave();
      if (r && r.ok === false) alert(r.error || "failed to save baseline");
      await refreshBaselineStatus();
    } finally { setBaselineBusy(false); }
  };
  const doBaselineDiff = async () => {
    setBaselineBusy(true);
    try { setBaselineDiff(await NL.actions.baselineDiff()); }
    finally { setBaselineBusy(false); }
  };
  const doBaselineClear = async () => {
    if (!confirm("Clear the saved baseline? This can't be undone.")) return;
    setBaselineBusy(true);
    try {
      await NL.actions.baselineClear();
      setBaselineDiff(null);
      await refreshBaselineStatus();
    } finally { setBaselineBusy(false); }
  };

  // AI-assisted triage (/api/triage/finding) -- per-finding, keyed by id.
  const [triage, setTriage] = React.useState({});      // id -> {loading,ok,triage,error,model}
  const [triageOpenId, setTriageOpenId] = React.useState(null);

  // Rehydrate any verdict already computed (this session, an earlier tab
  // switch, or a prior page load) from the localStorage cache, matched by
  // finding identity rather than the ephemeral id.
  React.useEffect(() => {
    if (!findings.length) return;
    const cache = loadTriageCache();
    setTriage(prev => {
      let changed = false;
      const next = { ...prev };
      for (const f of findings) {
        if (next[f.id]) continue;
        const cached = cache[findingIdentityKey(f)];
        if (cached) { next[f.id] = cached; changed = true; }
      }
      return changed ? next : prev;
    });
  }, [findings]);

  const doTriage = async (f) => {
    const existing = triage[f.id];
    if (existing && !existing.loading) {
      // Already have a verdict (fresh or rehydrated) -- toggle the panel
      // instead of re-querying the model.
      setTriageOpenId(prev => (prev === f.id ? null : f.id));
      return;
    }
    setTriageOpenId(f.id);
    setTriage(prev => ({ ...prev, [f.id]: { loading: true } }));
    try {
      const r = await NL.actions.triageFinding({
        rowId: f.rowId, kind: f.kind, severity: f.severity,
        summary: f.summary, evidence: f.evidence || "",
      });
      const entry = { loading: false, ...r };
      setTriage(prev => ({ ...prev, [f.id]: entry }));
      saveTriageCacheEntry(findingIdentityKey(f), entry);
    } catch (e) {
      setTriage(prev => ({ ...prev, [f.id]: { loading: false, error: String(e) } }));
    }
  };

  const jumpToRow = (rowId) => {
    dispatch({ type: "set", payload: { tab: "proxy", selectedRowId: rowId }});
  };

  // Inline issue-detail pane (Advisory / Request / Response) -- clicking a
  // finding used to navigate straight away to the Proxy tab with no way to
  // see the advisory data (cwe/owasp/cvss/fix) or the underlying request in
  // context. jumpToRow() above still exists as an explicit escape hatch.
  const [detailOpenId, setDetailOpenId] = React.useState(null);
  const [detailTab, setDetailTab] = React.useState("advisory"); // advisory|request|response
  const toggleDetail = (f) => {
    if (detailOpenId === f.id) { setDetailOpenId(null); return; }
    setDetailOpenId(f.id);
    setDetailTab("advisory");
  };

  const Chip = ({ label, active, onClick, color, count }) => (
    <button
      onClick={onClick}
      style={{
        background: active ? (color || "var(--accent)") : "transparent",
        color:      active ? "var(--bg)" : (color || "var(--text-2)"),
        border: "1px solid " + (color || "var(--line)"),
        padding: "3px 10px", fontSize: "10.5px",
        fontFamily: "var(--ff-mono)", cursor: "pointer",
        letterSpacing: "0.05em", textTransform: "uppercase",
        marginRight: 4, marginBottom: 4,
      }}
    >{label}{count !== undefined ? " · " + count : ""}</button>
  );

  return (
    <div style={{
      padding: 14, display: "flex", flexDirection: "column",
      gap: 10, height: "100%", minHeight: 0,
    }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}>
        <span style={{
          fontSize: "11px", color: "var(--accent)", textTransform: "uppercase",
          letterSpacing: "0.06em", fontWeight: 600,
        }}>Findings</span>
        <span style={{ color: "var(--dim)", fontSize: "11px" }}>
          {total} total · showing {view === "grouped"
            ? (grouped ? grouped.groups.length + " groups" : "…")
            : visible.length}
        </span>
        <button onClick={() => switchView("flat")}
          style={{
            background: view === "flat" ? "var(--accent)" : "transparent",
            color: view === "flat" ? "var(--bg)" : "var(--text-2)",
            border: "1px solid var(--accent)", padding: "3px 10px",
            fontSize: "10.5px", fontFamily: "var(--ff-mono)", cursor: "pointer",
            letterSpacing: "0.05em", textTransform: "uppercase",
          }}>Flat</button>
        <button onClick={() => switchView("grouped")}
          style={{
            background: view === "grouped" ? "var(--accent)" : "transparent",
            color: view === "grouped" ? "var(--bg)" : "var(--text-2)",
            border: "1px solid var(--accent)", padding: "3px 10px",
            fontSize: "10.5px", fontFamily: "var(--ff-mono)", cursor: "pointer",
            letterSpacing: "0.05em", textTransform: "uppercase",
          }}>Grouped</button>
        <button onClick={() => setShowHidden(h => !h)}
          title={showHidden ? "Hide deleted / muted findings again" : "Show findings marked deleted or from a muted kind"}
          style={{
            background: showHidden ? "var(--accent)" : "transparent",
            color: showHidden ? "var(--bg)" : "var(--text-2)",
            border: "1px solid var(--line)", padding: "3px 10px",
            fontSize: "10.5px", fontFamily: "var(--ff-mono)", cursor: "pointer",
            letterSpacing: "0.05em", textTransform: "uppercase",
          }}>{showHidden ? "showing hidden" : "show hidden"}{hiddenCount ? " · " + hiddenCount : ""}</button>
        <span style={{ flex: 1 }} />
        <button
          onClick={() => {
            const a = document.createElement("a");
            a.href = "/api/export/sarif"; a.download = "nullock-findings.sarif.json";
            document.body.appendChild(a); a.click(); a.remove();
          }}
          disabled={findings.length === 0}
          style={{
            background: "transparent",
            color: findings.length ? "var(--accent)" : "var(--dim)",
            border: "1px solid " + (findings.length ? "var(--accent)" : "var(--line)"),
            padding: "3px 10px",
            fontSize: "10.5px", fontFamily: "var(--ff-mono)",
            cursor: findings.length ? "pointer" : "not-allowed",
            letterSpacing: "0.05em", textTransform: "uppercase",
          }}>Export SARIF</button>
        <button
          onClick={async () => {
            if (!confirm("Run active probe against every row with query params? (throttled at 200ms by default; takes seconds-to-minutes)"))
              return;
            const r = await NL.actions.probeAll(200, 50);
            if (r && r.queued !== undefined) {
              alert("Queued " + r.queued + " row(s). Findings will stream in.");
            }
          }}
          style={{
            background: "transparent", color: "var(--accent)",
            border: "1px solid var(--accent)", padding: "3px 10px",
            fontSize: "10.5px", fontFamily: "var(--ff-mono)", cursor: "pointer",
            letterSpacing: "0.05em", textTransform: "uppercase",
          }}>Probe all rows</button>
        <button
          onClick={async () => {
            if (!confirm("Run the FULL deep-audit battery (cmdi/xxe/ldap/xpath/smuggle/hostheader/cache-poison/deser/nosql/mass-assign/cors) against every row with params or a body? This is slower and noisier than Probe."))
              return;
            const r = await NL.actions.auditAll(150, 50);
            if (r && r.ok === false) {
              alert(r.error || "deep-audit sweep could not start");
            } else if (r && r.queued !== undefined) {
              alert("Queued " + r.queued + " row(s) for deep audit" +
                    (r.scopeSkipped ? " (" + r.scopeSkipped + " skipped, out of scope)" : "") +
                    ". Findings will stream in.");
            }
          }}
          style={{
            background: "transparent", color: "var(--accent)",
            border: "1px solid var(--accent)", padding: "3px 10px",
            fontSize: "10.5px", fontFamily: "var(--ff-mono)", cursor: "pointer",
            letterSpacing: "0.05em", textTransform: "uppercase",
          }}>Deep audit all rows</button>
        <button
          onClick={() => { if (confirm("Clear all findings?")) NL.actions.clearFindings(); }}
          style={{
            background: "transparent", color: "var(--err, #f88)",
            border: "1px solid var(--err, #f88)", padding: "3px 10px",
            fontSize: "10.5px", fontFamily: "var(--ff-mono)", cursor: "pointer",
            letterSpacing: "0.05em", textTransform: "uppercase",
          }}>Clear all</button>
      </div>

      <div style={{
        display: "flex", alignItems: "baseline", gap: 10,
        background: "var(--pane)", border: "1px solid var(--line)",
        borderRadius: 4, padding: "6px 10px",
      }}>
        <span style={{
          fontSize: "10.5px", color: "var(--text-2)", textTransform: "uppercase",
          letterSpacing: "0.06em", fontWeight: 600,
        }}>Baseline</span>
        <span style={{ color: "var(--dim)", fontSize: "11px" }}>
          {baselineStatus == null
            ? "…"
            : baselineStatus.corrupt
              ? "baseline file present but unreadable"
              : baselineStatus.hasBaseline
                ? baselineStatus.baselineCount + " findings saved " + baselineStatus.savedAt
                : "no baseline saved yet"}
        </span>
        <span style={{ flex: 1 }} />
        <button disabled={baselineBusy} onClick={doBaselineSave}
          style={{
            background: "transparent", color: "var(--accent)",
            border: "1px solid var(--accent)", padding: "2px 8px",
            fontSize: "10px", fontFamily: "var(--ff-mono)",
            cursor: baselineBusy ? "not-allowed" : "pointer",
            letterSpacing: "0.05em", textTransform: "uppercase",
          }}>Save baseline</button>
        <button disabled={baselineBusy || !baselineStatus || !baselineStatus.hasBaseline}
          onClick={doBaselineDiff}
          style={{
            background: "transparent",
            color: (!baselineStatus || !baselineStatus.hasBaseline) ? "var(--dim)" : "var(--accent)",
            border: "1px solid " + ((!baselineStatus || !baselineStatus.hasBaseline) ? "var(--line)" : "var(--accent)"),
            padding: "2px 8px", fontSize: "10px", fontFamily: "var(--ff-mono)",
            cursor: (baselineBusy || !baselineStatus || !baselineStatus.hasBaseline) ? "not-allowed" : "pointer",
            letterSpacing: "0.05em", textTransform: "uppercase",
          }}>Diff vs current</button>
        <button disabled={baselineBusy || !baselineStatus || (!baselineStatus.hasBaseline && !baselineStatus.corrupt)}
          onClick={doBaselineClear}
          style={{
            background: "transparent", color: "var(--err, #f88)",
            border: "1px solid var(--err, #f88)", padding: "2px 8px",
            fontSize: "10px", fontFamily: "var(--ff-mono)",
            cursor: baselineBusy ? "not-allowed" : "pointer",
            letterSpacing: "0.05em", textTransform: "uppercase",
          }}>Clear</button>
      </div>
      {baselineDiff && baselineDiff.hasBaseline && (
        <div style={{
          background: "var(--pane)", border: "1px solid var(--line)",
          borderRadius: 4, padding: "8px 10px", fontSize: "11px",
          display: "flex", flexDirection: "column", gap: 6,
        }}>
          <span style={{ color: "var(--text-2)" }}>
            saved {baselineDiff.savedAt} ({baselineDiff.baselineCount}) vs current ({baselineDiff.currentCount}) —
            {" "}<span style={{ color: "var(--err, #f88)" }}>{baselineDiff.newCount} new</span>
            {" "}·{" "}<span style={{ color: "#3f8f29" }}>{baselineDiff.fixedCount} fixed</span>
            {" "}· {baselineDiff.unchangedCount} unchanged
          </span>
          {baselineDiff.new.length > 0 && (
            <div>
              <div style={{ color: "var(--err, #f88)", fontSize: "10px", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 3 }}>New</div>
              {baselineDiff.new.map((f, i) => (
                <div key={i} style={{ color: "var(--text)", padding: "2px 0" }}>
                  <span style={{ color: SEVERITY_COLOR[f.severity] || "var(--dim)" }}>{f.severity}</span> {f.kind} — {f.summary} <span style={{ color: "var(--dim)" }}>({f.host})</span>
                </div>
              ))}
            </div>
          )}
          {baselineDiff.fixed.length > 0 && (
            <div>
              <div style={{ color: "#3f8f29", fontSize: "10px", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 3 }}>Fixed</div>
              {baselineDiff.fixed.map((f, i) => (
                <div key={i} style={{ color: "var(--dim)", padding: "2px 0" }}>
                  {f.kind} — {f.summary} <span>({f.host})</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {view === "flat" && (
        <React.Fragment>
          <div>
            <Chip label="all" active={sevFilter === "all"} onClick={() => setSevFilter("all")} />
            {["critical", "high", "medium", "low", "info"].map(s => (
              <Chip key={s} label={s} count={sevCounts[s]}
                    color={SEVERITY_COLOR[s]}
                    active={sevFilter === s}
                    onClick={() => setSevFilter(s)} />
            ))}
          </div>
          <div>
            <Chip label="any kind" active={kindFilter === "all"} onClick={() => setKindFilter("all")} />
            {Object.entries(kindCounts).sort((a, b) => b[1] - a[1]).map(([k, c]) => {
              const kindMuted = findings.some(f => f.kind === k && f.suppressed);
              return (
                <span key={k} style={{ display: "inline-flex", verticalAlign: "top" }}>
                  <Chip label={k} count={c}
                        active={kindFilter === k}
                        onClick={() => setKindFilter(k)} />
                  <button
                    onClick={(e) => doSuppressKind(k, !kindMuted, e)}
                    title={kindMuted ? "Un-mute this kind (stop hiding it)" : "Mute this kind (hide every finding of it)"}
                    style={{
                      background: kindMuted ? "var(--dim)" : "transparent",
                      color: kindMuted ? "var(--bg)" : "var(--dim)",
                      border: "1px solid var(--line)",
                      marginLeft: -8, marginRight: 4, marginBottom: 4,
                      padding: "3px 6px", fontSize: "9.5px", fontFamily: "var(--ff-mono)",
                      cursor: "pointer", letterSpacing: "0.05em", textTransform: "uppercase",
                    }}>{kindMuted ? "muted" : "mute"}</button>
                </span>
              );
            })}
          </div>
        </React.Fragment>
      )}

      <div style={{
        background: "var(--pane)", border: "1px solid var(--line)",
        borderRadius: 4, flex: 1, minHeight: 0, overflow: "auto",
      }}>
        {view === "flat" ? (
          <React.Fragment>
            {visible.length === 0 && (
              <div style={{ padding: 24, textAlign: "center", color: "var(--dim)", fontSize: "12px" }}>
                no findings yet — proxy some traffic and check back
              </div>
            )}
            {visible.map(f => (
              <div key={f.id} style={{
                borderBottom: "1px solid var(--line-soft)",
                opacity: (f.deleted || f.falsePositive || f.suppressed) ? 0.5 : 1,
              }}>
                <div onClick={() => toggleDetail(f)}
                     style={{
                       display: "grid",
                       gridTemplateColumns: "70px 60px 180px 1fr 96px",
                       gap: 8, padding: "6px 12px",
                       alignItems: "baseline",
                       cursor: "pointer", fontSize: "12px",
                       fontFamily: "var(--ff-mono)",
                     }}
                     title="Click to view Advisory / Request / Response">
                  <span style={{
                    color: SEVERITY_COLOR[f.severity],
                    fontWeight: 600,
                    textTransform: "uppercase", letterSpacing: "0.05em",
                    fontSize: "10.5px",
                  }}>{f.severity}</span>
                  <span style={{ color: "var(--dim)" }}>
                    #{String(f.rowId).padStart(3, "0")}
                  </span>
                  <span style={{ color: "var(--accent)", overflow: "hidden",
                                 textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {f.kind}
                  </span>
                  <div style={{ display: "flex", flexDirection: "column", gap: 2, minWidth: 0 }}>
                    <span style={{
                      color: "var(--text)",
                      textDecoration: (f.deleted || f.falsePositive) ? "line-through" : "none",
                    }}>{f.summary}</span>
                    <span style={{
                      color: "var(--text-2)", fontSize: "10.5px",
                      overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                    }}>{f.host} · {f.url}</span>
                    {f.evidence && (
                      <span style={{
                        color: "var(--dim)", fontSize: "10px",
                        overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                      }}>↳ {f.evidence}</span>
                    )}
                    {(f.deleted || f.falsePositive || f.suppressed) && (
                      <span style={{ color: "var(--dim)", fontSize: "9.5px", textTransform: "uppercase", letterSpacing: "0.05em" }}>
                        {[f.deleted && "deleted", f.falsePositive && "false positive", f.suppressed && "kind muted"].filter(Boolean).join(" · ")}
                      </span>
                    )}
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: 3, justifySelf: "start" }}>
                    <button
                      onClick={(e) => { e.stopPropagation(); doTriage(f); }}
                      style={{
                        background: "transparent", color: "var(--accent)",
                        border: "1px solid var(--accent)", padding: "1px 6px",
                        fontSize: "9.5px", fontFamily: "var(--ff-mono)", cursor: "pointer",
                        letterSpacing: "0.05em", textTransform: "uppercase",
                      }}>Triage</button>
                    <div style={{ display: "flex", gap: 3 }}>
                      <button
                        onClick={(e) => doMarkFP(f, e)}
                        title={f.falsePositive ? "Un-mark as false positive" : "Mark as false positive"}
                        style={{
                          background: f.falsePositive ? "var(--dim)" : "transparent",
                          color: f.falsePositive ? "var(--bg)" : "var(--text-2)",
                          border: "1px solid var(--line)", padding: "1px 5px",
                          fontSize: "9px", fontFamily: "var(--ff-mono)", cursor: "pointer",
                          letterSpacing: "0.05em", textTransform: "uppercase", flex: 1,
                        }}>{f.falsePositive ? "un-fp" : "fp"}</button>
                      <button
                        onClick={(e) => doToggleDelete(f, e)}
                        title={f.deleted ? "Restore this finding" : "Delete this finding (soft -- can be restored)"}
                        style={{
                          background: f.deleted ? "var(--dim)" : "transparent",
                          color: f.deleted ? "var(--bg)" : "var(--text-2)",
                          border: "1px solid var(--line)", padding: "1px 5px",
                          fontSize: "9px", fontFamily: "var(--ff-mono)", cursor: "pointer",
                          letterSpacing: "0.05em", textTransform: "uppercase", flex: 1,
                        }}>{f.deleted ? "restore" : "del"}</button>
                    </div>
                    <select
                      value={f.severity}
                      onClick={(e) => e.stopPropagation()}
                      onChange={(e) => doSetSeverity(f, e.target.value, e)}
                      title="Override this finding's severity (persisted per project)"
                      style={{
                        background: "var(--pane)", color: "var(--text-2)",
                        border: "1px solid var(--line)", padding: "1px 3px",
                        fontSize: "9px", fontFamily: "var(--ff-mono)", cursor: "pointer",
                        letterSpacing: "0.03em", width: "100%",
                      }}>
                      {["critical", "high", "medium", "low", "info"].map(s => (
                        <option key={s} value={s}>{s}</option>
                      ))}
                    </select>
                  </div>
                </div>
                {triageOpenId === f.id && triage[f.id] && (
                  <div style={{
                    margin: "0 12px 8px", padding: "6px 8px",
                    background: "var(--bg-deep)", border: "1px solid var(--line)",
                    borderRadius: 3, fontSize: "11px", color: "var(--text-2)",
                    whiteSpace: "pre-wrap",
                  }}>
                    {triage[f.id].loading
                      ? "asking the AI triage model…"
                      : (!triage[f.id].triage && triage[f.id].error)
                        ? <span style={{ color: "var(--err, #f88)" }}>{String(triage[f.id].error)}</span>
                        : (
                          <React.Fragment>
                            <span style={{ color: "var(--dim)", fontSize: "10px" }}>
                              model: {triage[f.id].model || "?"}{triage[f.id].ok === false ? " (fallback heuristic — " + triage[f.id].error + ")" : ""}
                            </span>
                            <div>{triage[f.id].triage}</div>
                          </React.Fragment>
                        )}
                  </div>
                )}
                {detailOpenId === f.id && (
                  <div style={{
                    margin: "0 12px 10px", border: "1px solid var(--line)",
                    borderRadius: 3, background: "var(--bg-deep)",
                  }}>
                    <div style={{ display: "flex", borderBottom: "1px solid var(--line)" }}>
                      {["advisory", "request", "response"].map(t => (
                        <button key={t} onClick={() => setDetailTab(t)}
                          style={{
                            background: detailTab === t ? "var(--pane)" : "transparent",
                            color: detailTab === t ? "var(--accent)" : "var(--text-2)",
                            border: "none", borderRight: "1px solid var(--line)",
                            padding: "5px 12px", fontSize: "10.5px",
                            fontFamily: "var(--ff-mono)", cursor: "pointer",
                            letterSpacing: "0.05em", textTransform: "uppercase",
                          }}>{t}</button>
                      ))}
                      <button
                        onClick={(e) => { e.stopPropagation(); if (f.rowId) jumpToRow(f.rowId); }}
                        disabled={!f.rowId}
                        title={f.rowId ? "Open the underlying request/response in Proxy" : "No associated request (extension finding)"}
                        style={{
                          marginLeft: "auto", background: "transparent",
                          color: f.rowId ? "var(--accent)" : "var(--dim)",
                          border: "none", padding: "5px 12px", fontSize: "10.5px",
                          fontFamily: "var(--ff-mono)",
                          cursor: f.rowId ? "pointer" : "not-allowed",
                          letterSpacing: "0.05em", textTransform: "uppercase",
                        }}>Open in proxy ↦</button>
                    </div>
                    <div style={{ padding: "8px 10px", fontSize: "11px" }}>
                      <IssueDetailBody finding={f} tab={detailTab} />
                    </div>
                  </div>
                )}
              </div>
            ))}
          </React.Fragment>
        ) : (
          <React.Fragment>
            {groupedLoading && (
              <div style={{ padding: 24, textAlign: "center", color: "var(--dim)", fontSize: "12px" }}>
                loading grouped findings…
              </div>
            )}
            {!groupedLoading && grouped && grouped.groups.length === 0 && (
              <div style={{ padding: 24, textAlign: "center", color: "var(--dim)", fontSize: "12px" }}>
                no findings yet — proxy some traffic and check back
              </div>
            )}
            {!groupedLoading && grouped && grouped.groups
              .slice()
              .sort((a, b) => {
                const sa = SEVERITY_ORDER[a.severity] ?? 5;
                const sb = SEVERITY_ORDER[b.severity] ?? 5;
                if (sa !== sb) return sa - sb;
                return b.instances - a.instances;
              })
              .map((g, i) => (
                <div key={i}
                     onClick={() => g.sampleRowIds.length && jumpToRow(g.sampleRowIds[0])}
                     style={{
                       display: "grid",
                       gridTemplateColumns: "70px 60px 180px 1fr 70px",
                       gap: 8, padding: "6px 12px",
                       borderBottom: "1px solid var(--line-soft)",
                       alignItems: "baseline",
                       cursor: g.sampleRowIds.length ? "pointer" : "default",
                       fontSize: "12px", fontFamily: "var(--ff-mono)",
                     }}
                     title={g.sampleRowIds.length ? "Click to jump to row #" + String(g.sampleRowIds[0]).padStart(3, "0") : ""}>
                  <span style={{
                    color: SEVERITY_COLOR[g.severity] || "var(--dim)",
                    fontWeight: 600, textTransform: "uppercase",
                    letterSpacing: "0.05em", fontSize: "10.5px",
                  }}>{g.severity}</span>
                  <span style={{ color: "var(--dim)" }}>{g.instances}×</span>
                  <span style={{ color: "var(--accent)", overflow: "hidden",
                                 textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {g.kind}
                  </span>
                  <div style={{ display: "flex", flexDirection: "column", gap: 2, minWidth: 0 }}>
                    <span style={{ color: "var(--text)" }}>{g.summary}</span>
                    <span style={{
                      color: "var(--text-2)", fontSize: "10.5px",
                      overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                    }}>{g.host}{g.cwe ? " · " + g.cwe : ""}{g.owasp ? " · " + g.owasp : ""}</span>
                  </div>
                  <span style={{ color: "var(--dim)", fontSize: "10.5px", textAlign: "right" }}>
                    {g.cvssScore ? "cvss " + g.cvssScore.toFixed(1) : ""}
                  </span>
                </div>
              ))}
          </React.Fragment>
        )}
      </div>
    </div>
  );
}

// TCP port scanner (Nmap-flavored). Run a preset or custom port list
// against a host, watch live progress, see banner-grabbed services.
function ScansTab() {
  const [, force] = React.useReducer(x => x + 1, 0);
  React.useEffect(() => {
    const onUpdate = () => force();
    window.addEventListener("nl-update", onUpdate);
    return () => window.removeEventListener("nl-update", onUpdate);
  }, []);

  const ps = (window.NL && NL.portScan) ? NL.portScan
            : { host: "", running: false, done: 0, total: 0, results: [], error: "" };
  const [host, setHost] = React.useState("127.0.0.1");
  const [preset, setPreset] = React.useState("top100");
  const [customPorts, setCustomPorts] = React.useState("22,80,443,3306,5432,6379");
  const [timeoutMs, setTimeoutMs] = React.useState(1500);
  const [parallel, setParallel]   = React.useState(64);
  const [grabBanner, setGrabBanner] = React.useState(true);
  const [onlyOpen, setOnlyOpen]   = React.useState(true);
  const [throttleMs, setThrottleMs] = React.useState(0);
  const [randomize, setRandomize]   = React.useState(false);

  // --- nmap XML import: lets a scan run outside Nullock (or a saved
  // nmap -oX file) feed the same port-result pipeline as a live scan.
  const nmapFileRef = React.useRef(null);
  const [importBusy, setImportBusy] = React.useState(false);
  const [importMsg, setImportMsg]   = React.useState("");
  const doImportNmap = async (file) => {
    if (!file) return;
    setImportBusy(true); setImportMsg("");
    try {
      const text = await file.text();
      const r = await NL.actions.portscanImportNmap(text);
      setImportMsg(r && r.ok ? ("imported " + r.imported + " port results") : ("import failed: " + ((r && r.error) || "unknown error")));
    } catch (e) {
      setImportMsg("import failed: " + String(e && e.message ? e.message : e));
    } finally {
      setImportBusy(false);
    }
  };

  // --- unified scan/audit runners: assess/audit/paramminer/chain/pipeline
  // plus the read-only posture/inventory/compliance/gate rollups. All were
  // complete backends with zero ui-v2 callers before this.
  const [busy2, setBusy2] = React.useState("");
  const [err2, setErr2]   = React.useState("");

  const [postureRes, setPostureRes]       = React.useState(null);
  const [inventoryRes, setInventoryRes]   = React.useState(null);
  const [complianceRes, setComplianceRes] = React.useState(null);
  const [gateRes, setGateRes]             = React.useState(null);
  const [gateFailOn, setGateFailOn]       = React.useState("high");

  const [assessUrl, setAssessUrl] = React.useState("");
  const [assessRes, setAssessRes] = React.useState(null);

  const [pmUrl, setPmUrl]           = React.useState("");
  const [pmWordlist, setPmWordlist] = React.useState("");
  const [pmRes, setPmRes]           = React.useState(null);

  const [auditUrl, setAuditUrl]       = React.useState("");
  const [auditMethod, setAuditMethod] = React.useState("");
  const [auditBody, setAuditBody]     = React.useState("");
  const [auditInclude, setAuditInclude] = React.useState([]);
  const [auditRes, setAuditRes]       = React.useState(null);

  const [pipeHost, setPipeHost]                 = React.useState("");
  const [pipeAssessWeb, setPipeAssessWeb]       = React.useState(true);
  const [pipeIncludePorts, setPipeIncludePorts] = React.useState(true);
  const [pipeCorrelateCves, setPipeCorrelateCves] = React.useState(true);
  const [pipeRes, setPipeRes]                   = React.useState(null);

  const [chainSteps, setChainSteps]     = React.useState("");
  const [chainContinue, setChainContinue] = React.useState(false);
  const [chainRes, setChainRes]         = React.useState(null);

  const [exposureUrl, setExposureUrl] = React.useState("");
  const [exposureRes, setExposureRes] = React.useState(null);

  const [svHost, setSvHost]   = React.useState("");
  const [svPorts, setSvPorts] = React.useState("");
  const [svRes, setSvRes]     = React.useState(null);

  const [jsreconUrl, setJsreconUrl] = React.useState("");
  const [jsreconRes, setJsreconRes] = React.useState(null);

  const [tlsHost, setTlsHost] = React.useState("");
  const [tlsPort, setTlsPort] = React.useState("");
  const [tlsRes, setTlsRes]   = React.useState(null);
  const [http3Url, setHttp3Url] = React.useState("");
  const [http3Res, setHttp3Res] = React.useState(null);

  // Detection templates (nuclei-style matcher/extractor engine, /api/template/*)
  const [tplList, setTplList]     = React.useState(null);
  const [tplUrl, setTplUrl]       = React.useState("");
  const [tplSelected, setTplSelected] = React.useState("");
  const [tplCustom, setTplCustom] = React.useState("");
  const [tplRes, setTplRes]       = React.useState(null);

  // CVE overlay (extend Service CVE correlation at runtime, /api/cve/*)
  const [cveOverlay, setCveOverlay]   = React.useState(null);
  const [cveEntries, setCveEntries]   = React.useState("");
  const [cveUrl, setCveUrl]           = React.useState("");
  const [cveSyncRes, setCveSyncRes]   = React.useState(null);

  // Port scan -> findings bridge: promotes the port scanner's current
  // results (exposed db/remote-admin/mgmt-API/cleartext/file-share, plus
  // banner->CVE correlation) into the shared findings pipeline.
  const [bridgeIncludeOpen, setBridgeIncludeOpen]     = React.useState(true);
  const [bridgeCorrelateCves, setBridgeCorrelateCves] = React.useState(true);
  const [bridgeRes, setBridgeRes]                     = React.useState(null);

  const runBusy2 = async (key, setRes, fn) => {
    setErr2(""); setBusy2(key); setRes(null);
    try {
      const r = await fn();
      if (r && r.ok === false) setErr2(r.error || (key + " failed"));
      setRes(r);
    } catch (e) { setErr2(String(e && e.message ? e.message : e)); }
    finally { setBusy2(""); }
  };

  const loadPosture    = () => runBusy2("posture", setPostureRes, () => NL.actions.getPosture());
  const loadInventory  = () => runBusy2("inventory", setInventoryRes, () => NL.actions.getInventory());
  const loadCompliance = () => runBusy2("compliance", setComplianceRes, () => NL.actions.getCompliance());
  const loadGate       = () => runBusy2("gate", setGateRes, () => NL.actions.getGate(gateFailOn));

  const doAssess = () => {
    if (!assessUrl.trim()) { setErr2("enter a target URL"); return; }
    runBusy2("assess", setAssessRes, () => NL.actions.assess(assessUrl.trim()));
  };

  const doParamMine = () => {
    if (!pmUrl.trim()) { setErr2("enter a target URL"); return; }
    const wl = pmWordlist.split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
    runBusy2("paramminer", setPmRes, () => NL.actions.paramMine(pmUrl.trim(), wl.length ? { wordlist: wl } : {}));
  };

  const AUDIT_INCLUDES = ["params", "verbs", "cors", "idor", "massassign", "openredirect", "cache", "hostheader", "smuggle", "nosqli", "xxe"];
  const toggleInclude = (name) => setAuditInclude(prev => prev.includes(name) ? prev.filter(x => x !== name) : [...prev, name]);
  const doAuditRun = () => {
    if (!auditUrl.trim()) { setErr2("enter a target URL"); return; }
    const opts = {};
    if (auditMethod) opts.method = auditMethod;
    if (auditBody) opts.body = auditBody;
    if (auditInclude.length) opts.include = auditInclude;
    runBusy2("audit", setAuditRes, () => NL.actions.auditRun(auditUrl.trim(), opts));
  };

  const doPipeline = () => {
    const opts = { assessWeb: pipeAssessWeb, includeOpenPorts: pipeIncludePorts, correlateCves: pipeCorrelateCves };
    if (pipeHost.trim()) opts.host = pipeHost.trim();
    runBusy2("pipeline", setPipeRes, () => NL.actions.pipelineRun(opts));
  };

  const doChainRun = () => {
    let steps;
    try { steps = JSON.parse(chainSteps); } catch (e) { setErr2("steps must be valid JSON: " + (e && e.message ? e.message : e)); return; }
    if (!Array.isArray(steps) || !steps.length) { setErr2("steps must be a non-empty JSON array"); return; }
    runBusy2("chain", setChainRes, () => NL.actions.chainRun(steps, chainContinue));
  };

  const doExposureScan = () => {
    if (!exposureUrl.trim()) { setErr2("enter a target URL"); return; }
    runBusy2("exposure", setExposureRes, () => NL.actions.exposureScan(exposureUrl.trim()));
  };

  const doServiceVulns = () => {
    if (!svHost.trim()) { setErr2("enter a target host"); return; }
    const opts = {};
    const ports = svPorts.split(/[,\s]+/).map(s => parseInt(s, 10)).filter(p => Number.isFinite(p) && p > 0 && p < 65536);
    if (ports.length) opts.ports = ports;
    runBusy2("servicevulns", setSvRes, () => NL.actions.servicevulnsScan(svHost.trim(), opts));
  };

  const doJsRecon = () => {
    if (!jsreconUrl.trim()) { setErr2("enter a target URL"); return; }
    runBusy2("jsrecon", setJsreconRes, () => NL.actions.jsReconScan(jsreconUrl.trim()));
  };

  const doTlsInspect = () => {
    if (!tlsHost.trim()) { setErr2("enter a target host"); return; }
    const opts = {};
    const port = parseInt(tlsPort, 10);
    if (Number.isFinite(port) && port > 0 && port < 65536) opts.port = port;
    runBusy2("tls", setTlsRes, () => NL.actions.tlsInspect(tlsHost.trim(), opts));
  };

  const doHttp3Detect = () => {
    if (!http3Url.trim()) { setErr2("enter a target URL"); return; }
    runBusy2("http3", setHttp3Res, () => NL.actions.http3Detect(http3Url.trim()));
  };

  const doBridgeToFindings = () => runBusy2("bridge", setBridgeRes,
    () => NL.actions.portscanToFindings({ includeOpenPorts: bridgeIncludeOpen, correlateCves: bridgeCorrelateCves }));

  const loadTemplates = React.useCallback(() => runBusy2("templates", setTplList, () => NL.actions.templateList()), []);
  React.useEffect(() => { loadTemplates(); }, [loadTemplates]);
  const doTemplateRun = (spec) => {
    if (!tplUrl.trim()) { setErr2("enter a target URL"); return; }
    runBusy2("templaterun", setTplRes, () => NL.actions.templateRun(tplUrl.trim(), spec));
  };
  const doCustomTemplateRun = () => {
    if (!tplCustom.trim()) { setErr2("enter a custom template JSON"); return; }
    let tpl;
    try { tpl = JSON.parse(tplCustom); } catch (e) { setErr2("template must be valid JSON: " + (e && e.message ? e.message : e)); return; }
    doTemplateRun({ template: tpl });
  };

  const loadCveOverlay = React.useCallback(() => runBusy2("cveoverlay", setCveOverlay, () => NL.actions.cveOverlay()), []);
  React.useEffect(() => { loadCveOverlay(); }, [loadCveOverlay]);
  const doCveSync = () => {
    let payload;
    if (cveEntries.trim()) {
      let entries;
      try { entries = JSON.parse(cveEntries); } catch (e) { setErr2("entries must be valid JSON: " + (e && e.message ? e.message : e)); return; }
      if (!Array.isArray(entries)) { setErr2("entries must be a JSON array"); return; }
      payload = { entries };
    } else if (cveUrl.trim()) {
      payload = { url: cveUrl.trim() };
    } else {
      setErr2("provide entries JSON or a feed URL"); return;
    }
    runBusy2("cvesync", setCveSyncRes, () => NL.actions.cveSync(payload).then(r => { loadCveOverlay(); return r; }));
  };
  const doCveClear = () => runBusy2("cveclear", setCveOverlay, () => NL.actions.cveOverlayClear());

  const start = async () => {
    // Recognize three host-field shapes:
    // 1. CIDR "192.168.1.0/24" -> backend expands
    // 2. Comma-separated "1.1.1.1,2.2.2.2" -> hosts: [...]
    // 3. Single hostname/IP -> host: ...
    const payload = { timeoutMs, parallel, banner: grabBanner, throttleMs, randomize };
    const trimmed = host.trim();
    if (trimmed.includes("/")) {
      payload.cidr = trimmed;
    } else if (trimmed.includes(",")) {
      payload.hosts = trimmed.split(/[,\s]+/).filter(s => s);
    } else {
      payload.host = trimmed;
    }
    if (preset === "custom") {
      payload.ports = customPorts.split(/[,\s]+/)
        .map(s => parseInt(s, 10))
        .filter(p => Number.isFinite(p) && p > 0 && p < 65536);
    } else {
      payload.preset = preset;
    }
    const r = await NL.actions.portscanStart(payload);
    if (r && r.ok === false) alert("Scan failed to start: " + (r.error || ""));
  };

  const sorted = [...ps.results].sort((a, b) => {
    // open ports first, then by host, then by port
    if ((a.status === "open") !== (b.status === "open")) return a.status === "open" ? -1 : 1;
    const hc = (a.host || "").localeCompare(b.host || "");
    if (hc !== 0) return hc;
    return a.port - b.port;
  });
  const visible = sorted.filter(r => !onlyOpen || r.status === "open");
  const pct = ps.total ? Math.round((ps.done / ps.total) * 100) : 0;

  const Btn = ({ label, onClick, primary, danger, disabled }) => (
    <button onClick={onClick} disabled={disabled}
      style={{
        background: primary ? "var(--accent)" : "transparent",
        color: disabled ? "var(--dim)"
             : primary ? "var(--bg)"
             : danger ? "var(--err)"
             : "var(--accent)",
        border: "1px solid " + (disabled ? "var(--line)"
                              : danger ? "var(--err)"
                              : "var(--accent)"),
        padding: "4px 10px", fontSize: "11px",
        fontFamily: "var(--ff-mono)", cursor: disabled ? "not-allowed" : "pointer",
        letterSpacing: "0.05em", textTransform: "uppercase",
      }}>{label}</button>
  );

  const inp = {
    background: "var(--bg-deep)", color: "var(--text)",
    border: "1px solid var(--line)", padding: "4px 6px",
    fontSize: "12px", fontFamily: "var(--ff-mono)",
  };

  const Section = ({ title, hint, children }) => (
    <div style={{ background: "var(--pane)", border: "1px solid var(--line)", borderRadius: 4, padding: 12, display: "flex", flexDirection: "column", gap: 8 }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 10, flexWrap: "wrap" }}>
        <span style={{ fontSize: "11px", color: "var(--accent)", textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600 }}>{title}</span>
        {hint && <span style={{ color: "var(--dim)", fontSize: "11px" }}>{hint}</span>}
      </div>
      {children}
    </div>
  );
  const Btn2 = ({ label, onClick, k, disabled }) => (
    <button onClick={onClick} disabled={disabled || !!busy2} style={{
      background: "transparent",
      color: (disabled || busy2) ? "var(--dim)" : "var(--accent)",
      border: "1px solid var(--accent)", padding: "4px 10px", fontSize: "11px",
      fontFamily: "var(--ff-mono)", cursor: (disabled || busy2) ? (busy2 ? "wait" : "not-allowed") : "pointer",
      letterSpacing: "0.04em", textTransform: "uppercase",
    }}>{busy2 === k ? "…" : label}</button>
  );
  const CHAIN_STEPS_PLACEHOLDER =
    '[\n  {\n    "name": "login",\n    "host": "example.com",\n    "tls": true,\n' +
    '    "request": "POST /login HTTP/1.1\\r\\nHost: example.com\\r\\nContent-Type: application/x-www-form-urlencoded\\r\\nContent-Length: 13\\r\\n\\r\\nuser=a&pass=b",\n' +
    '    "extract": [ { "var": "token", "from": "json", "key": "data.token" } ]\n  }\n]';
  const RawResult = ({ res }) => res ? (
    <pre style={{
      margin: 0, padding: 8, background: "var(--bg-deep)", border: "1px solid var(--line)",
      fontSize: "11px", maxHeight: 220, overflow: "auto", whiteSpace: "pre-wrap", wordBreak: "break-all",
      color: "var(--text-2)",
    }}>{JSON.stringify(res, null, 2)}</pre>
  ) : null;

  return (
    <div style={{ padding: 14, display: "flex", flexDirection: "column", gap: 10, height: "100%", minHeight: 0, overflow: "auto" }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}>
        <span style={{
          fontSize: "11px", color: "var(--accent)", textTransform: "uppercase",
          letterSpacing: "0.06em", fontWeight: 600,
        }}>Port scanner</span>
        <span style={{ color: "var(--dim)", fontSize: "11px" }}>
          TCP connect · no raw sockets · safe to run anywhere
        </span>
      </div>

      <div style={{
        background: "var(--pane)", border: "1px solid var(--line)",
        padding: 12, borderRadius: 4, display: "grid",
        gridTemplateColumns: "100px 1fr 100px 1fr", gap: 8,
        alignItems: "center",
      }}>
        <label style={{ fontSize: "11px", color: "var(--dim)" }}>Host</label>
        <input style={inp} value={host}
               placeholder="127.0.0.1 · example.com · 192.168.1.0/24 · a,b,c"
               onChange={e => setHost(e.target.value)} />
        <label style={{ fontSize: "11px", color: "var(--dim)" }}>Preset</label>
        <select style={inp} value={preset} onChange={e => setPreset(e.target.value)}>
          <option value="discovery">discovery (22/80/443/3389)</option>
          <option value="top100">top 100 ports (nmap default)</option>
          <option value="web">web ports (80/443/8080/...)</option>
          <option value="full1024">all 1-1024</option>
          <option value="custom">custom (comma-sep)</option>
        </select>

        {preset === "custom" && (
          <>
            <label style={{ fontSize: "11px", color: "var(--dim)" }}>Ports</label>
            <input style={{ ...inp, gridColumn: "2 / span 3" }}
                   value={customPorts}
                   placeholder="22, 80, 443, 8080, 9000-9100"
                   onChange={e => setCustomPorts(e.target.value)} />
          </>
        )}

        <label style={{ fontSize: "11px", color: "var(--dim)" }}>Timeout</label>
        <input style={inp} type="number" value={timeoutMs}
               onChange={e => setTimeoutMs(parseInt(e.target.value, 10) || 1500)} />
        <label style={{ fontSize: "11px", color: "var(--dim)" }}>Parallel</label>
        <input style={inp} type="number" value={parallel}
               onChange={e => setParallel(parseInt(e.target.value, 10) || 64)} />

        <label style={{ fontSize: "11px", color: "var(--dim)" }}>Throttle</label>
        <input style={inp} type="number" value={throttleMs}
               title="Delay between probe launches in ms. 0 = no throttle"
               onChange={e => setThrottleMs(parseInt(e.target.value, 10) || 0)} />
        <label style={{ fontSize: "11px", color: "var(--dim)" }}>Stealth</label>
        <label style={{ display: "flex", gap: 6, alignItems: "center", fontSize: "11px", color: "var(--text)" }}>
          <input type="checkbox" checked={randomize}
                 onChange={e => setRandomize(e.target.checked)} />
          shuffle probe order (less obvious to log monitors)
        </label>

        <label style={{ fontSize: "11px", color: "var(--dim)" }}>Flags</label>
        <label style={{ display: "flex", gap: 6, alignItems: "center", fontSize: "11px", color: "var(--text)" }}>
          <input type="checkbox" checked={grabBanner}
                 onChange={e => setGrabBanner(e.target.checked)} />
          grab banner (5xx ms slower per open port)
        </label>
        <span />
        <label style={{ display: "flex", gap: 6, alignItems: "center", fontSize: "11px", color: "var(--text)" }}>
          <input type="checkbox" checked={onlyOpen}
                 onChange={e => setOnlyOpen(e.target.checked)} />
          show open only
        </label>

        <div style={{ gridColumn: "1 / span 4", display: "flex", gap: 6, marginTop: 4, alignItems: "center" }}>
          {!ps.running && <Btn label="Start scan" primary onClick={start} disabled={!host} />}
          {ps.running  && <Btn label="Stop" danger onClick={() => NL.actions.portscanStop()} />}
          <Btn label="Clear" onClick={() => NL.actions.portscanClear()} disabled={ps.running || !ps.results.length} />
          <Btn label="Export nmap XML" onClick={() => {
            const a = document.createElement("a");
            a.href = "/api/export/nmap-xml"; a.download = "nullock-portscan.xml";
            document.body.appendChild(a); a.click(); a.remove();
          }} disabled={!ps.results.length} />
          <input ref={nmapFileRef} type="file" accept=".xml" style={{ display: "none" }}
                 onChange={e => { const f = e.target.files && e.target.files[0]; e.target.value = ""; doImportNmap(f); }} />
          <Btn label="Import nmap XML" onClick={() => nmapFileRef.current && nmapFileRef.current.click()} disabled={importBusy} />
          {importMsg && <span style={{ color: "var(--dim)", fontSize: "11px" }}>{importMsg}</span>}
          <span style={{ flex: 1 }} />
          <span style={{ color: "var(--dim)", fontSize: "11px" }}>
            {ps.running ? "scanning… " : "ready · "}
            {ps.total ? (ps.done + "/" + ps.total + " · " + pct + "%") : ""}
            {ps.error ? " · err: " + ps.error : ""}
          </span>
        </div>
        {ps.total > 0 && (
          <div style={{ gridColumn: "1 / span 4", height: 4, background: "var(--bg-deep)" }}>
            <div style={{ width: pct + "%", height: "100%", background: "var(--accent)", transition: "width 0.2s" }} />
          </div>
        )}
      </div>

      {/* RESULTS */}
      <div style={{
        background: "var(--pane)", border: "1px solid var(--line)",
        borderRadius: 4, flex: "0 1 320px", minHeight: 120, maxHeight: 320,
        display: "flex", flexDirection: "column",
      }}>
        <div style={{
          display: "grid",
          gridTemplateColumns: "150px 70px 80px 80px 120px 1fr",
          gap: 6, padding: "6px 10px", borderBottom: "1px solid var(--line)",
          fontSize: "10px", color: "var(--dim)", textTransform: "uppercase",
          letterSpacing: "0.06em",
        }}>
          <span>host</span><span>port</span><span>status</span><span>latency</span><span>service</span><span>banner</span>
        </div>
        <div style={{ overflow: "auto", flex: 1 }}>
          {visible.length === 0 && (
            <div style={{ padding: 24, textAlign: "center", color: "var(--dim)", fontSize: "12px" }}>
              {ps.running ? "scanning…" : "no results yet"}
            </div>
          )}
          {visible.map((r, i) => (
            <div key={(r.host || "") + ":" + r.port + ":" + i} style={{
              display: "grid",
              gridTemplateColumns: "150px 70px 80px 80px 120px 1fr",
              gap: 6, padding: "5px 10px", alignItems: "baseline",
              fontSize: "12px", fontFamily: "var(--ff-mono)",
              borderBottom: "1px solid var(--line-soft)",
            }}>
              <span style={{ color: "var(--text-2)", overflow: "hidden",
                             textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                    title={r.host}>{r.host}</span>
              <span style={{ color: "var(--text)" }}>{r.port}</span>
              <span style={{
                color: r.status === "open" ? "#8ee5a0"
                     : r.status === "closed" ? "var(--err, #f88)"
                     : "var(--dim)",
                fontWeight: 600, fontSize: "11px",
                textTransform: "uppercase", letterSpacing: "0.05em",
              }}>{r.status}</span>
              <span style={{ color: "var(--dim)" }}>{r.latency}ms</span>
              <span style={{ color: "var(--accent)" }}>{r.service || "—"}</span>
              <span style={{
                color: "var(--text-2)", overflow: "hidden",
                textOverflow: "ellipsis", whiteSpace: "nowrap",
              }} title={r.banner}>{r.banner || ""}</span>
            </div>
          ))}
        </div>
      </div>

      {/* UNIFIED SCAN/AUDIT RUNNERS -- assess/audit/paramminer/chain/pipeline
          plus the read-only posture/inventory/compliance/gate rollups. */}
      <div style={{ display: "flex", alignItems: "baseline", gap: 12, marginTop: 4 }}>
        <span style={{ fontSize: "11px", color: "var(--accent)", textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600 }}>Assess &amp; audit</span>
        <span style={{ color: "var(--dim)", fontSize: "11px" }}>one-shot target assessment, deep audit, hidden-param mining, multi-step chains, and posture rollups</span>
        {err2 && <span style={{ color: "var(--err)", fontSize: "11px" }}>{err2}</span>}
      </div>

      <Section title="Port scan → findings" hint="promotes the port scanner's current results (exposed db/remote-admin/mgmt-API/cleartext/file-share, plus banner→CVE correlation) into the shared findings list -- makes no network requests, re-posting is a no-op on unchanged results">
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center" }}>
          <label style={{ display: "flex", gap: 6, alignItems: "center", fontSize: "11px", color: "var(--text)" }}>
            <input type="checkbox" checked={bridgeIncludeOpen} onChange={e => setBridgeIncludeOpen(e.target.checked)} />
            include open-port findings
          </label>
          <label style={{ display: "flex", gap: 6, alignItems: "center", fontSize: "11px", color: "var(--text)" }}>
            <input type="checkbox" checked={bridgeCorrelateCves} onChange={e => setBridgeCorrelateCves(e.target.checked)} />
            correlate banners against CVE table
          </label>
          <Btn2 k="bridge" label="Convert to findings" onClick={doBridgeToFindings} disabled={!ps.results.length} />
        </div>
        {bridgeRes && bridgeRes.ok !== false && (
          <div style={{ fontSize: "12px", color: "var(--text-2)" }}>
            {bridgeRes.openPorts} open ports · {bridgeRes.emitted} finding(s) emitted · {bridgeRes.skippedDuplicates} duplicate(s) skipped
            {bridgeRes.bySeverity && Object.keys(bridgeRes.bySeverity).length > 0 &&
              (" · " + Object.entries(bridgeRes.bySeverity).map(([k, v]) => k + ":" + v).join(", "))}
          </div>
        )}
        <RawResult res={bridgeRes} />
      </Section>

      <Section title="Posture / inventory / compliance / gate" hint="rollups over the current in-memory finding set -- no scanning, safe to poll">
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <Btn2 k="posture" label="Posture grade" onClick={loadPosture} />
          <Btn2 k="inventory" label="Inventory" onClick={loadInventory} />
          <Btn2 k="compliance" label="Compliance coverage" onClick={loadCompliance} />
          <select value={gateFailOn} onChange={e => setGateFailOn(e.target.value)} style={{ ...inp, width: 110 }}>
            <option value="critical">critical</option><option value="high">high</option>
            <option value="medium">medium</option><option value="low">low</option>
            <option value="info">info</option><option value="none">none</option>
          </select>
          <Btn2 k="gate" label="CI gate check" onClick={loadGate} />
        </div>
        {postureRes && postureRes.ok !== false && (
          <div style={{ fontSize: "12px", color: "var(--text-2)" }}>
            posture: <span style={{ color: "var(--accent)" }}>{postureRes.grade}</span> ({postureRes.score}/100) ·{" "}
            penalty {postureRes.penalty} · {postureRes.totalFindings} findings
          </div>
        )}
        {inventoryRes && inventoryRes.ok !== false && (
          <div style={{ fontSize: "12px", color: "var(--text-2)" }}>
            {inventoryRes.hostCount} hosts · {inventoryRes.totalOpenPorts} open ports · {inventoryRes.totalFindings} findings
          </div>
        )}
        {complianceRes && complianceRes.ok !== false && (
          <div style={{ fontSize: "12px", color: "var(--text-2)" }}>
            {complianceRes.mappedFindings}/{complianceRes.totalFindings} findings mapped ·{" "}
            {complianceRes.owaspCategoriesHit} OWASP Top 10 categories hit · {complianceRes.complianceTagsHit} compliance tags hit
          </div>
        )}
        {gateRes && gateRes.ok !== false && (
          <div style={{ fontSize: "12px", color: gateRes.pass ? "#8ee5a0" : "var(--err)" }}>
            {gateRes.pass ? "PASS" : "FAIL"} (exit {gateRes.exitCode}) — fail-on {gateRes.failOn}, {gateRes.offendingCount} offending / {gateRes.totalFindings} total
          </div>
        )}
        <RawResult res={postureRes || inventoryRes || complianceRes || gateRes} />
      </Section>

      <Section title="Assess target" hint="fingerprint + CVE correlation + header/method/TLS audit against one URL">
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <input value={assessUrl} onChange={e => setAssessUrl(e.target.value)} placeholder="https://target/"
                 onKeyDown={e => { if (e.key === "Enter") doAssess(); }}
                 style={{ ...inp, flex: "1 1 260px", minWidth: 200 }} spellCheck={false} />
          <Btn2 k="assess" label="Assess" onClick={doAssess} />
        </div>
        {assessRes && assessRes.ok !== false && (
          <div style={{ fontSize: "12px", color: "var(--text-2)" }}>
            {assessRes.host}:{assessRes.port} {assessRes.tls ? "(tls)" : ""} · tech: {(assessRes.tech || []).join(", ") || "—"} ·{" "}
            {assessRes.findingCount} findings
          </div>
        )}
        <RawResult res={assessRes} />
      </Section>

      <Section title="Param miner" hint="response-diff hidden query/body parameter discovery">
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <input value={pmUrl} onChange={e => setPmUrl(e.target.value)} placeholder="https://target/path"
                 style={{ ...inp, flex: "1 1 260px", minWidth: 200 }} spellCheck={false} />
          <Btn2 k="paramminer" label="Mine params" onClick={doParamMine} />
        </div>
        <textarea value={pmWordlist} onChange={e => setPmWordlist(e.target.value)}
                  placeholder="custom wordlist, one per line or comma-separated (optional -- default wordlist used if empty)"
                  rows={2} style={{ ...inp, resize: "vertical", fontSize: "11px" }} spellCheck={false} />
        {pmRes && pmRes.ok !== false && (
          <div style={{ fontSize: "12px", color: "var(--text-2)" }}>
            {pmRes.requestsSent} requests · {pmRes.candidatesTried} candidates tried · {pmRes.foundCount} found
          </div>
        )}
        <RawResult res={pmRes} />
      </Section>

      <Section title="Audit run" hint="synchronous deep-audit battery against one URL (blocks until done)">
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <input value={auditUrl} onChange={e => setAuditUrl(e.target.value)} placeholder="https://target/path?id=1"
                 style={{ ...inp, flex: "1 1 260px", minWidth: 200 }} spellCheck={false} />
          <select value={auditMethod} onChange={e => setAuditMethod(e.target.value)} style={{ ...inp, width: 90 }}>
            <option value="">auto</option><option value="GET">GET</option><option value="POST">POST</option>
          </select>
          <Btn2 k="audit" label="Run audit" onClick={doAuditRun} />
        </div>
        <textarea value={auditBody} onChange={e => setAuditBody(e.target.value)} placeholder="request body (optional)"
                  rows={1} style={{ ...inp, resize: "vertical", fontSize: "11px" }} spellCheck={false} />
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          {AUDIT_INCLUDES.map(name => (
            <label key={name} style={{ display: "flex", gap: 4, alignItems: "center", fontSize: "11px", color: "var(--text)" }}>
              <input type="checkbox" checked={auditInclude.includes(name)} onChange={() => toggleInclude(name)} />
              {name}{name === "smuggle" ? " (opt-in, not in default sweep)" : ""}
            </label>
          ))}
        </div>
        <div style={{ fontSize: "10px", color: "var(--dim)" }}>no boxes checked = run the default battery (all except smuggle)</div>
        {auditRes && auditRes.ok !== false && (
          <div style={{ fontSize: "12px", color: "var(--text-2)" }}>
            {auditRes.totalFindings} tester(s) hit on {auditRes.target}
          </div>
        )}
        <RawResult res={auditRes} />
      </Section>

      <Section title="Pipeline run" hint="capstone: bridge port-scan results into findings, then assess every open web port">
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
          <input value={pipeHost} onChange={e => setPipeHost(e.target.value)} placeholder="host filter (blank = all scanned hosts)"
                 style={{ ...inp, flex: "1 1 220px", minWidth: 180 }} spellCheck={false} />
          <label style={{ display: "flex", gap: 4, alignItems: "center", fontSize: "11px", color: "var(--text)" }}>
            <input type="checkbox" checked={pipeAssessWeb} onChange={e => setPipeAssessWeb(e.target.checked)} /> assess web
          </label>
          <label style={{ display: "flex", gap: 4, alignItems: "center", fontSize: "11px", color: "var(--text)" }}>
            <input type="checkbox" checked={pipeIncludePorts} onChange={e => setPipeIncludePorts(e.target.checked)} /> include open ports
          </label>
          <label style={{ display: "flex", gap: 4, alignItems: "center", fontSize: "11px", color: "var(--text)" }}>
            <input type="checkbox" checked={pipeCorrelateCves} onChange={e => setPipeCorrelateCves(e.target.checked)} /> correlate CVEs
          </label>
          <Btn2 k="pipeline" label="Run pipeline" onClick={doPipeline} />
        </div>
        <div style={{ fontSize: "10px", color: "var(--dim)" }}>runs against results already collected by the port scanner above — run a port scan first</div>
        {pipeRes && pipeRes.ok !== false && (
          <div style={{ fontSize: "12px", color: "var(--text-2)" }}>
            {pipeRes.openPorts} open ports · {pipeRes.networkFindings} network findings ·{" "}
            {pipeRes.webTargetsAssessed} web targets assessed · {pipeRes.webFindings} web findings
          </div>
        )}
        <RawResult res={pipeRes} />
      </Section>

      <Section title="Request chain" hint="multi-step raw-HTTP chain with {{var}} extraction/substitution (e.g. login -> use token)">
        <textarea value={chainSteps} onChange={e => setChainSteps(e.target.value)}
                  placeholder={CHAIN_STEPS_PLACEHOLDER}
                  rows={5} style={{ ...inp, resize: "vertical", fontSize: "11px" }} spellCheck={false} />
        <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <label style={{ display: "flex", gap: 4, alignItems: "center", fontSize: "11px", color: "var(--text)" }}>
            <input type="checkbox" checked={chainContinue} onChange={e => setChainContinue(e.target.checked)} /> continue on error
          </label>
          <Btn2 k="chain" label="Run chain" onClick={doChainRun} />
        </div>
        {chainRes && chainRes.ok !== false && (
          <div style={{ fontSize: "12px", color: "var(--text-2)" }}>
            ran {chainRes.ran} step(s) · vars: {Object.keys(chainRes.vars || {}).join(", ") || "—"}
          </div>
        )}
        <RawResult res={chainRes} />
      </Section>

      <Section title="Exposure scan" hint="probes curated sensitive paths (.git/.env/actuator/backups/...), confirmed by content signature">
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <input value={exposureUrl} onChange={e => setExposureUrl(e.target.value)} placeholder="https://target/"
                 onKeyDown={e => { if (e.key === "Enter") doExposureScan(); }}
                 style={{ ...inp, flex: "1 1 260px", minWidth: 200 }} spellCheck={false} />
          <Btn2 k="exposure" label="Scan" onClick={doExposureScan} />
        </div>
        {exposureRes && exposureRes.ok !== false && (
          <div style={{ fontSize: "12px", color: "var(--text-2)" }}>
            {exposureRes.probed} path(s) probed · {exposureRes.hitCount} hit(s){exposureRes.catchAll ? " · catch-all response detected (results may be unreliable)" : ""}
          </div>
        )}
        <RawResult res={exposureRes} />
      </Section>

      <Section title="Service CVE correlation" hint="banner-grabs network services and matches versions against a curated CVE table">
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <input value={svHost} onChange={e => setSvHost(e.target.value)} placeholder="host or IP"
                 onKeyDown={e => { if (e.key === "Enter") doServiceVulns(); }}
                 style={{ ...inp, flex: "1 1 200px", minWidth: 160 }} spellCheck={false} />
          <input value={svPorts} onChange={e => setSvPorts(e.target.value)} placeholder="ports (optional, e.g. 22,80,443)"
                 style={{ ...inp, flex: "1 1 200px", minWidth: 160 }} spellCheck={false} />
          <Btn2 k="servicevulns" label="Scan" onClick={doServiceVulns} />
        </div>
        {svRes && svRes.ok !== false && (
          <div style={{ fontSize: "12px", color: "var(--text-2)" }}>
            {svRes.portsProbed} port(s) probed · {svRes.hitCount} CVE hit(s)
          </div>
        )}
        <RawResult res={svRes} />
      </Section>

      <Section title="JS recon" hint="mines same-origin JS bundles for API endpoints, hardcoded secrets, and exposed source maps">
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <input value={jsreconUrl} onChange={e => setJsreconUrl(e.target.value)} placeholder="https://target/"
                 onKeyDown={e => { if (e.key === "Enter") doJsRecon(); }}
                 style={{ ...inp, flex: "1 1 260px", minWidth: 200 }} spellCheck={false} />
          <Btn2 k="jsrecon" label="Mine" onClick={doJsRecon} />
        </div>
        {jsreconRes && jsreconRes.ok !== false && (
          <div style={{ fontSize: "12px", color: "var(--text-2)" }}>
            {(jsreconRes.scripts || []).length} script(s) · {jsreconRes.endpointCount} endpoint(s) found ·{" "}
            {(jsreconRes.sourceMaps || []).filter(m => m.accessible).length} exposed source map(s) · {jsreconRes.secretCount} secret(s)
          </div>
        )}
        <RawResult res={jsreconRes} />
      </Section>

      <Section title="TLS / certificate inspection" hint="opens a live TLS connection and flags expired/self-signed/weak-key/hostname-mismatch/legacy-protocol config (CWE-295)">
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <input value={tlsHost} onChange={e => setTlsHost(e.target.value)} placeholder="host or IP"
                 onKeyDown={e => { if (e.key === "Enter") doTlsInspect(); }}
                 style={{ ...inp, flex: "1 1 200px", minWidth: 160 }} spellCheck={false} />
          <input value={tlsPort} onChange={e => setTlsPort(e.target.value)} placeholder="port (default 443)"
                 onKeyDown={e => { if (e.key === "Enter") doTlsInspect(); }}
                 style={{ ...inp, flex: "0 1 160px", minWidth: 120 }} spellCheck={false} />
          <Btn2 k="tls" label="Inspect" onClick={doTlsInspect} />
        </div>
        {tlsRes && tlsRes.connected && (
          <div style={{ fontSize: "12px", color: "var(--text-2)" }}>
            {tlsRes.protocol} · {tlsRes.cipher} · subject: {tlsRes.subject || "—"} ·{" "}
            expires in {tlsRes.daysToExpiry != null ? tlsRes.daysToExpiry + "d" : "—"} ·{" "}
            {tlsRes.findingCount} finding(s)
          </div>
        )}
        {tlsRes && tlsRes.findingCount > 0 && (
          <div style={{ display: "flex", flexDirection: "column", gap: 2, fontSize: "12px" }}>
            {tlsRes.findings.map((f, i) => (
              <div key={i}>
                <span style={{ color: SEVERITY_COLOR[f.severity] || "var(--dim)" }}>{f.severity}</span> {f.kind} — <span style={{ color: "var(--text-2)" }}>{f.detail}</span>
              </div>
            ))}
          </div>
        )}
        <RawResult res={tlsRes} />
      </Section>

      <Section title="HTTP/3 detection" hint="checks the Alt-Svc response header for advertised h3/h3-* protocol support (QUIC transport, not yet fetched over)">
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <input value={http3Url} onChange={e => setHttp3Url(e.target.value)} placeholder="https://target/"
                 onKeyDown={e => { if (e.key === "Enter") doHttp3Detect(); }}
                 style={{ ...inp, flex: "1 1 260px", minWidth: 200 }} spellCheck={false} />
          <Btn2 k="http3" label="Detect" onClick={doHttp3Detect} />
        </div>
        {http3Res && http3Res.ok !== false && (
          <div style={{ fontSize: "12px", color: "var(--text-2)" }}>
            {http3Res.advertisesHttp3
              ? <>advertises HTTP/3 ({(http3Res.http3Versions || []).join(", ") || "—"})</>
              : "no HTTP/3 advertised"}
            {http3Res.altSvc ? <> · Alt-Svc: <code>{http3Res.altSvc}</code></> : null}
          </div>
        )}
        {http3Res && (http3Res.protocols || []).length > 0 && (
          <div style={{ display: "flex", flexDirection: "column", gap: 2, fontSize: "12px" }}>
            {http3Res.protocols.map((p, i) => (
              <div key={i}>
                <span style={{ color: p.isHttp3 ? "var(--ok)" : "var(--text-2)" }}>{p.id}</span>{" "}
                {p.authority ? <>· authority: {p.authority}</> : null}{" "}
                {p.maxAge ? <>· max-age: {p.maxAge}</> : null}
              </div>
            ))}
          </div>
        )}
        <RawResult res={http3Res} />
      </Section>

      <Section title="Detection templates" hint="nuclei-style matcher/extractor engine -- bundled templates or custom JSON, a match also files a finding into Issues">
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <input value={tplUrl} onChange={e => setTplUrl(e.target.value)} placeholder="https://target/"
                 onKeyDown={e => { if (e.key === "Enter" && tplSelected) doTemplateRun({ templateId: tplSelected }); }}
                 style={{ ...inp, flex: "1 1 260px", minWidth: 200 }} spellCheck={false} />
          <select style={inp} value={tplSelected} onChange={e => setTplSelected(e.target.value)}>
            <option value="">-- pick a bundled template --</option>
            {((tplList && tplList.templates) || []).map(t => (
              <option key={t.id} value={t.id}>{t.name} ({t.severity})</option>
            ))}
          </select>
          <Btn2 k="templaterun" label="Run" disabled={!tplSelected} onClick={() => doTemplateRun({ templateId: tplSelected })} />
          <Btn2 k="templates" label="Reload list" onClick={loadTemplates} />
        </div>
        {tplList && tplList.templates && tplList.templates.length > 0 && (
          <Table cols={["id", "name", "severity", "description"]} rows={tplList.templates}
                 cell={t => [t.id, t.name, <span style={{ color: SEVERITY_COLOR[t.severity] || "var(--dim)" }}>{t.severity}</span>, t.description]} />
        )}
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <label style={{ fontSize: "11px", color: "var(--dim)" }}>Custom template (JSON) — nuclei-style matchers/extractors, runs against the URL above</label>
          <textarea value={tplCustom} onChange={e => setTplCustom(e.target.value)}
                    placeholder={'{"matchers-condition":"and","matchers":[{"type":"status","status":[200]}]}'}
                    style={{ ...inp, minHeight: 70, resize: "vertical" }} spellCheck={false} />
          <div><Btn2 k="templaterun" label="Run custom" onClick={doCustomTemplateRun} /></div>
        </div>
        {tplRes && tplRes.ok !== false && (
          <div style={{ fontSize: "12px", color: "var(--text-2)" }}>
            {tplRes.matched ? <span style={{ color: "var(--err)" }}>MATCHED</span> : "no match"} · {tplRes.requests} request(s){tplRes.capped ? " (capped)" : ""}
            {tplRes.name ? " · " + tplRes.name : ""}{tplRes.severity ? " (" + tplRes.severity + ")" : ""}
          </div>
        )}
        <RawResult res={tplRes} />
      </Section>

      <Section title="CVE overlay" hint="extend Service CVE correlation at runtime -- push extra service CVEs directly (air-gapped) or sync from a JSON feed URL">
        <div style={{ fontSize: "12px", color: "var(--text-2)" }}>
          {cveOverlay && cveOverlay.ok !== false
            ? cveOverlay.count + " overlay entr" + (cveOverlay.count === 1 ? "y" : "ies") + " loaded"
            : "—"}
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <label style={{ fontSize: "11px", color: "var(--dim)" }}>
            Entries (JSON array) — each needs product + cveId, and either minVer/maxVer or exact
          </label>
          <textarea value={cveEntries} onChange={e => setCveEntries(e.target.value)}
                    placeholder={'[{"product":"nginx","cveId":"CVE-2021-23017","cvss":9.8,"minVer":"1.20.0","maxVer":"1.20.0","summary":"off-by-one in resolver","fix":"upgrade to 1.20.1"}]'}
                    style={{ ...inp, minHeight: 70, resize: "vertical" }} spellCheck={false} />
        </div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <input value={cveUrl} onChange={e => setCveUrl(e.target.value)}
                 placeholder="or a feed URL (JSON array, or {entries:[...]} / {cves:[...]}) -- used if entries above is blank"
                 onKeyDown={e => { if (e.key === "Enter") doCveSync(); }}
                 style={{ ...inp, flex: "1 1 320px", minWidth: 220 }} spellCheck={false} />
          <Btn2 k="cvesync" label="Sync" onClick={doCveSync} />
          <Btn2 k="cveclear" label="Clear overlay" disabled={!cveOverlay || !cveOverlay.count} onClick={doCveClear} />
          <Btn2 k="cveoverlay" label="Refresh count" onClick={loadCveOverlay} />
        </div>
        {cveSyncRes && cveSyncRes.ok !== false && cveSyncRes.synced != null && (
          <div style={{ fontSize: "12px", color: "var(--text-2)" }}>
            synced {cveSyncRes.synced} of {cveSyncRes.received} (dropped {cveSyncRes.dropped}) from {cveSyncRes.source}
          </div>
        )}
        {cveSyncRes && cveSyncRes.ok === false && (
          <div style={{ fontSize: "12px", color: "var(--err)" }}>{cveSyncRes.error}</div>
        )}
        <RawResult res={cveSyncRes} />
      </Section>
    </div>
  );
}

// Curated short subdomain wordlist for the wordlist subdomain enum.
// Tier-1 candidates only -- the user can paste a bigger list if they
// want to be thorough.
const SUBDOMAIN_WORDLIST = [
  "www","mail","webmail","smtp","pop","imap","ftp","sftp","ssh","vpn",
  "remote","admin","administrator","portal","login","auth","sso","oauth",
  "api","api-v1","api-v2","api-v3","graphql","rest","gateway","apigw",
  "app","apps","beta","alpha","dev","development","staging","stage",
  "test","testing","qa","preprod","sandbox","preview","demo",
  "blog","forum","forums","wiki","docs","documentation","help","support",
  "store","shop","payments","pay","checkout","billing","invoice",
  "cdn","static","assets","media","img","images","files","download","downloads",
  "git","gitlab","github","bitbucket","jenkins","ci","build",
  "monitoring","grafana","kibana","prometheus","metrics","status",
  "elastic","es","search","db","database","mysql","postgres","redis",
  "cache","memcache","mongo","rabbitmq",
  "internal","intranet","corp","corporate","hr","finance","accounting",
  "secure","secured","old","new","beta2","mobile","m","wap","go",
  "track","tracker","analytics","stats","logs","kibana","splunk",
  "ns1","ns2","ns3","dns","dns1","dns2","mx","mx1","mx2",
];

// RECON tab. DNS lookups, cert-transparency subdomain enum, wordlist
// subdomain enum -- the recon-for-web-testing flavor, not OSINT for
// people. Pairs with the rest of the workflow: scope a domain here,
// click a found subdomain to populate the proxy host filter.
function ProcessorTab() {
  const [payload, setPayload] = React.useState("");
  const [variants, setVariants] = React.useState([]);
  const [err, setErr] = React.useState("");
  const [copied, setCopied] = React.useState(-1);

  const run = async () => {
    setErr("");
    try {
      const r = await NL.actions.processPayload(payload);
      setVariants(r.variants || []);
    } catch (e) { setErr(String(e && e.message ? e.message : e)); }
  };
  const copy = (text, i) => {
    try { navigator.clipboard?.writeText(text); setCopied(i); setTimeout(() => setCopied(-1), 1000); } catch (e) {}
  };

  const Btn = ({ label, onClick, primary, disabled, title }) => (
    <button onClick={onClick} disabled={disabled} title={title}
      style={{
        background: primary ? "var(--accent)" : "transparent",
        color: disabled ? "var(--dim)" : primary ? "var(--bg)" : "var(--accent)",
        border: "1px solid " + (disabled ? "var(--line)" : "var(--accent)"),
        padding: "4px 10px", fontSize: "11px", fontFamily: "var(--ff-mono)",
        cursor: disabled ? "not-allowed" : "pointer", letterSpacing: "0.04em",
        textTransform: "uppercase",
      }}>{label}</button>
  );

  return (
    <div style={{ padding: 14, display: "flex", flexDirection: "column",
                  gap: 10, height: "100%", minHeight: 0 }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}>
        <span style={{ fontSize: "11px", color: "var(--accent)", textTransform: "uppercase",
                       letterSpacing: "0.06em", fontWeight: 600 }}>Processor</span>
        <span style={{ color: "var(--dim)", fontSize: "11px" }}>
          filter-bypass variants of a payload — for authorized WAF/filter-coverage testing
        </span>
      </div>

      <div style={{ background: "var(--pane)", border: "1px solid var(--line)",
                    padding: 12, borderRadius: 4, display: "flex", gap: 8, alignItems: "center" }}>
        <input style={{ flex: 1, background: "var(--bg-deep)", color: "var(--text)",
                        border: "1px solid var(--line)", padding: "5px 8px",
                        fontSize: "12px", fontFamily: "var(--ff-mono)" }}
               value={payload} placeholder="' OR 1=1 --   or   <script>alert(1)</script>"
               onChange={e => setPayload(e.target.value)}
               onKeyDown={e => { if (e.key === "Enter") run(); }} />
        <Btn label="process" primary onClick={run} disabled={!payload} />
        <span style={{ color: "var(--dim)", fontSize: "11px" }}>
          {err ? err : (variants.length ? variants.length + " variants" : "")}
        </span>
      </div>

      <div style={{ flex: 1, minHeight: 0, overflow: "auto", display: "flex",
                    flexDirection: "column", gap: 6 }}>
        {variants.map((v, i) => (
          <div key={i} style={{ background: "var(--pane)", border: "1px solid var(--line)",
                                borderRadius: 4, padding: 8, display: "flex",
                                flexDirection: "column", gap: 4 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ color: "var(--accent)", fontSize: "11px", fontWeight: 600 }}>{v.name}</span>
              <span style={{ color: "var(--dim)", fontSize: "10px", flex: 1 }}>{v.note}</span>
              <Btn label={copied === i ? "copied" : "copy"} onClick={() => copy(v.output, i)} />
            </div>
            <pre style={{ margin: 0, padding: 6, background: "var(--bg-deep)",
                          border: "1px solid var(--line)", borderRadius: 3,
                          fontSize: "11.5px", fontFamily: "var(--ff-mono)", color: "var(--text)",
                          whiteSpace: "pre-wrap", wordBreak: "break-all" }}>{v.output}</pre>
          </div>
        ))}
        {!variants.length ? (
          <div style={{ color: "var(--dim)", fontSize: "11px", padding: 8 }}>
            Enter a payload and press process to generate encoding/casing/comment bypass variants.
          </div>
        ) : null}
      </div>
    </div>
  );
}

// Hex-dump rendering shared by Comparer's Text/Hex toggle. Byte-for-byte
// (UTF-8), space-separated pairs -- not an offset/ascii triple-column dump,
// just enough to inspect binary-looking diff segments without decoding them
// as text.
function textToHexPairs(text) {
  const bytes = new TextEncoder().encode(text || "");
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, "0");
    if (i < bytes.length - 1) out += " ";
  }
  return out;
}

// #313: pair up an adjacent del+ins (or ins+del) run in the backend's
// merged diff segment list into a "modified" replacement -- greedy
// left-to-right, one pair consumed at a time. A lone del or ins next to
// unrelated ops (not immediately followed/preceded by its opposite) stays
// a plain delete/insert. Pure function, no DOM/React dependency.
function comparerMarkModified(segs) {
  const out = segs.map((s) => ({ ...s }));
  for (let i = 0; i < out.length - 1; i++) {
    const a = out[i], b = out[i + 1];
    if ((a.op === "del" && b.op === "ins") || (a.op === "ins" && b.op === "del")) {
      a.modified = true;
      b.modified = true;
      i++;
    }
  }
  return out;
}

function ComparerTab({ comparer, dispatch }) {
  const items = comparer.items;
  const selA = comparer.selA;
  const selB = comparer.selB;
  const itemA = items.find(i => i.id === selA) || null;
  const itemB = items.find(i => i.id === selB) || null;

  const [mode, setMode]       = React.useState("words");
  const [result, setRes]      = React.useState(null);
  const [err, setErr]         = React.useState("");
  const [view, setView]       = React.useState("text");   // "text" | "hex"
  const [syncScroll, setSync] = React.useState(true);
  const [pasteOpen, setPasteOpen]   = React.useState(false);
  const [pasteLabel, setPasteLabel] = React.useState("");
  const [pasteText, setPasteText]   = React.useState("");
  const fileRef = React.useRef(null);
  const paneARef = React.useRef(null);
  const paneBRef = React.useRef(null);

  // Re-diff whenever the selected pair or the comparison mode changes.
  // Items are append-only (never mutated after creation), so keying off the
  // ids is enough -- unrelated list edits (adding/removing other items)
  // don't need to re-trigger the backend call.
  React.useEffect(() => {
    if (!itemA || !itemB) { setRes(null); setErr(""); return; }
    let cancelled = false;
    setErr("");
    NL.actions.compareBlobs(mode, itemA.text, itemB.text)
      .then(r => { if (!cancelled) setRes(r); })
      .catch(e => { if (!cancelled) setErr(String(e && e.message ? e.message : e)); });
    return () => { cancelled = true; };
  }, [selA, selB, mode]);

  const addFile = (e) => {
    const f = e.target.files && e.target.files[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = () => dispatch({ type: "comparer-add", label: f.name, text: String(reader.result || "") });
    reader.readAsText(f);
    e.target.value = "";
  };
  const addPaste = () => {
    if (!pasteText) return;
    dispatch({ type: "comparer-add", label: pasteLabel || undefined, text: pasteText });
    setPasteText(""); setPasteLabel(""); setPasteOpen(false);
  };

  const onScrollA = () => {
    if (!syncScroll || !paneARef.current || !paneBRef.current) return;
    paneBRef.current.scrollTop = paneARef.current.scrollTop;
    paneBRef.current.scrollLeft = paneARef.current.scrollLeft;
  };
  const onScrollB = () => {
    if (!syncScroll || !paneARef.current || !paneBRef.current) return;
    paneARef.current.scrollTop = paneBRef.current.scrollTop;
    paneARef.current.scrollLeft = paneBRef.current.scrollLeft;
  };

  const Btn = ({ label, onClick, primary, disabled, title }) => (
    <button onClick={onClick} disabled={disabled} title={title}
      style={{
        background: primary ? "var(--accent)" : "transparent",
        color: disabled ? "var(--dim)" : primary ? "var(--bg)" : "var(--accent)",
        border: "1px solid " + (disabled ? "var(--line)" : "var(--accent)"),
        padding: "4px 10px", fontSize: "11px", fontFamily: "var(--ff-mono)",
        cursor: disabled ? "not-allowed" : "pointer", letterSpacing: "0.04em",
        textTransform: "uppercase",
      }}>{label}</button>
  );

  const area = {
    width: "100%", boxSizing: "border-box", background: "var(--pane)",
    color: "var(--text)", border: "1px solid var(--line)", borderRadius: 4,
    padding: 8, fontSize: "12px", fontFamily: "var(--ff-mono)",
    flex: 1, minHeight: 0, overflow: "auto", whiteSpace: "pre-wrap", wordBreak: "break-all",
  };
  const segStyle = (op, modified) => modified ? {
    background: "rgba(208,160,58,0.25)",
    color: "var(--warn, #d0a03a)",
    textDecoration: "none",
  } : ({
    background: op === "ins" ? "rgba(70,200,120,0.22)"
              : op === "del" ? "rgba(220,80,80,0.22)" : "transparent",
    color: op === "ins" ? "var(--ok, #6c8)" : op === "del" ? "var(--err)" : "var(--text)",
    textDecoration: op === "del" ? "line-through" : "none",
  });

  // Split the backend's single merged diff into two synced streams: the
  // left pane reconstructs A (common + deleted), the right reconstructs B
  // (common + inserted) -- same shape as Burp's two-pane Comparer result.
  // #313: an adjacent del+ins pair reads as one replacement, not an
  // unrelated delete next to an unrelated insert -- comparerMarkModified()
  // (pure helper, see below) flags both halves of such a pair so they can
  // render as a distinct "modified" color instead of plain red/green.
  const segs = comparerMarkModified((result && result.segments) || []);
  const streamA = segs.filter(s => s.op !== "ins");
  const streamB = segs.filter(s => s.op !== "del");
  const renderSeg = (s, i) => (
    <span key={i} style={segStyle(s.op, s.modified)}>
      {view === "hex" ? textToHexPairs(s.text) + "  " : s.text}
    </span>
  );

  const status = err ? err
    : !itemA || !itemB ? "pick an A and a B item to compare"
    : result
      ? (result.identical ? "identical"
         : ("+" + result.added + " / -" + result.removed + " · " + result.common + " common")
           + (result.truncated ? " · (truncated)" : ""))
      : "comparing…";

  return (
    <div style={{ padding: 14, display: "flex", flexDirection: "column",
                  gap: 10, height: "100%", minHeight: 0 }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}>
        <span style={{ fontSize: "11px", color: "var(--accent)", textTransform: "uppercase",
                       letterSpacing: "0.06em", fontWeight: 600 }}>Comparer</span>
        <span style={{ color: "var(--dim)", fontSize: "11px" }}>
          item list — paste, load, or send from another tool, then pick A/B — word / line / char level
        </span>
      </div>

      <div style={{ background: "var(--panel, var(--pane))", border: "1px solid var(--line)",
                    padding: 10, borderRadius: 4, display: "flex", gap: 6, flexWrap: "wrap",
                    alignItems: "center" }}>
        <div style={{ position: "relative", display: "inline-block" }}>
          <Btn label="+ paste item" onClick={() => setPasteOpen(o => !o)} />
          {pasteOpen && (
            <div onClick={e => e.stopPropagation()}
                 style={{
                   position: "absolute", top: "100%", left: 0, zIndex: 30,
                   background: "var(--pane)", border: "1px solid var(--accent)",
                   boxShadow: "0 8px 24px rgba(0,0,0,0.4)", padding: 8,
                   display: "flex", flexDirection: "column", gap: 6,
                   width: 320, marginTop: 4,
                 }}>
              <input value={pasteLabel} onChange={e => setPasteLabel(e.target.value)}
                     placeholder="label (optional)"
                     style={{ background: "var(--bg-deep)", color: "var(--text)", border: "1px solid var(--line)",
                              borderRadius: 4, padding: "4px 6px", fontSize: "11px", fontFamily: "var(--ff-mono)" }} />
              <textarea value={pasteText} onChange={e => setPasteText(e.target.value)}
                        placeholder="paste text…" spellCheck={false}
                        style={{ background: "var(--bg-deep)", color: "var(--text)", border: "1px solid var(--line)",
                                 borderRadius: 4, padding: 6, fontSize: "11px", fontFamily: "var(--ff-mono)",
                                 minHeight: 90, resize: "vertical" }} />
              <div style={{ display: "flex", gap: 6, justifyContent: "flex-end" }}>
                <Btn label="cancel" onClick={() => setPasteOpen(false)} />
                <Btn label="add" primary disabled={!pasteText} onClick={addPaste} />
              </div>
            </div>
          )}
        </div>
        <Btn label="load file" onClick={() => fileRef.current && fileRef.current.click()} />
        <input ref={fileRef} type="file" style={{ display: "none" }} onChange={addFile} />
        <Btn label="clear all" disabled={items.length === 0}
             onClick={() => dispatch({ type: "comparer-clear" })} />
        <span style={{ color: "var(--dim)", fontSize: "11px", marginLeft: 4 }}>
          {items.length} item{items.length === 1 ? "" : "s"}
        </span>
      </div>

      <div style={{ maxHeight: 130, overflow: "auto", border: "1px solid var(--line)", borderRadius: 4 }}>
        {items.length === 0 ? (
          <div style={{ padding: 10, color: "var(--dim)", fontSize: "11px" }}>
            no items yet — paste one, load a file, or use "Send to Comparer" in Proxy / Repeater
          </div>
        ) : items.map(it => (
          <div key={it.id} style={{
                 display: "flex", alignItems: "center", gap: 8, padding: "4px 8px",
                 borderBottom: "1px solid var(--line-soft)",
                 background: (it.id === selA || it.id === selB) ? "var(--pane)" : "transparent",
               }}>
            <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                           fontSize: "11px", color: "var(--text)" }}>{it.label}</span>
            <span style={{ color: "var(--dim)", fontSize: "10px" }}>{it.text.length}b</span>
            <Btn label="A" primary={it.id === selA} onClick={() => dispatch({ type: "comparer-select", slot: "A", id: it.id })} />
            <Btn label="B" primary={it.id === selB} onClick={() => dispatch({ type: "comparer-select", slot: "B", id: it.id })} />
            <span onClick={() => dispatch({ type: "comparer-remove", id: it.id })}
                  title="remove" style={{ cursor: "pointer", color: "var(--dim)", padding: "0 4px" }}>×</span>
          </div>
        ))}
      </div>

      <div style={{ background: "var(--pane)", border: "1px solid var(--line)",
                    padding: 10, borderRadius: 4, display: "flex", gap: 6, flexWrap: "wrap",
                    alignItems: "center" }}>
        <Btn label="words" primary={mode === "words"} onClick={() => setMode("words")} />
        <Btn label="lines" primary={mode === "lines"} onClick={() => setMode("lines")} />
        <Btn label="chars" primary={mode === "chars"} onClick={() => setMode("chars")} />
        <span style={{ width: 1, height: 18, background: "var(--line)", margin: "0 2px" }} />
        <Btn label="text" primary={view === "text"} onClick={() => setView("text")} />
        <Btn label="hex" primary={view === "hex"} onClick={() => setView("hex")} />
        <Btn label={syncScroll ? "sync: on" : "sync: off"} primary={syncScroll} onClick={() => setSync(s => !s)}
             title="Scroll both result panes together" />
        <span style={{ color: "var(--dim)", fontSize: "11px", marginLeft: 8 }}>{status}</span>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, flex: 1, minHeight: 0 }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 4, minHeight: 0 }}>
          <div style={{ fontSize: "10px", color: "var(--dim)", textTransform: "uppercase" }}>
            A {itemA ? "· " + itemA.label : ""}
          </div>
          <div ref={paneARef} onScroll={onScrollA} style={area}>
            {segs.length ? streamA.map(renderSeg)
              : <span style={{ color: "var(--dim)" }}>result appears here — red = removed from A</span>}
          </div>
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 4, minHeight: 0 }}>
          <div style={{ fontSize: "10px", color: "var(--dim)", textTransform: "uppercase" }}>
            B {itemB ? "· " + itemB.label : ""}
          </div>
          <div ref={paneBRef} onScroll={onScrollB} style={area}>
            {segs.length ? streamB.map(renderSeg)
              : <span style={{ color: "var(--dim)" }}>result appears here — green = added in B</span>}
          </div>
        </div>
      </div>
    </div>
  );
}

function InspectorTab() {
  // Structured view of a raw request or response via /api/inspect. The whole
  // backend (inspector_logic: request/response line, headers, cookies, query
  // and body params, and JWT decode) already existed with no UI -- this is the
  // tab that makes it reachable.
  const [mode, setMode] = React.useState("parse");   // "parse" | "jwt"
  const [raw, setRaw]   = React.useState("");
  const [kind, setKind] = React.useState("");   // "" auto | request | response
  const [view, setView] = React.useState(null);
  const [detected, setDetected] = React.useState("");
  const [err, setErr]   = React.useState("");

  const run = async () => {
    setErr("");
    try {
      const r = await NL.actions.inspect(raw, kind);
      if (r && r.ok) { setView(r.view || {}); setDetected(r.kind || ""); }
      else { setView(null); setErr((r && r.error) || "inspect failed"); }
    } catch (e) { setView(null); setErr(String(e && e.message ? e.message : e)); }
  };

  const area = {
    width: "100%", boxSizing: "border-box", background: "var(--bg-deep)",
    color: "var(--text)", border: "1px solid var(--line)", borderRadius: 4,
    padding: 8, fontSize: "12px", fontFamily: "var(--ff-mono)", resize: "none",
    flex: 1, minHeight: 0, whiteSpace: "pre", overflow: "auto",
  };
  const Btn = ({ label, onClick, primary }) => (
    <button onClick={onClick} style={{
      background: primary ? "var(--accent)" : "transparent",
      color: primary ? "var(--bg)" : "var(--accent)",
      border: "1px solid var(--accent)", padding: "4px 10px", fontSize: "11px",
      fontFamily: "var(--ff-mono)", cursor: "pointer", letterSpacing: "0.04em",
      textTransform: "uppercase",
    }}>{label}</button>
  );
  const th = { textAlign: "left", color: "var(--dim)", fontWeight: 500, padding: "2px 10px 2px 0", whiteSpace: "nowrap", verticalAlign: "top" };
  const td = { padding: "2px 10px 2px 0", wordBreak: "break-all", color: "var(--text)" };
  const Section = ({ title, children }) => (
    <div style={{ marginBottom: 12 }}>
      <div style={{ fontSize: "10px", color: "var(--accent)", textTransform: "uppercase",
                    letterSpacing: "0.08em", marginBottom: 4 }}>{title}</div>
      {children}
    </div>
  );
  const KV = ({ rows }) => (
    <table style={{ borderCollapse: "collapse", fontSize: "12px", fontFamily: "var(--ff-mono)", width: "100%" }}>
      <tbody>{(rows || []).map((r, i) => (
        <tr key={i}><td style={th}>{r.name}</td><td style={td}>{String(r.value == null ? "" : r.value)}</td></tr>
      ))}</tbody>
    </table>
  );

  const isResp = view && (view.status !== undefined || view.reason !== undefined) && view.method === undefined;

  return (
    <div style={{ padding: 14, display: "flex", flexDirection: "column", gap: 10, height: "100%", minHeight: 0 }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}>
        <span style={{ fontSize: "11px", color: "var(--accent)", textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600 }}>Inspector</span>
        <span style={{ color: "var(--dim)", fontSize: "11px" }}>
          {mode === "parse" ? "structured view of a raw request or response — headers, cookies, params, JWTs" : "offline JWT analyze/forge + a live acceptance test against a target"}
        </span>
        <span style={{ flex: 1 }} />
        <Btn label="parse" primary={mode === "parse"} onClick={() => setMode("parse")} />
        <Btn label="jwt toolkit" primary={mode === "jwt"} onClick={() => setMode("jwt")} />
      </div>

      {mode === "jwt" ? <JwtToolkit /> : (
      <React.Fragment>
      <div style={{ display: "flex", flexDirection: "column", gap: 6, minHeight: 0, height: "40%" }}>
        <div style={{ fontSize: "10px", color: "var(--dim)", textTransform: "uppercase", letterSpacing: "0.06em" }}>RAW HTTP</div>
        <textarea style={area} value={raw} placeholder={"paste a raw request or response…\nGET /path?q=1 HTTP/1.1\nHost: example.com\nCookie: token=eyJ..."}
                  onChange={e => setRaw(e.target.value)} spellCheck={false} />
      </div>

      <div style={{ background: "var(--pane)", border: "1px solid var(--line)", padding: 10, borderRadius: 4, display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
        <Btn label="inspect" primary onClick={run} />
        {["", "request", "response"].map(k => (
          <Btn key={k || "auto"} label={k || "auto"} primary={kind === k} onClick={() => setKind(k)} />
        ))}
        <span style={{ color: "var(--dim)", fontSize: "11px", marginLeft: 8 }}>
          {err ? err : view ? ("parsed as " + (detected || (isResp ? "response" : "request"))) : "paste HTTP and inspect"}
        </span>
      </div>

      <div style={{ flex: 1, overflow: "auto", background: "var(--pane)", border: "1px solid var(--line)", borderRadius: 4, padding: 12, minHeight: 0 }}>
        {!view ? <span style={{ color: "var(--dim)", fontSize: "12px" }}>structured breakdown appears here</span> : isResp ? (
          <div>
            <Section title="Status line">
              <KV rows={[{ name: "version", value: view.version }, { name: "status", value: view.status }, { name: "reason", value: view.reason }, { name: "content-type", value: view.contentType }, { name: "body size", value: view.bodySize }]} />
            </Section>
            {view.headers && view.headers.length ? <Section title={"Headers (" + view.headers.length + ")"}><KV rows={view.headers} /></Section> : null}
            {view.setCookies && view.setCookies.length ? <Section title={"Set-Cookie (" + view.setCookies.length + ")"}>
              <table style={{ borderCollapse: "collapse", fontSize: "12px", fontFamily: "var(--ff-mono)", width: "100%" }}><tbody>
                {view.setCookies.map((c, i) => (<tr key={i}><td style={th}>{c.name}</td><td style={td}>{c.value}</td><td style={{ ...td, color: "var(--dim)" }}>{c.attributes}</td></tr>))}
              </tbody></table></Section> : null}
            {view.jwts && view.jwts.length ? <Section title={"JWTs decoded (" + view.jwts.length + ")"}><JwtList jwts={view.jwts} /></Section> : null}
            {view.bodyPreview ? <Section title="Body preview"><pre style={{ margin: 0, fontSize: "12px", whiteSpace: "pre-wrap", wordBreak: "break-all", color: "var(--text-2)" }}>{view.bodyPreview}</pre></Section> : null}
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
            {view.jwts && view.jwts.length ? <Section title={"JWTs decoded (" + view.jwts.length + ")"}><JwtList jwts={view.jwts} /></Section> : null}
          </div>
        )}
      </div>
      </React.Fragment>
      )}
    </div>
  );
}

function JwtList({ jwts }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {jwts.map((j, i) => (
        <div key={i} style={{ border: "1px solid var(--line)", borderRadius: 4, padding: 8 }}>
          <div style={{ fontSize: "11px", color: "var(--accent)", marginBottom: 4 }}>
            {j.where} <span style={{ color: "var(--dim)" }}>· alg={j.alg || "?"} {j.typ ? "· typ=" + j.typ : ""}</span>
          </div>
          <pre style={{ margin: 0, fontSize: "11.5px", whiteSpace: "pre-wrap", wordBreak: "break-all", color: "var(--text-2)" }}>
            {JSON.stringify(j.payload == null ? { header: j.header } : { header: j.header, payload: j.payload }, null, 2)}
          </pre>
        </div>
      ))}
    </div>
  );
}

function JwtToolkit() {
  // Offline analyze/forge (JwtTool, /api/jwt/analyze + /api/jwt/forge) and a
  // live acceptance test (JwtProbe, /api/jwt/test) against a real target --
  // all three were API-only with no UI. A single shared token box feeds all
  // three actions since forge/test both start from an already-decoded token.
  const [token, setToken]       = React.useState("");
  const [wordlist, setWordlist] = React.useState("");

  const [analysis, setAnalysis]   = React.useState(null);
  const [analyzeErr, setAnalyzeErr] = React.useState("");
  const [busyA, setBusyA]         = React.useState(false);

  const [attack, setAttack]     = React.useState("none");
  const [secret, setSecret]     = React.useState("");
  const [claimsText, setClaimsText] = React.useState("");
  const [forged, setForged]     = React.useState("");
  const [forgeErr, setForgeErr] = React.useState("");
  const [busyF, setBusyF]       = React.useState(false);
  const [copied, setCopied]     = React.useState(false);

  const [testUrl, setTestUrl]     = React.useState("");
  const [location, setLocation]   = React.useState("");
  const [testMethod, setTestMethod] = React.useState("");
  const [testRes, setTestRes]     = React.useState(null);
  const [testErr, setTestErr]     = React.useState("");
  const [busyT, setBusyT]         = React.useState(false);

  const words = () => wordlist.split("\n").map(s => s.trim()).filter(Boolean);

  const doAnalyze = async () => {
    if (!token.trim()) { setAnalyzeErr("paste a token first"); return; }
    setAnalyzeErr(""); setBusyA(true); setAnalysis(null);
    try {
      const w = words();
      const r = await NL.actions.jwtAnalyze(token.trim(), w.length ? w : undefined);
      if (r && r.ok) setAnalysis(r); else setAnalyzeErr((r && r.error) || "analyze failed");
    } catch (e) { setAnalyzeErr(String(e && e.message ? e.message : e)); }
    finally { setBusyA(false); }
  };

  const doForge = async () => {
    if (!token.trim()) { setForgeErr("paste a token first"); return; }
    let claims;
    if (claimsText.trim()) {
      try { claims = JSON.parse(claimsText); }
      catch (e) { setForgeErr("claim overrides must be valid JSON"); return; }
    }
    setForgeErr(""); setBusyF(true); setForged(""); setCopied(false);
    try {
      const r = await NL.actions.jwtForge(token.trim(), attack, attack === "none" ? undefined : secret, claims);
      if (r && r.ok) setForged(r.token); else setForgeErr((r && r.error) || "forge failed");
    } catch (e) { setForgeErr(String(e && e.message ? e.message : e)); }
    finally { setBusyF(false); }
  };

  const doTest = async () => {
    if (!testUrl.trim()) { setTestErr("enter a target URL"); return; }
    if (!token.trim()) { setTestErr("paste the currently-valid token to calibrate against"); return; }
    setTestErr(""); setBusyT(true); setTestRes(null);
    try {
      const opts = {};
      if (location.trim()) opts.location = location.trim();
      if (testMethod) opts.method = testMethod;
      const w = words();
      if (w.length) opts.wordlist = w;
      const r = await NL.actions.jwtTest(testUrl.trim(), token.trim(), opts);
      if (r && r.ok !== false) setTestRes(r); else setTestErr((r && r.error) || "test failed");
    } catch (e) { setTestErr(String(e && e.message ? e.message : e)); }
    finally { setBusyT(false); }
  };

  const inp = {
    background: "var(--bg-deep)", color: "var(--text)", border: "1px solid var(--line)",
    borderRadius: 4, padding: "5px 8px", fontSize: "12px", fontFamily: "var(--ff-mono)",
  };
  const Btn = ({ label, onClick, primary, disabled }) => (
    <button onClick={onClick} disabled={disabled} style={{
      background: primary ? "var(--accent)" : "transparent",
      color: disabled ? "var(--dim)" : primary ? "var(--bg)" : "var(--accent)",
      border: "1px solid " + (disabled ? "var(--line)" : "var(--accent)"), padding: "4px 10px", fontSize: "11px",
      fontFamily: "var(--ff-mono)", cursor: disabled ? "default" : "pointer", letterSpacing: "0.04em",
      textTransform: "uppercase",
    }}>{label}</button>
  );
  const Section = ({ title, children }) => (
    <div style={{ background: "var(--pane)", border: "1px solid var(--line)", borderRadius: 4, padding: 10, display: "flex", flexDirection: "column", gap: 8 }}>
      <div style={{ fontSize: "10px", color: "var(--accent)", textTransform: "uppercase", letterSpacing: "0.08em" }}>{title}</div>
      {children}
    </div>
  );
  const sevColor = (s) => ({
    critical: "var(--err)", high: "#ea580c", medium: "#d97706",
    low: "#3f8f29", info: "var(--dim)",
  }[String(s || "").toLowerCase()] || "var(--text-2)");

  return (
    <div style={{ flex: 1, overflow: "auto", display: "flex", flexDirection: "column", gap: 10, minHeight: 0 }}>
      <Section title="Token">
        <textarea value={token} onChange={e => setToken(e.target.value)}
                  placeholder="paste a captured JWT (header.payload.signature)…"
                  spellCheck={false}
                  style={{ ...inp, minHeight: 46, resize: "vertical", whiteSpace: "pre-wrap", wordBreak: "break-all" }} />
        <textarea value={wordlist} onChange={e => setWordlist(e.target.value)}
                  placeholder="HS* secret wordlist, one per line (optional — used by analyze's brute-force and test's weak-secret attack)"
                  spellCheck={false} style={{ ...inp, minHeight: 40, resize: "vertical" }} />
      </Section>

      <Section title="Analyze (offline)">
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <Btn label={busyA ? "analyzing…" : "analyze"} primary disabled={busyA} onClick={doAnalyze} />
          <span style={{ color: "var(--err)", fontSize: "11px" }}>{analyzeErr}</span>
        </div>
        {analysis && (
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <div style={{ fontSize: "11px", fontFamily: "var(--ff-mono)", color: "var(--dim)" }}>
              alg <span style={{ color: "var(--text)" }}>{analysis.alg || "?"}</span>
              {analysis.typ ? <span> · typ <span style={{ color: "var(--text)" }}>{analysis.typ}</span></span> : null}
              {analysis.kid ? <span> · kid <span style={{ color: "var(--text)" }}>{analysis.kid}</span></span> : null}
            </div>
            {(analysis.weaknesses || []).map((w, i) => (
              <div key={i} style={{ border: "1px solid var(--line)", borderRadius: 4, padding: "4px 8px", fontSize: "11.5px", fontFamily: "var(--ff-mono)" }}>
                <span style={{ color: sevColor(w.severity), fontWeight: 600, textTransform: "uppercase" }}>{w.severity}</span>
                {"  "}<span style={{ color: "var(--accent)" }}>{w.id}</span>
                <div style={{ color: "var(--text-2)" }}>{w.detail}</div>
              </div>
            ))}
            {!analysis.weaknesses || !analysis.weaknesses.length ? <span style={{ color: "var(--dim)", fontSize: "11px" }}>no weaknesses flagged</span> : null}
            {"secretRecovered" in analysis && (
              <div style={{ fontSize: "11.5px", fontFamily: "var(--ff-mono)" }}>
                {analysis.secretRecovered
                  ? <span style={{ color: "var(--err)" }}>HS* secret recovered from wordlist: <b>{analysis.secret}</b></span>
                  : <span style={{ color: "var(--dim)" }}>secret not found in wordlist</span>}
              </div>
            )}
            <pre style={{ margin: 0, fontSize: "11px", whiteSpace: "pre-wrap", wordBreak: "break-all", color: "var(--text-2)" }}>
              {JSON.stringify({ header: analysis.header, payload: analysis.payload }, null, 2)}
            </pre>
          </div>
        )}
      </Section>

      <Section title="Forge">
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <select value={attack} onChange={e => setAttack(e.target.value)} style={{ ...inp, flex: "0 0 140px" }}>
            <option value="none">alg:none bypass</option>
            <option value="hs256">re-sign HS256</option>
          </select>
          {attack !== "none" && (
            <input value={secret} onChange={e => setSecret(e.target.value)} placeholder="HMAC secret (or PEM public key, for RS256→HS256 confusion)"
                   style={{ ...inp, flex: "1 1 260px" }} spellCheck={false} />
          )}
          <Btn label={busyF ? "forging…" : "forge"} primary disabled={busyF} onClick={doForge} />
        </div>
        <textarea value={claimsText} onChange={e => setClaimsText(e.target.value)}
                  placeholder={'claim overrides as JSON, optional — e.g. {"role":"admin"}'}
                  spellCheck={false} style={{ ...inp, minHeight: 34, resize: "vertical" }} />
        <span style={{ color: "var(--err)", fontSize: "11px" }}>{forgeErr}</span>
        {forged && (
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <textarea readOnly value={forged} style={{ ...inp, minHeight: 46, resize: "vertical", whiteSpace: "pre-wrap", wordBreak: "break-all" }} />
            <div>
              <Btn label={copied ? "copied" : "copy"} onClick={() => {
                navigator.clipboard && navigator.clipboard.writeText(forged).then(() => {
                  setCopied(true); setTimeout(() => setCopied(false), 1200);
                });
              }} />
            </div>
          </div>
        )}
      </Section>

      <Section title="Active test (live acceptance check)">
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <input value={testUrl} onChange={e => setTestUrl(e.target.value)} placeholder="https://target/protected/endpoint"
                 style={{ ...inp, flex: "1 1 260px" }} spellCheck={false} />
          <select value={testMethod} onChange={e => setTestMethod(e.target.value)} style={{ ...inp, flex: "0 0 90px" }}>
            <option value="">auto</option><option value="GET">GET</option><option value="POST">POST</option>
          </select>
          <input value={location} onChange={e => setLocation(e.target.value)} placeholder="location (optional — e.g. cookie:session, header:X-Auth-Token; default fans out)"
                 style={{ ...inp, flex: "1 1 220px" }} spellCheck={false} />
          <Btn label={busyT ? "testing…" : "test"} primary disabled={busyT} onClick={doTest} />
        </div>
        <span style={{ color: "var(--err)", fontSize: "11px" }}>{testErr}</span>
        {testRes && (
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <div style={{ fontSize: "12px", fontFamily: "var(--ff-mono)" }}>
              <span style={{ color: testRes.vulnerable ? "var(--err)" : "var(--ok, #6c8)", fontWeight: 600 }}>
                {testRes.vulnerable ? "VULNERABLE" : "no accepted forgery"}
              </span>
              <span style={{ color: "var(--dim)" }}>
                {"  · calibrated=" + String(testRes.calibrated) + " · auth=" + testRes.authStatus + " · reject=" + testRes.rejectStatus + " · requests=" + testRes.requestsSent}
              </span>
            </div>
            {(testRes.hits || []).map((h, i) => (
              <div key={i} style={{ border: "1px solid var(--line)", borderRadius: 4, padding: "4px 8px", fontSize: "11.5px", fontFamily: "var(--ff-mono)" }}>
                <span style={{ color: "var(--err)", fontWeight: 600 }}>{h.attack}</span>
                {h.carrier ? <span style={{ color: "var(--dim)" }}> · {h.carrier}</span> : null}
                <div style={{ color: "var(--text-2)" }}>{h.detail}</div>
              </div>
            ))}
          </div>
        )}
      </Section>
    </div>
  );
}

function ProbeTab() {
  // Active per-URL probes whose backends existed with no UI (all four sink
  // their findings into Issues AND return them here): tech/CVE fingerprint,
  // security-header/CSP audit, WAF detection, and client-side secret scan.
  const [url, setUrl]     = React.useState("");
  const [kind, setKind]   = React.useState("");
  const [res, setRes]     = React.useState(null);
  const [busy, setBusy]   = React.useState(false);
  const [err, setErr]     = React.useState("");

  const run = async (k, fn) => {
    if (!url) { setErr("enter a URL"); return; }
    setKind(k); setErr(""); setBusy(true); setRes(null);
    try {
      const r = await fn(url);
      if (r && r.ok === false && r.error) { setErr(r.error); setRes(null); }
      else setRes(r);
    } catch (e) { setErr(String(e && e.message ? e.message : e)); }
    finally { setBusy(false); }
  };

  const sevColor = (s) => ({
    critical: "var(--err)", high: "#ea580c", medium: "#d97706",
    low: "#3f8f29", info: "var(--dim)",
  }[String(s || "").toLowerCase()] || "var(--text-2)");
  const th = { textAlign: "left", color: "var(--dim)", fontWeight: 500, padding: "3px 12px 3px 0", whiteSpace: "nowrap", verticalAlign: "top" };
  const td = { padding: "3px 12px 3px 0", wordBreak: "break-word", color: "var(--text)", verticalAlign: "top" };
  const Btn = ({ label, k, fn }) => (
    <button onClick={() => run(k, fn)} disabled={busy} style={{
      background: kind === k ? "var(--accent)" : "transparent",
      color: busy ? "var(--dim)" : kind === k ? "var(--bg)" : "var(--accent)",
      border: "1px solid var(--accent)", padding: "4px 10px", fontSize: "11px",
      fontFamily: "var(--ff-mono)", cursor: busy ? "wait" : "pointer",
      letterSpacing: "0.04em", textTransform: "uppercase",
    }}>{label}</button>
  );
  const Table = ({ cols, rows, cell }) => (
    <table style={{ borderCollapse: "collapse", fontSize: "12px", fontFamily: "var(--ff-mono)", width: "100%" }}>
      <thead><tr>{cols.map((c, i) => <th key={i} style={th}>{c}</th>)}</tr></thead>
      <tbody>{(rows || []).map((r, i) => <tr key={i}>{cell(r).map((v, j) => <td key={j} style={td}>{v}</td>)}</tr>)}</tbody>
    </table>
  );
  const Section = ({ title, children }) => (
    <div style={{ marginBottom: 12 }}>
      <div style={{ fontSize: "10px", color: "var(--accent)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 4 }}>{title}</div>
      {children}
    </div>
  );

  const render = () => {
    if (!res) return <span style={{ color: "var(--dim)", fontSize: "12px" }}>results appear here — and are also added to Issues</span>;
    if (kind === "fingerprint") return (
      <div>
        <div style={{ color: "var(--dim)", fontSize: "11px", marginBottom: 8 }}>HTTP {res.status} · {res.techCount || 0} technologies</div>
        {res.tech && res.tech.length ? <Section title="Technologies"><Table cols={["name", "version", "source"]} rows={res.tech} cell={t => [t.name, t.version || "—", <span style={{ color: "var(--dim)" }}>{t.source}</span>]} /></Section> : <div style={{ color: "var(--dim)", fontSize: "12px" }}>no technologies fingerprinted</div>}
        {res.cves && res.cves.length ? <Section title={"Correlated CVEs (" + res.cves.length + ")"}><Table cols={["cve", "cvss", "tech", "summary"]} rows={res.cves} cell={c => [<span style={{ color: "var(--err)" }}>{c.cveId}</span>, c.cvss, c.tech, c.summary]} /></Section> : null}
      </div>
    );
    if (kind === "headers") return (
      <div>
        <div style={{ color: "var(--dim)", fontSize: "11px", marginBottom: 8 }}>HTTP {res.status} · CSP: {res.hasCsp ? "present" : "absent"}{res.reportOnlyOnly ? " (report-only)" : ""} · {res.findingCount || 0} findings</div>
        {res.findings && res.findings.length ? <Table cols={["severity", "issue", "detail"]} rows={res.findings} cell={f => [<span style={{ color: sevColor(f.severity) }}>{f.severity}</span>, f.title, <span style={{ color: "var(--text-2)" }}>{f.detail}</span>]} /> : <div style={{ color: "var(--dim)", fontSize: "12px" }}>no header issues found</div>}
      </div>
    );
    if (kind === "waf") return (
      <div>
        <div style={{ color: "var(--dim)", fontSize: "11px", marginBottom: 8 }}>{res.host} · HTTP {res.status} · {res.detectionCount || 0} detections</div>
        {res.detections && res.detections.length ? <Table cols={["name", "kind", "evidence"]} rows={res.detections} cell={d => [<span style={{ color: "var(--accent)" }}>{d.name}</span>, d.kind, <span style={{ color: "var(--text-2)" }}>{d.evidence}</span>]} /> : <div style={{ color: "var(--dim)", fontSize: "12px" }}>no WAF detected</div>}
      </div>
    );
    if (kind === "secrets") return (
      <div>
        <div style={{ color: "var(--dim)", fontSize: "11px", marginBottom: 8 }}>{res.resourcesScanned || 0} resources · {res.requestsSent || 0} requests · {res.hitCount || 0} hits</div>
        {res.hits && res.hits.length ? <Table cols={["severity", "type", "location", "masked"]} rows={res.hits} cell={h => [<span style={{ color: sevColor(h.severity) }}>{h.severity}</span>, h.type, <span style={{ color: "var(--text-2)", wordBreak: "break-all" }}>{h.location}</span>, <span style={{ color: "var(--dim)" }}>{h.masked}</span>]} /> : <div style={{ color: "var(--dim)", fontSize: "12px" }}>no secrets found in client code</div>}
      </div>
    );
    if (kind === "graphqlSchema") {
      if (res.ok === true && res.introspectionEnabled === false) return (
        <div style={{ color: "var(--dim)", fontSize: "12px" }}>introspection disabled or unreachable{res.note ? " — " + res.note : ""}</div>
      );
      return (
        <div>
          <div style={{ color: "var(--dim)", fontSize: "11px", marginBottom: 8 }}>introspection enabled · {res.types || 0} types · {res.fields || 0} fields · mutation root: {res.mutationType || "—"}</div>
          {res.dangerousMutations && res.dangerousMutations.length ? <Section title={"Dangerous mutations (" + res.dangerousMutations.length + ")"}><Table cols={["mutation"]} rows={res.dangerousMutations} cell={m => [<span style={{ color: "var(--err)" }}>{m}</span>]} /></Section> : <div style={{ color: "var(--dim)", fontSize: "12px", marginBottom: 8 }}>no obviously dangerous mutation names found</div>}
          {res.sensitiveFields && res.sensitiveFields.length ? <Section title={"Sensitive fields (" + res.sensitiveFields.length + ")"}><Table cols={["type.field"]} rows={res.sensitiveFields} cell={f => [<span style={{ color: "var(--err)" }}>{f}</span>]} /></Section> : null}
        </div>
      );
    }
    if (kind === "graphqlProbe") return (
      <div style={{ color: "var(--dim)", fontSize: "12px" }}>
        {res.queued !== undefined
          ? "queued " + res.queued + " active GraphQL probe(s) (introspection / field-suggestion / alias-amplification / depth-bypass / batch-bypass) against " + res.target + " — findings stream into Issues"
          : (res.error || "no response")}
      </div>
    );
    return null;
  };

  return (
    <div style={{ padding: 14, display: "flex", flexDirection: "column", gap: 10, height: "100%", minHeight: 0 }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}>
        <span style={{ fontSize: "11px", color: "var(--accent)", textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600 }}>Probe</span>
        <span style={{ color: "var(--dim)", fontSize: "11px" }}>active per-URL checks — tech/CVE, security headers, WAF, client-side secrets, GraphQL (also sent to Issues)</span>
      </div>
      <div style={{ background: "var(--pane)", border: "1px solid var(--line)", padding: 10, borderRadius: 4, display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <input value={url} onChange={e => setUrl(e.target.value)} placeholder="https://target.example.com/path"
               onKeyDown={e => { if (e.key === "Enter" && kind) run(kind, { fingerprint: NL.actions.fingerprintUrl, headers: NL.actions.auditHeaders, waf: NL.actions.detectWaf, secrets: NL.actions.scanSecrets, graphqlSchema: NL.actions.graphqlSchema, graphqlProbe: NL.actions.graphqlProbe }[kind]); }}
               style={{ flex: "1 1 320px", minWidth: 220, background: "var(--bg-deep)", color: "var(--text)", border: "1px solid var(--line)", borderRadius: 4, padding: "5px 8px", fontSize: "12px", fontFamily: "var(--ff-mono)" }} spellCheck={false} />
        <Btn label="fingerprint" k="fingerprint" fn={NL.actions.fingerprintUrl} />
        <Btn label="header audit" k="headers" fn={NL.actions.auditHeaders} />
        <Btn label="waf detect" k="waf" fn={NL.actions.detectWaf} />
        <Btn label="secret scan" k="secrets" fn={NL.actions.scanSecrets} />
        <Btn label="graphql schema" k="graphqlSchema" fn={NL.actions.graphqlSchema} />
        <Btn label="graphql probe" k="graphqlProbe" fn={NL.actions.graphqlProbe} />
        <span style={{ color: err ? "var(--err)" : "var(--dim)", fontSize: "11px" }}>{busy ? "probing…" : err || ""}</span>
      </div>
      <div style={{ flex: 1, overflow: "auto", background: "var(--pane)", border: "1px solid var(--line)", borderRadius: 4, padding: 12, minHeight: 0 }}>
        {render()}
      </div>
    </div>
  );
}

// Pure: token-count / shortest / longest / mean-length summary shown BEFORE
// the corpus is sent to /api/sequencer/analyze -- Burp shows this in the
// Manual Load pane before the user hits "Analyze now".
function sequencerSampleSummary(tokens) {
  if (!tokens || !tokens.length) return null;
  let min = Infinity, max = 0, total = 0;
  for (const t of tokens) {
    const len = t.length;
    if (len < min) min = len;
    if (len > max) max = len;
    total += len;
  }
  return {
    n: tokens.length,
    minLen: min,
    maxLen: max,
    meanLen: Math.round((total / tokens.length) * 10) / 10,
  };
}

// Escape text pulled from token data (e.g. lcs.longest is a literal substring
// of the analyzed corpus) before it lands inside a generated HTML/XML report --
// the corpus is untrusted input, so a token like "<script>" or "]]>" must never
// be interpreted as markup by whatever opens the exported file.
function sequencerReportEscape(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

// #185 "Sequencer analysis report export": build a standalone HTML report from
// an /api/sequencer/analyze result, the same fields SequencerTab already
// renders (Section blocks below), so the export can never drift from what the
// operator sees on screen. Pure: no DOM, no I/O -- the caller wraps this in a
// Blob download.
function sequencerReportHtml(result, tokenCount) {
  const esc = sequencerReportEscape;
  if (!result || result.verdict === "no-data") {
    return "<!doctype html><html><head><meta charset=\"utf-8\"><title>Nullock Sequencer report</title></head>"
      + "<body><h1>Nullock Sequencer report</h1><p>No tokens analyzed.</p></body></html>";
  }
  const sh = result.shannon || {}, cls = result.charClass || {}, ham = result.hamming || {};
  const lcs = result.lcs || {}, seq = result.sequential || {}, pos = result.positional || {}, bit = result.bitLevel || {};
  const fmt = (v, d) => (v == null ? "—" : (typeof v === "number" ? v.toFixed(d == null ? 3 : d) : esc(v)));
  const pct = (v) => (v == null ? "—" : (v * 100).toFixed(0) + "%");
  let rows = "";
  rows += "<tr><th>Verdict</th><td>" + esc(result.verdict) + " (score " + esc(result.score) + ")</td></tr>";
  rows += "<tr><th>Tokens analyzed</th><td>" + esc(result.n != null ? result.n : tokenCount) + "</td></tr>";
  rows += "<tr><th>Distinct tokens</th><td>" + esc(result.distinctTokens != null ? result.distinctTokens : "—") + "</td></tr>";
  rows += "<tr><th>Average length</th><td>" + esc(result.avgLen) + "</td></tr>";
  rows += "<tr><th>Shannon entropy (bits/byte)</th><td>" + fmt(sh.bitsPerByte, 3) + "</td></tr>";
  rows += "<tr><th>Shannon alphabet verdict</th><td>" + esc(sh.verdict) + "</td></tr>";
  rows += "<tr><th>Effective bits/token</th><td>" + fmt(sh.effectiveBitsPerToken, 1) + "</td></tr>";
  rows += "<tr><th>Character class ratios</th><td>alpha " + pct(cls.alphaRatio) + ", digit " + pct(cls.digitRatio)
        + ", hex " + pct(cls.hexRatio) + ", upper " + pct(cls.upperRatio) + ", lower " + pct(cls.lowerRatio)
        + ", special " + pct(cls.specialRatio) + "</td></tr>";
  rows += "<tr><th>Hamming distance (consecutive)</th><td>min " + esc(ham.min) + ", avg " + esc(ham.avg) + ", max " + esc(ham.max) + "</td></tr>";
  rows += "<tr><th>Longest common substring</th><td>length " + esc(lcs.length)
        + (lcs.longest ? ", “" + esc(lcs.longest) + "”" : "") + "</td></tr>";
  rows += "<tr><th>Sequential / counter detection</th><td>sequential " + esc(!!seq.looksSequential)
        + ", monotonic " + esc(!!seq.looksMonotonic)
        + (seq.looksSequential ? ", delta " + esc(seq.delta) : "") + "</td></tr>";
  rows += "<tr><th>Per-position entropy</th><td>" + (pos.applicable
        ? "width " + esc(pos.width) + ", sampled " + esc(pos.n) + ", weak columns " + esc(pos.weakColumns) + ", biased " + esc(!!pos.biased)
        : "not applicable — needs ≥20 tokens of the same width") + "</td></tr>";
  rows += "<tr><th>Bit-level tests</th><td>" + (bit.applicable
        ? "scheme " + esc(bit.scheme) + ", bits " + esc(bit.bits)
          + ", monobit p " + fmt(bit.monobit && bit.monobit.pValue, 3)
          + ", two-bit χ² " + fmt(bit.twoBit && bit.twoBit.chiSquare, 2)
          + ", serial r " + fmt(bit.serialCorrelation && bit.serialCorrelation.r, 3)
        : "not applicable — needs ≥20 tokens that are all hex or all base64") + "</td></tr>";
  return "<!doctype html><html><head><meta charset=\"utf-8\"><title>Nullock Sequencer report</title>"
    + "<style>body{font-family:monospace;margin:24px;color:#111}table{border-collapse:collapse}"
    + "th{text-align:left;padding:4px 12px 4px 0;color:#555}td{padding:4px 0}"
    + "h1{font-size:16px}</style></head><body>"
    + "<h1>Nullock Sequencer analysis report</h1>"
    + "<p>Generated client-side from the token corpus currently loaded in the Sequencer tab.</p>"
    + "<table>" + rows + "</table></body></html>";
}

// XML twin of sequencerReportHtml -- same field set, Burp's own Sequencer
// export offers both formats.
function sequencerReportXml(result, tokenCount) {
  const esc = sequencerReportEscape;
  if (!result || result.verdict === "no-data") {
    return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<sequencerReport><status>no-data</status></sequencerReport>";
  }
  const sh = result.shannon || {}, cls = result.charClass || {}, ham = result.hamming || {};
  const lcs = result.lcs || {}, seq = result.sequential || {}, pos = result.positional || {}, bit = result.bitLevel || {};
  const n = (v) => (v == null ? "" : esc(v));
  let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<sequencerReport>";
  xml += "<summary verdict=\"" + n(result.verdict) + "\" score=\"" + n(result.score) + "\" tokensAnalyzed=\""
       + n(result.n != null ? result.n : tokenCount) + "\" distinctTokens=\"" + n(result.distinctTokens)
       + "\" avgLen=\"" + n(result.avgLen) + "\"/>";
  xml += "<shannon bitsPerByte=\"" + n(sh.bitsPerByte) + "\" verdict=\"" + n(sh.verdict)
       + "\" variableLen=\"" + n(sh.variableLen) + "\" effectiveBitsPerToken=\"" + n(sh.effectiveBitsPerToken) + "\"/>";
  xml += "<charClass alphaRatio=\"" + n(cls.alphaRatio) + "\" digitRatio=\"" + n(cls.digitRatio)
       + "\" hexRatio=\"" + n(cls.hexRatio) + "\" upperRatio=\"" + n(cls.upperRatio)
       + "\" lowerRatio=\"" + n(cls.lowerRatio) + "\" specialRatio=\"" + n(cls.specialRatio) + "\"/>";
  xml += "<hamming min=\"" + n(ham.min) + "\" avg=\"" + n(ham.avg) + "\" max=\"" + n(ham.max) + "\"/>";
  xml += "<longestCommonSubstring length=\"" + n(lcs.length) + "\">" + (lcs.longest ? esc(lcs.longest) : "") + "</longestCommonSubstring>";
  xml += "<sequential looksSequential=\"" + n(!!seq.looksSequential) + "\" looksMonotonic=\"" + n(!!seq.looksMonotonic)
       + "\" delta=\"" + n(seq.delta) + "\"/>";
  xml += pos.applicable
    ? "<positional applicable=\"true\" width=\"" + n(pos.width) + "\" sampled=\"" + n(pos.n)
        + "\" weakColumns=\"" + n(pos.weakColumns) + "\" biased=\"" + n(!!pos.biased) + "\"/>"
    : "<positional applicable=\"false\"/>";
  xml += bit.applicable
    ? "<bitLevel applicable=\"true\" scheme=\"" + n(bit.scheme) + "\" bits=\"" + n(bit.bits)
        + "\" monobitP=\"" + n(bit.monobit && bit.monobit.pValue) + "\" twoBitChiSquare=\"" + n(bit.twoBit && bit.twoBit.chiSquare)
        + "\" serialR=\"" + n(bit.serialCorrelation && bit.serialCorrelation.r) + "\"/>"
    : "<bitLevel applicable=\"false\"/>";
  xml += "</sequencerReport>";
  return xml;
}

function SequencerTab({ sequencer, dispatch }) {
  // Token randomness analyzer (Burp's Sequencer). Backend
  // (/api/sequencer/analyze, Src/Core/Networking/sequencer_logic.cpp) was
  // complete and API-only -- no tab, no manual-load box, nothing. This is
  // a Manual Load + Analysis pane; Live Capture (repeatedly issuing a
  // request and harvesting a token from each response) has no backend
  // request-issuing engine yet and is intentionally not claimed here.
  const [text, setText]   = React.useState("");
  const [result, setResult] = React.useState(null);
  const [busy, setBusy]   = React.useState(false);
  const [err, setErr]     = React.useState("");
  const fileRef = React.useRef(null);

  // #167 "Send to Sequencer": Proxy history / Repeater dispatch
  // sequencer-add-token, appending into the app-level sequencer.tokens
  // inbox (persists across this tab unmounting). Anything not yet folded
  // into the local textarea gets appended here -- on first mount that's
  // the whole inbox; while mounted, only genuinely new arrivals.
  const seenTokenCountRef = React.useRef(0);
  React.useEffect(() => {
    const incoming = sequencer.tokens;
    const already = seenTokenCountRef.current;
    if (incoming.length > already) {
      const added = incoming.slice(already);
      setText(prev => (prev ? prev.replace(/\n?$/, "\n") + added.join("\n") : added.join("\n")));
    }
    seenTokenCountRef.current = incoming.length;
  }, [sequencer.tokens]);

  const tokens = React.useMemo(
    () => text.split(/\r?\n/).map(s => s.trim()).filter(Boolean),
    [text]
  );
  const summary = React.useMemo(() => sequencerSampleSummary(tokens), [tokens]);

  function loadFile(e) {
    const f = e.target.files && e.target.files[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = () => setText(String(reader.result));
    reader.readAsText(f);
    e.target.value = "";
  }

  async function pasteFromClipboard() {
    try {
      if (!navigator.clipboard || !navigator.clipboard.readText) {
        setErr("clipboard access unavailable in this context");
        return;
      }
      const t = await navigator.clipboard.readText();
      if (t) setText(prev => (prev ? prev.replace(/\n?$/, "\n") + t : t));
    } catch (e) {
      setErr("clipboard read failed: " + String(e && e.message ? e.message : e));
    }
  }

  async function copyTokens() {
    try {
      if (!navigator.clipboard || !navigator.clipboard.writeText) {
        setErr("clipboard access unavailable in this context");
        return;
      }
      await navigator.clipboard.writeText(tokens.join("\n"));
    } catch (e) {
      setErr("clipboard write failed: " + String(e && e.message ? e.message : e));
    }
  }

  function saveTokens() {
    try {
      const blob = new Blob([tokens.join("\n") + (tokens.length ? "\n" : "")], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "nullock-sequencer-tokens.txt";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (e) {
      setErr("save failed: " + String(e && e.message ? e.message : e));
    }
  }

  async function analyze() {
    if (tokens.length < 2) { setErr("need at least 2 tokens"); return; }
    setBusy(true); setErr(""); setResult(null);
    try {
      const r = await NL.actions.sequencerAnalyze(tokens);
      if (r && r.error) setErr(r.error);
      else setResult(r);
    } catch (e) { setErr(String(e && e.message ? e.message : e)); }
    finally { setBusy(false); }
  }

  // #185: download the current analysis as a standalone HTML or XML report.
  function exportReport(format) {
    try {
      const body = format === "xml" ? sequencerReportXml(result, tokens.length) : sequencerReportHtml(result, tokens.length);
      const blob = new Blob([body], { type: format === "xml" ? "application/xml" : "text/html" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "nullock-sequencer-report." + (format === "xml" ? "xml" : "html");
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (e) {
      setErr("report export failed: " + String(e && e.message ? e.message : e));
    }
  }

  const verdictColor = (v) => ({
    "looks-random": "#3f8f29",
    "may-be-predictable": "#d97706",
    "predictable": "var(--err)",
    "no-data": "var(--dim)",
  }[v] || "var(--text-2)");

  const Section = ({ title, children }) => (
    <div style={{ marginBottom: 12 }}>
      <div style={{ fontSize: "10px", color: "var(--accent)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 4 }}>{title}</div>
      {children}
    </div>
  );
  const row = { display: "flex", gap: 16, flexWrap: "wrap", fontSize: "12px", color: "var(--text)" };
  const lbl = { color: "var(--dim)", marginRight: 4 };
  const bar = (frac, color) => (
    <div style={{ background: "var(--bg-deep)", borderRadius: 2, height: 6, width: 80, overflow: "hidden", display: "inline-block", verticalAlign: "middle" }}>
      <div style={{ background: color, height: "100%", width: Math.max(0, Math.min(100, frac * 100)) + "%" }} />
    </div>
  );

  const renderResult = () => {
    if (!result) return <span style={{ color: "var(--dim)", fontSize: "12px" }}>paste or load a token corpus, then ANALYZE NOW</span>;
    if (result.verdict === "no-data") return <span style={{ color: "var(--dim)", fontSize: "12px" }}>no tokens analyzed</span>;
    const sh = result.shannon || {};
    const cls = result.charClass || {};
    const ham = result.hamming || {};
    const lcs = result.lcs || {};
    const seq = result.sequential || {};
    const pos = result.positional || {};
    const bit = result.bitLevel || {};
    return (
      <div>
        <Section title="Verdict">
          <div style={row}>
            <span style={{ fontSize: "20px", fontWeight: 700, color: verdictColor(result.verdict) }}>{result.score}</span>
            <span style={{ color: verdictColor(result.verdict), textTransform: "uppercase", alignSelf: "center" }}>{result.verdict}</span>
            <span><span style={lbl}>analyzed</span>{result.n}</span>
            <span><span style={lbl}>distinct</span>{result.distinctTokens != null ? result.distinctTokens : "—"}</span>
            <span><span style={lbl}>avg len</span>{result.avgLen}</span>
          </div>
        </Section>
        <Section title="Entropy (Shannon)">
          <div style={row}>
            <span><span style={lbl}>bits/byte</span>{sh.bitsPerByte != null ? sh.bitsPerByte.toFixed(3) : "—"}</span>
            <span><span style={lbl}>alphabet</span>{sh.verdict}</span>
            <span><span style={lbl}>variable len</span>{sh.variableLen}</span>
            <span><span style={lbl}>effective bits/token</span>{sh.effectiveBitsPerToken != null ? sh.effectiveBitsPerToken.toFixed(1) : "—"}</span>
          </div>
        </Section>
        <Section title="Character class">
          <div style={row}>
            {["alphaRatio", "digitRatio", "hexRatio", "upperRatio", "lowerRatio", "specialRatio"].map(k => (
              <span key={k}>{bar(cls[k] || 0, "var(--accent)")} <span style={lbl}>{k.replace("Ratio", "")}</span>{cls[k] != null ? (cls[k] * 100).toFixed(0) + "%" : "—"}</span>
            ))}
          </div>
        </Section>
        <Section title="Hamming distance (consecutive tokens)">
          <div style={row}>
            <span><span style={lbl}>min</span>{ham.min}</span>
            <span><span style={lbl}>avg</span>{ham.avg}</span>
            <span><span style={lbl}>max</span>{ham.max}</span>
          </div>
        </Section>
        <Section title="Longest common substring">
          <div style={row}>
            <span><span style={lbl}>length</span>{lcs.length}</span>
            {lcs.longest ? <span style={{ wordBreak: "break-all", color: "var(--text-2)" }}>"{lcs.longest}"</span> : null}
          </div>
        </Section>
        <Section title="Sequential / counter detection">
          <div style={row}>
            <span><span style={lbl}>sequential</span><span style={{ color: seq.looksSequential ? "var(--err)" : "var(--text)" }}>{String(!!seq.looksSequential)}</span></span>
            <span><span style={lbl}>monotonic</span><span style={{ color: seq.looksMonotonic ? "#d97706" : "var(--text)" }}>{String(!!seq.looksMonotonic)}</span></span>
            {seq.looksSequential ? <span><span style={lbl}>delta</span>{seq.delta}</span> : null}
          </div>
        </Section>
        <Section title="Per-position entropy (fixed-width corpora, n>=20)">
          {pos.applicable ? (
            <div>
              <div style={row}>
                <span><span style={lbl}>width</span>{pos.width}</span>
                <span><span style={lbl}>sampled</span>{pos.n}</span>
                <span><span style={lbl}>weak columns</span><span style={{ color: pos.biased ? "var(--err)" : "var(--text)" }}>{pos.weakColumns}</span></span>
                <span><span style={lbl}>biased</span>{String(!!pos.biased)}</span>
              </div>
              <div style={{ marginTop: 6, display: "flex", gap: 2, flexWrap: "wrap" }}>
                {(pos.columnEntropy || []).map((h, i) => (
                  <div key={i} title={"col " + i + ": " + h.toFixed(2) + " bits"} style={{ width: 5, height: 24, background: "var(--bg-deep)", position: "relative" }}>
                    <div style={{ position: "absolute", bottom: 0, width: "100%", height: Math.min(100, (h / (pos.reference || 1)) * 100) + "%", background: h < 0.5 * (pos.reference || 1) ? "var(--err)" : "var(--accent)" }} />
                  </div>
                ))}
              </div>
            </div>
          ) : <span style={{ color: "var(--dim)", fontSize: "12px" }}>not applicable — needs ≥20 tokens of the same (modal) width</span>}
        </Section>
        <Section title="Bit-level tests (decodable hex/base64 corpora, n>=20)">
          {bit.applicable ? (
            <div style={row}>
              <span><span style={lbl}>scheme</span>{bit.scheme}</span>
              <span><span style={lbl}>bits</span>{bit.bits}</span>
              <span><span style={lbl}>monobit p</span><span style={{ color: bit.monobit && bit.monobit.failed ? "var(--err)" : "var(--text)" }}>{bit.monobit ? bit.monobit.pValue.toFixed(3) : "—"}</span></span>
              <span><span style={lbl}>two-bit χ²</span><span style={{ color: bit.twoBit && bit.twoBit.failed ? "var(--err)" : "var(--text)" }}>{bit.twoBit ? bit.twoBit.chiSquare.toFixed(2) : "—"}</span></span>
              <span><span style={lbl}>serial r</span><span style={{ color: bit.serialCorrelation && bit.serialCorrelation.failed ? "var(--err)" : "var(--text)" }}>{bit.serialCorrelation ? bit.serialCorrelation.r.toFixed(3) : "—"}</span></span>
            </div>
          ) : <span style={{ color: "var(--dim)", fontSize: "12px" }}>not applicable — needs ≥20 tokens that are all hex or all base64</span>}
        </Section>
      </div>
    );
  };

  return (
    <div style={{ padding: 14, display: "flex", flexDirection: "column", gap: 10, height: "100%", minHeight: 0 }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}>
        <span style={{ fontSize: "11px", color: "var(--accent)", textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600 }}>Sequencer</span>
        <span style={{ color: "var(--dim)", fontSize: "11px" }}>manual-load token randomness analysis — Shannon/positional/bit-level tests, sequential-counter detection</span>
      </div>
      <div style={{ background: "var(--pane)", border: "1px solid var(--line)", padding: 10, borderRadius: 4, display: "flex", flexDirection: "column", gap: 8 }}>
        <textarea
          value={text}
          onChange={e => setText(e.target.value)}
          placeholder="paste one token per line (session cookies, CSRF tokens, reset-URL tokens, ...)"
          spellCheck={false}
          style={{ minHeight: 90, resize: "vertical", background: "var(--bg-deep)", color: "var(--text)", border: "1px solid var(--line)", borderRadius: 4, padding: "6px 8px", fontSize: "12px", fontFamily: "var(--ff-mono)" }}
        />
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <button className="btn" onClick={() => fileRef.current && fileRef.current.click()}>LOAD FILE</button>
          <input ref={fileRef} type="file" accept=".txt,.csv,.log" style={{ display: "none" }} onChange={loadFile} />
          <button className="btn" onClick={pasteFromClipboard}>PASTE FROM CLIPBOARD</button>
          <button className="btn" disabled={!tokens.length} onClick={copyTokens}>COPY TOKENS</button>
          <button className="btn" disabled={!tokens.length} onClick={saveTokens}>SAVE TOKENS</button>
          <button className="btn" disabled={!result || result.verdict === "no-data"} onClick={() => exportReport("html")} title="Download an HTML report of the current analysis">EXPORT HTML</button>
          <button className="btn" disabled={!result || result.verdict === "no-data"} onClick={() => exportReport("xml")} title="Download an XML report of the current analysis">EXPORT XML</button>
          <button className="btn" onClick={() => {
            setText(""); setResult(null); setErr("");
            seenTokenCountRef.current = sequencer.tokens.length; // don't resurrect cleared tokens on remount
            dispatch({ type: "sequencer-clear-tokens" });
          }}>CLEAR</button>
          <button
            onClick={analyze}
            disabled={busy || tokens.length < 2}
            style={{
              background: "var(--accent)", color: "var(--bg)", border: "1px solid var(--accent)",
              padding: "4px 10px", fontSize: "11px", fontFamily: "var(--ff-mono)",
              cursor: busy ? "wait" : "pointer", letterSpacing: "0.04em", textTransform: "uppercase",
              opacity: tokens.length < 2 ? 0.5 : 1,
            }}
          >{busy ? "ANALYZING…" : "ANALYZE NOW"}</button>
          <span style={{ color: err ? "var(--err)" : "var(--dim)", fontSize: "11px" }}>{err || ""}</span>
        </div>
        {summary && (
          <div style={{ fontSize: "11px", color: "var(--dim)" }}>
            sample: <span style={{ color: "var(--text)" }}>{summary.n}</span> tokens ·
            {" "}shortest <span style={{ color: "var(--text)" }}>{summary.minLen}</span> ·
            {" "}longest <span style={{ color: "var(--text)" }}>{summary.maxLen}</span> ·
            {" "}mean <span style={{ color: "var(--text)" }}>{summary.meanLen}</span>
          </div>
        )}
      </div>
      <div style={{ flex: 1, overflow: "auto", background: "var(--pane)", border: "1px solid var(--line)", borderRadius: 4, padding: 12, minHeight: 0 }}>
        {renderResult()}
      </div>
    </div>
  );
}

// Pure helpers for the Labs tab (task #122) -- kept outside the component so
// they're independently testable, same pattern as sequencerSampleSummary above.

function labsVisible(labs, { category, difficulty, query }) {
  const q = (query || "").trim().toLowerCase();
  return labs.filter(l => {
    if (category && category !== "all" && l.category !== category) return false;
    if (difficulty && difficulty !== "all" && l.difficulty !== difficulty) return false;
    if (!q) return true;
    return (l.title + " " + l.vuln + " " + l.slug + " " + l.port + " " + l.category)
      .toLowerCase().indexOf(q) >= 0;
  });
}

function labsXpSummary(labs, completedSlugs, xpTable) {
  const table = xpTable || {};
  const completed = new Set(completedSlugs || []);
  let earned = 0, possible = 0;
  const byCategory = {};
  for (const l of labs) {
    const xp = table[l.difficulty] || 0;
    possible += xp;
    const done = completed.has(l.slug);
    if (done) earned += xp;
    if (!byCategory[l.category]) byCategory[l.category] = { total: 0, done: 0 };
    byCategory[l.category].total += 1;
    if (done) byCategory[l.category].done += 1;
  }
  const tracks = Object.keys(byCategory).sort().map(name => ({
    name, done: byCategory[name].done, total: byCategory[name].total,
  }));
  return { earned, possible, solvedCount: completed.size, total: labs.length, tracks };
}

function LabsTab({ dispatch }) {
  // In-app surfacing of the 50 Nullock Labs (task #122's "wire into ... in-app"
  // leg -- the docs/labs static site already had the catalog/hints/walkthrough,
  // but nothing in the desktop GUI itself). Catalog is generated straight from
  // labs/README.md + each lab's app.py docstring by scripts/labs_site.py into
  // ui-v2/labs-data.js (window.NULLOCK_LABS / window.NULLOCK_LABS_XP) -- the
  // same source of truth as the static site, so the two can never drift.
  // "Solved" tracking + XP/tracks gamification is client-side only (localStorage):
  // there is no backend concept of lab progress, and these apps run as separate
  // throwaway localhost processes outside Nullock's own project state.
  const labs = React.useMemo(() => (window.NULLOCK_LABS || []), []);
  const xpTable = window.NULLOCK_LABS_XP || {};

  const [completed, setCompleted] = React.useState(() => {
    try {
      const raw = window.localStorage && window.localStorage.getItem("nullock:labs:completed");
      const arr = raw ? JSON.parse(raw) : [];
      return Array.isArray(arr) ? arr.filter(s => typeof s === "string") : [];
    } catch (e) { return []; }
  });
  React.useEffect(() => {
    try {
      window.localStorage && window.localStorage.setItem("nullock:labs:completed", JSON.stringify(completed));
    } catch (e) { /* storage unavailable/full -- progress just won't persist */ }
  }, [completed]);

  const [category, setCategory] = React.useState("all");
  const [difficulty, setDifficulty] = React.useState("all");
  const [query, setQuery] = React.useState("");
  const [selectedSlug, setSelectedSlug] = React.useState(null);
  const [hintsOpen, setHintsOpen] = React.useState(0);
  const [fixOpen, setFixOpen] = React.useState(false);

  const categories = React.useMemo(() => ["all", ...Array.from(new Set(labs.map(l => l.category))).sort()], [labs]);
  const visible = React.useMemo(() => labsVisible(labs, { category, difficulty, query }), [labs, category, difficulty, query]);
  const xp = React.useMemo(() => labsXpSummary(labs, completed, xpTable), [labs, completed, xpTable]);
  const selected = labs.find(l => l.slug === selectedSlug) || null;

  function selectLab(slug) {
    setSelectedSlug(slug);
    setHintsOpen(0);
    setFixOpen(false);
  }

  function toggleSolved(slug) {
    setCompleted(prev => prev.includes(slug) ? prev.filter(s => s !== slug) : [...prev, slug]);
  }

  function sendFlagCheckToRepeater(l) {
    const port = l.port;
    const text = "GET /flag HTTP/1.1\r\nHost: localhost:" + port + "\r\nConnection: close\r\n\r\n";
    dispatch({ type: "send-to-repeater-raw", host: "localhost", port: Number(port), tls: false, text });
  }

  const chip = (active) => ({
    background: active ? "var(--accent)" : "var(--pane)",
    color: active ? "var(--bg-deep)" : "var(--text-2)",
    border: "1px solid " + (active ? "var(--accent)" : "var(--line)"),
    borderRadius: 999, padding: "3px 10px", fontSize: "11px", cursor: "pointer",
  });
  const diffColor = (d) => ({ Easy: "#3f8f29", Medium: "#d97706", Hard: "var(--err)" }[d] || "var(--text-2)");

  if (!labs.length) {
    return (
      <div style={{ padding: 14, color: "var(--dim)", fontSize: "12px" }}>
        no lab catalog loaded (ui-v2/labs-data.js missing or failed to load)
      </div>
    );
  }

  return (
    <div style={{ padding: 14, display: "flex", flexDirection: "column", gap: 10, height: "100%", minHeight: 0 }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 12, flexWrap: "wrap" }}>
        <span style={{ fontSize: "11px", color: "var(--accent)", textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600 }}>Labs</span>
        <span style={{ color: "var(--dim)", fontSize: "11px" }}>50 intentionally-vulnerable practice targets, run on localhost -- objective, hints, walkthrough and a live flag check, without leaving the app</span>
        <span style={{ marginLeft: "auto", fontSize: "12px" }}>
          <span style={{ color: "var(--accent)", fontWeight: 700 }}>{xp.earned}</span>
          <span style={{ color: "var(--dim)" }}> / {xp.possible} XP</span>
          <span style={{ color: "var(--dim)", marginLeft: 8 }}>{xp.solvedCount} / {xp.total} solved</span>
        </span>
      </div>

      <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
        {xp.tracks.map(t => (
          <div key={t.name} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: "11px", color: "var(--text-2)" }}>
            <span>{t.name}</span>
            <div style={{ background: "var(--bg-deep)", borderRadius: 2, height: 6, width: 50, overflow: "hidden" }}>
              <div style={{ background: "var(--accent)", height: "100%", width: (t.total ? (t.done / t.total) * 100 : 0) + "%" }} />
            </div>
            <span style={{ color: "var(--dim)" }}>{t.done}/{t.total}</span>
          </div>
        ))}
      </div>

      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <input
          value={query}
          onChange={e => setQuery(e.target.value)}
          placeholder="filter by name, bug class, port..."
          spellCheck={false}
          style={{ background: "var(--bg-deep)", color: "var(--text)", border: "1px solid var(--line)", borderRadius: 4, padding: "5px 8px", fontSize: "12px", minWidth: 220 }}
        />
        {categories.map(c => (
          <span key={c} style={chip(category === c)} onClick={() => setCategory(c)}>{c}</span>
        ))}
        {["all", "Easy", "Medium", "Hard"].map(d => (
          <span key={d} style={chip(difficulty === d)} onClick={() => setDifficulty(d)}>{d === "all" ? "all difficulty" : d}</span>
        ))}
        <span style={{ marginLeft: "auto", color: "var(--dim)", fontSize: "11px" }}>{visible.length} of {labs.length}</span>
      </div>

      <div style={{ flex: 1, display: "flex", gap: 10, minHeight: 0 }}>
        <div style={{ width: "40%", overflow: "auto", display: "flex", flexDirection: "column", gap: 6 }}>
          {visible.map(l => {
            const done = completed.includes(l.slug);
            return (
              <div
                key={l.slug}
                onClick={() => selectLab(l.slug)}
                style={{
                  background: selectedSlug === l.slug ? "var(--pane-hover, var(--pane))" : "var(--pane)",
                  border: "1px solid " + (selectedSlug === l.slug ? "var(--accent)" : "var(--line)"),
                  borderRadius: 4, padding: "8px 10px", cursor: "pointer",
                }}
              >
                <div style={{ display: "flex", gap: 8, alignItems: "center", fontSize: "10px" }}>
                  <span style={{ color: "var(--dim)" }}>{l.num}</span>
                  <span style={{ color: "var(--text-2)" }}>{l.category}</span>
                  <span style={{ color: diffColor(l.difficulty) }}>{l.difficulty}</span>
                  <span style={{ color: "var(--dim)" }}>:{l.port}</span>
                  {done && <span style={{ color: "#3f8f29", marginLeft: "auto" }}>{"✓ solved"}</span>}
                </div>
                <div style={{ fontSize: "13px", marginTop: 2 }}>{l.title}</div>
                <div style={{ fontSize: "11px", color: "var(--dim)" }}>{l.vuln}</div>
              </div>
            );
          })}
          {!visible.length && <div style={{ color: "var(--dim)", fontSize: "12px" }}>no labs match that filter</div>}
        </div>

        <div style={{ flex: 1, overflow: "auto", background: "var(--pane)", border: "1px solid var(--line)", borderRadius: 4, padding: 12, minHeight: 0 }}>
          {!selected ? (
            <span style={{ color: "var(--dim)", fontSize: "12px" }}>select a lab on the left</span>
          ) : (
            <div>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <span style={{ fontSize: "15px", fontWeight: 600 }}>{selected.title}</span>
                <span style={{ color: diffColor(selected.difficulty), fontSize: "11px" }}>{selected.difficulty}</span>
                <span style={{ color: "var(--dim)", fontSize: "11px" }}>{selected.category} · +{xpTable[selected.difficulty] || 0} XP</span>
              </div>
              <p style={{ fontSize: "12.5px", color: "var(--text-2)", marginTop: 6 }}>{selected.desc || selected.vuln}</p>
              <div style={{ fontFamily: "var(--ff-mono)", fontSize: "11.5px", background: "var(--bg-deep)", border: "1px solid var(--line)", borderRadius: 4, padding: 8, marginTop: 6 }}>
                python labs/{selected.slug}/app.py{"\n"}# then open http://localhost:{selected.port}/
              </div>

              <div style={{ display: "flex", gap: 8, marginTop: 10, flexWrap: "wrap" }}>
                <button className="btn" onClick={() => sendFlagCheckToRepeater(selected)}>SEND GET /flag TO REPEATER</button>
                <button className="btn" onClick={() => toggleSolved(selected.slug)}>
                  {completed.includes(selected.slug) ? "MARK UNSOLVED" : "MARK SOLVED"}
                </button>
              </div>

              {!!(selected.hints && selected.hints.length) && (
                <div style={{ marginTop: 14 }}>
                  <div style={{ fontSize: "10px", color: "var(--accent)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 4 }}>Hints</div>
                  {selected.hints.slice(0, hintsOpen).map((h, i) => (
                    <div key={i} style={{ fontSize: "12px", color: "var(--text-2)", marginBottom: 4 }}>{i + 1}. {h}</div>
                  ))}
                  {hintsOpen < selected.hints.length && (
                    <button className="btn" onClick={() => setHintsOpen(n => n + 1)}>
                      REVEAL HINT {hintsOpen + 1} OF {selected.hints.length}
                    </button>
                  )}
                </div>
              )}

              {!!(selected.steps && selected.steps.length) && (
                <div style={{ marginTop: 14 }}>
                  <div style={{ fontSize: "10px", color: "var(--accent)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 4 }}>Walkthrough</div>
                  <ol style={{ margin: 0, paddingLeft: 18, fontSize: "12px", color: "var(--text-2)" }}>
                    {selected.steps.map((s, i) => <li key={i} style={{ marginBottom: 3 }}>{s}</li>)}
                  </ol>
                </div>
              )}

              {!!selected.fix && (
                <div style={{ marginTop: 14 }}>
                  {!fixOpen ? (
                    <button className="btn" onClick={() => setFixOpen(true)}>SHOW FIX</button>
                  ) : (
                    <div>
                      <div style={{ fontSize: "10px", color: "var(--accent)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 4 }}>The fix</div>
                      <p style={{ fontSize: "12px", color: "var(--text-2)" }}>{selected.fix}</p>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function DiscoverTab() {
  // Recon/discovery backends that existed with no UI: wordlist-based content
  // (directory/file) discovery, robots.txt + sitemap recon, and the BFS link
  // crawler. Content-discover and robots-scan are single-shot (result renders
  // below); the crawler is long-running -- it feeds pages straight into
  // Proxy history via entryLoaded, so its "result" here is just start/stop
  // status plus a pointer at where the captured pages show up.
  const [url, setUrl]         = React.useState("");
  const [kind, setKind]       = React.useState("");
  const [res, setRes]         = React.useState(null);
  const [busy, setBusy]       = React.useState(false);
  const [err, setErr]         = React.useState("");
  const [crawling, setCrawling] = React.useState(false);
  const [maxPages, setMaxPages]     = React.useState(200);
  const [maxDepth, setMaxDepth]     = React.useState(4);
  const [throttleMs, setThrottleMs] = React.useState(200);

  // Content-discovery config: a custom wordlist (paste or load-from-file, one
  // word per line -- empty means the backend's built-in default list) and the
  // extension-bruteforce suffixes (backend-side word x extension expansion,
  // so the 2000-request cap bounds the true total instead of a pre-multiplied
  // client-side array), plus the resource-pool dials the backend already
  // accepts (concurrency/throttle) that had no UI.
  const [wordlistText, setWordlistText]         = React.useState("");
  const [extensionsText, setExtensionsText]     = React.useState("");
  const [maxRequests, setMaxRequests]           = React.useState(300);
  const [discConcurrency, setDiscConcurrency]   = React.useState(10);
  const [discThrottleMs, setDiscThrottleMs]     = React.useState(0);

  // #394: robots.txt Disallow paths and sitemap.xml <loc> URLs are discovered
  // but otherwise dead-end here in a results table -- Burp infers unrequested
  // site-map nodes from exactly this data. "+ map" promotes one hit into the
  // same synthetic-import path the manual site-map add box uses, so it needs
  // no new backend route either.
  const [mappedHits, setMappedHits] = React.useState(() => new Set());
  const [mapBusyKey, setMapBusyKey] = React.useState(null);
  const addHitToMap = async (key, originUrl, path) => {
    setMapBusyKey(key); setErr("");
    try {
      const r = await NL.actions.addUrlToSiteMap(originUrl, path, "GET");
      if (r && r.ok === false) setErr(r.error || "add to map failed");
      else setMappedHits(prev => new Set(prev).add(key));
    } catch (e) { setErr(String(e && e.message ? e.message : e)); }
    finally { setMapBusyKey(null); }
  };
  const MapBtn = ({ hitKey, onAdd }) => (
    mappedHits.has(hitKey)
      ? <span style={{ color: "var(--ok)", fontSize: "10px" }}>✓ mapped</span>
      : <button onClick={onAdd} disabled={mapBusyKey === hitKey} title="Add to site map as an unrequested item"
          style={{ background: "transparent", color: "var(--accent)", border: "1px solid var(--accent)",
                   borderRadius: 3, padding: "1px 6px", fontSize: "10px", fontFamily: "var(--ff-mono)",
                   cursor: mapBusyKey === hitKey ? "wait" : "pointer" }}>
          {mapBusyKey === hitKey ? "…" : "+ map"}
        </button>
  );

  const run = async (k, fn) => {
    if (!url) { setErr("enter a URL"); return; }
    setKind(k); setErr(""); setBusy(true); setRes(null);
    try {
      const r = await fn(url);
      if (r && r.ok === false && r.error) { setErr(r.error); setRes(null); }
      else setRes(r);
    } catch (e) { setErr(String(e && e.message ? e.message : e)); }
    finally { setBusy(false); }
  };

  const runDiscover = async () => {
    if (!url) { setErr("enter a URL"); return; }
    setKind("content"); setErr(""); setBusy(true); setRes(null);
    try {
      const wordlist = wordlistText.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
      const extensions = extensionsText.split(/[,\n]/).map(s => s.trim()).filter(Boolean);
      const r = await NL.actions.discoverContent(url, maxRequests, {
        wordlist, extensions, concurrency: discConcurrency, throttleMs: discThrottleMs,
      });
      if (r && r.ok === false && r.error) { setErr(r.error); setRes(null); }
      else setRes(r);
    } catch (e) { setErr(String(e && e.message ? e.message : e)); }
    finally { setBusy(false); }
  };

  const loadWordlistFile = (e) => {
    const f = e.target.files && e.target.files[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = () => setWordlistText(String(reader.result || ""));
    reader.readAsText(f);
    e.target.value = "";
  };

  const startCrawl = async () => {
    if (!url) { setErr("enter a seed URL"); return; }
    setKind("crawl"); setErr(""); setBusy(true); setRes(null);
    try {
      const r = await NL.actions.crawlerStart(url, maxPages, maxDepth, throttleMs);
      if (r && r.ok === false) setErr(r.error || "crawler failed to start");
      else { setCrawling(true); setRes(r); }
    } catch (e) { setErr(String(e && e.message ? e.message : e)); }
    finally { setBusy(false); }
  };
  const stopCrawl = async () => {
    setBusy(true);
    try { await NL.actions.crawlerStop(); } catch (e) { /* best-effort */ }
    finally { setCrawling(false); setBusy(false); }
  };

  const th = { textAlign: "left", color: "var(--dim)", fontWeight: 500, padding: "3px 12px 3px 0", whiteSpace: "nowrap", verticalAlign: "top" };
  const td = { padding: "3px 12px 3px 0", wordBreak: "break-word", color: "var(--text)", verticalAlign: "top" };
  const Btn = ({ label, onClick, active }) => (
    <button onClick={onClick} disabled={busy} style={{
      background: active ? "var(--accent)" : "transparent",
      color: busy ? "var(--dim)" : active ? "var(--bg)" : "var(--accent)",
      border: "1px solid var(--accent)", padding: "4px 10px", fontSize: "11px",
      fontFamily: "var(--ff-mono)", cursor: busy ? "wait" : "pointer",
      letterSpacing: "0.04em", textTransform: "uppercase",
    }}>{label}</button>
  );
  const Table = ({ cols, rows, cell }) => (
    <table style={{ borderCollapse: "collapse", fontSize: "12px", fontFamily: "var(--ff-mono)", width: "100%" }}>
      <thead><tr>{cols.map((c, i) => <th key={i} style={th}>{c}</th>)}</tr></thead>
      <tbody>{(rows || []).map((r, i) => <tr key={i}>{cell(r).map((v, j) => <td key={j} style={td}>{v}</td>)}</tr>)}</tbody>
    </table>
  );
  const Section = ({ title, children }) => (
    <div style={{ marginBottom: 12 }}>
      <div style={{ fontSize: "10px", color: "var(--accent)", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: 4 }}>{title}</div>
      {children}
    </div>
  );

  const render = () => {
    if (!res) return <span style={{ color: "var(--dim)", fontSize: "12px" }}>results appear here — content-discovery + robots hits are also added to Issues</span>;
    if (kind === "content") return (
      <div>
        <div style={{ color: "var(--dim)", fontSize: "11px", marginBottom: 8 }}>
          {res.requestsSent || 0} requests · {res.wordsTried || 0}/{res.wordsTotal || 0} words (post-extension-expansion) · {res.hitCount || 0} hits
          {res.wordlistTruncated ? " · wordlist truncated" : ""}
          {!res.calibrationReliable ? " · soft-404 calibration unreliable" : ""}
          {res.softNotFoundIs200 ? " · soft-404 server (200s filtered by size)" : ""}
        </div>
        {res.hits && res.hits.length ? <Table cols={["path", "status", "size", "note"]} rows={res.hits} cell={h => [<span style={{ color: "var(--accent)" }}>{h.path}</span>, h.status, h.size, <span style={{ color: "var(--text-2)" }}>{h.note}</span>]} /> : <div style={{ color: "var(--dim)", fontSize: "12px" }}>no paths discovered</div>}
      </div>
    );
    if (kind === "robots") return (
      <div>
        <div style={{ color: "var(--dim)", fontSize: "11px", marginBottom: 8 }}>
          robots.txt: {res.robotsFound ? "found" : "absent"} · sitemap: {res.sitemapFound ? "found" : "absent"} · {res.disallowedCount || 0} disallowed · {res.sitemapUrlCount || 0} sitemap URLs
        </div>
        {res.disallowed && res.disallowed.length ? <Section title="Disallowed paths"><Table cols={["path", ""]} rows={res.disallowed} cell={p => {
          const key = "d:" + p;
          let origin = null;
          try { origin = new URL(url).origin; } catch (e) { /* url already validated by run() */ }
          return [p, origin ? <MapBtn hitKey={key} onAdd={() => addHitToMap(key, origin, p)} /> : null];
        }} /></Section> : null}
        {res.disallowedPatterns && res.disallowedPatterns.length ? <Section title="Disallowed patterns"><Table cols={["pattern"]} rows={res.disallowedPatterns} cell={p => [p]} /></Section> : null}
        {res.sitemapUrls && res.sitemapUrls.length ? <Section title={"Sitemap URLs (" + res.sitemapUrls.length + ")"}><Table cols={["url", ""]} rows={res.sitemapUrls.slice(0, 100)} cell={u => {
          const key = "s:" + u;
          let uu = null;
          try { uu = new URL(u); } catch (e) { /* malformed <loc>, no add-to-map possible */ }
          return [<span style={{ wordBreak: "break-all" }}>{u}</span>, uu ? <MapBtn hitKey={key} onAdd={() => addHitToMap(key, uu.origin, uu.pathname + uu.search)} /> : null];
        }} /></Section> : null}
        {!res.robotsFound && !res.sitemapFound ? <div style={{ color: "var(--dim)", fontSize: "12px" }}>no robots.txt or sitemap.xml found</div> : null}
      </div>
    );
    if (kind === "crawl") return (
      <div style={{ color: "var(--text-2)", fontSize: "12px" }}>
        {crawling ? "crawl running — " : "crawl stopped — "}
        pages fetched are streamed into <span style={{ color: "var(--accent)" }}>Proxy</span> history as they're captured; new findings land in <span style={{ color: "var(--accent)" }}>Issues</span> as usual.
      </div>
    );
    return null;
  };

  return (
    <div style={{ padding: 14, display: "flex", flexDirection: "column", gap: 10, height: "100%", minHeight: 0 }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}>
        <span style={{ fontSize: "11px", color: "var(--accent)", textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600 }}>Discover</span>
        <span style={{ color: "var(--dim)", fontSize: "11px" }}>content/directory discovery, robots.txt + sitemap recon, and the BFS link crawler</span>
      </div>
      <div style={{ background: "var(--pane)", border: "1px solid var(--line)", padding: 10, borderRadius: 4, display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <input value={url} onChange={e => setUrl(e.target.value)} placeholder="https://target.example.com/"
               onKeyDown={e => { if (e.key === "Enter") runDiscover(); }}
               style={{ flex: "1 1 320px", minWidth: 220, background: "var(--bg-deep)", color: "var(--text)", border: "1px solid var(--line)", borderRadius: 4, padding: "5px 8px", fontSize: "12px", fontFamily: "var(--ff-mono)" }} spellCheck={false} />
        <Btn label="content discover" active={kind === "content"} onClick={runDiscover} />
        <Btn label="robots + sitemap" active={kind === "robots"} onClick={() => run("robots", NL.actions.scanRobots)} />
        {!crawling
          ? <Btn label="start crawl" active={kind === "crawl"} onClick={startCrawl} />
          : <Btn label="stop crawl" active={true} onClick={stopCrawl} />}
        <span style={{ color: err ? "var(--err)" : "var(--dim)", fontSize: "11px" }}>{busy ? "working…" : err || ""}</span>
      </div>
      <div style={{ background: "var(--pane)", border: "1px solid var(--line)", padding: 10, borderRadius: 4, display: "flex", gap: 10, flexWrap: "wrap", alignItems: "flex-start" }}>
        <span style={{ color: "var(--dim)", fontSize: "10px", textTransform: "uppercase", letterSpacing: "0.06em", paddingTop: 4 }}>Discovery config</span>
        <label style={{ display: "flex", flexDirection: "column", gap: 3, fontSize: "11px", color: "var(--dim)" }}>
          custom wordlist (one path per line — blank = built-in default)
          <textarea value={wordlistText} onChange={e => setWordlistText(e.target.value)} rows={2} spellCheck={false}
                    placeholder="admin&#10;backup&#10;.git/config"
                    style={{ width: 220, resize: "vertical", background: "var(--bg-deep)", color: "var(--text)", border: "1px solid var(--line)", borderRadius: 4, padding: "5px 8px", fontSize: "11px", fontFamily: "var(--ff-mono)" }} />
        </label>
        <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: "11px", color: "var(--dim)" }}>
          load wordlist file
          <input type="file" accept=".txt,.lst" onChange={loadWordlistFile} style={{ fontSize: "11px", color: "var(--text)", maxWidth: 140 }} />
        </label>
        <label style={{ display: "flex", flexDirection: "column", gap: 3, fontSize: "11px", color: "var(--dim)" }}>
          extensions (backup sweep — comma or newline separated)
          <input value={extensionsText} onChange={e => setExtensionsText(e.target.value)} placeholder=".php, .bak, .old, .zip"
                 style={{ width: 200, background: "var(--bg-deep)", color: "var(--text)", border: "1px solid var(--line)", borderRadius: 4, padding: "5px 8px", fontSize: "11px", fontFamily: "var(--ff-mono)" }} spellCheck={false} />
        </label>
        <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: "11px", color: "var(--dim)" }}>
          max requests
          <input type="number" min={1} max={2000} value={maxRequests}
                 onChange={e => setMaxRequests(Number(e.target.value) || 1)}
                 style={{ width: 70, background: "var(--bg-deep)", color: "var(--text)", border: "1px solid var(--line)", borderRadius: 4, padding: "3px 6px", fontSize: "12px", fontFamily: "var(--ff-mono)" }} />
        </label>
        <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: "11px", color: "var(--dim)" }}>
          concurrency
          <input type="number" min={1} max={64} value={discConcurrency}
                 onChange={e => setDiscConcurrency(Number(e.target.value) || 1)}
                 style={{ width: 60, background: "var(--bg-deep)", color: "var(--text)", border: "1px solid var(--line)", borderRadius: 4, padding: "3px 6px", fontSize: "12px", fontFamily: "var(--ff-mono)" }} />
        </label>
        <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: "11px", color: "var(--dim)" }}>
          throttle (ms)
          <input type="number" min={0} max={60000} value={discThrottleMs}
                 onChange={e => setDiscThrottleMs(Number(e.target.value) || 0)}
                 style={{ width: 70, background: "var(--bg-deep)", color: "var(--text)", border: "1px solid var(--line)", borderRadius: 4, padding: "3px 6px", fontSize: "12px", fontFamily: "var(--ff-mono)" }} />
        </label>
      </div>
      <div style={{ background: "var(--pane)", border: "1px solid var(--line)", padding: 10, borderRadius: 4, display: "flex", gap: 14, flexWrap: "wrap", alignItems: "center" }}>
        <span style={{ color: "var(--dim)", fontSize: "10px", textTransform: "uppercase", letterSpacing: "0.06em" }}>Crawl config</span>
        <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: "11px", color: "var(--dim)" }}>
          max pages
          <input type="number" min={1} max={5000} value={maxPages} disabled={crawling}
                 onChange={e => setMaxPages(Number(e.target.value) || 1)}
                 style={{ width: 70, background: "var(--bg-deep)", color: "var(--text)", border: "1px solid var(--line)", borderRadius: 4, padding: "3px 6px", fontSize: "12px", fontFamily: "var(--ff-mono)" }} />
        </label>
        <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: "11px", color: "var(--dim)" }}>
          max depth
          <input type="number" min={0} max={10} value={maxDepth} disabled={crawling}
                 onChange={e => setMaxDepth(Number(e.target.value) || 0)}
                 style={{ width: 60, background: "var(--bg-deep)", color: "var(--text)", border: "1px solid var(--line)", borderRadius: 4, padding: "3px 6px", fontSize: "12px", fontFamily: "var(--ff-mono)" }} />
        </label>
        <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: "11px", color: "var(--dim)" }}>
          throttle (ms)
          <input type="number" min={0} max={60000} value={throttleMs} disabled={crawling}
                 onChange={e => setThrottleMs(Number(e.target.value) || 0)}
                 style={{ width: 70, background: "var(--bg-deep)", color: "var(--text)", border: "1px solid var(--line)", borderRadius: 4, padding: "3px 6px", fontSize: "12px", fontFamily: "var(--ff-mono)" }} />
        </label>
      </div>
      <div style={{ flex: 1, overflow: "auto", background: "var(--pane)", border: "1px solid var(--line)", borderRadius: 4, padding: 12, minHeight: 0 }}>
        {render()}
      </div>
    </div>
  );
}

function ReportingTab() {
  // Reporting & export backends that existed with no UI: engagement report
  // generation (Markdown/HTML/JSON), OpenAPI spec export/import, CycloneDX
  // SBOM export, and workspace push/pull sync with a shared nullock-workspace
  // server. report/build and report/html are POST-only (engagement documents,
  // not idempotent reads) so their downloads go through fetch->blob rather
  // than a plain <a href> like the GET-allowlisted exports below them.
  const [busy, setBusy] = React.useState("");
  const [err, setErr]   = React.useState("");
  const [summary, setSummary] = React.useState(null);

  const [spec, setSpec]           = React.useState("");
  const [baseUrl, setBaseUrl]     = React.useState("");
  const [importRes, setImportRes] = React.useState(null);

  const [wsUrl, setWsUrl] = React.useState("");
  const [wsKey, setWsKey] = React.useState("");
  const [wsEng, setWsEng] = React.useState("");
  const [wsRes, setWsRes] = React.useState(null);

  const downloadBlob = async (kind, fetcher, filename) => {
    setErr(""); setBusy(kind);
    try {
      const r = await fetcher();
      if (!r || !r.ok) { setErr(kind + " failed (" + (r ? r.status : "network error") + ")"); return; }
      const blob = await r.blob();
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = filename;
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(a.href);
    } catch (e) { setErr(String(e && e.message ? e.message : e)); }
    finally { setBusy(""); }
  };

  const downloadHref = (href, filename) => {
    const a = document.createElement("a");
    a.href = href; a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
  };

  const loadSummary = async () => {
    setErr(""); setBusy("json"); setSummary(null);
    try {
      const r = await NL.actions.reportJson();
      if (r && r.ok === false) setErr(r.error || "report/json failed");
      else setSummary(r);
    } catch (e) { setErr(String(e && e.message ? e.message : e)); }
    finally { setBusy(""); }
  };

  const doImport = async () => {
    if (!spec.trim()) { setErr("paste an OpenAPI spec (JSON)"); return; }
    setErr(""); setBusy("import"); setImportRes(null);
    try {
      const r = await NL.actions.openapiImport(spec, baseUrl);
      if (r && r.ok === false) setErr(r.error || "import failed");
      setImportRes(r);
    } catch (e) { setErr(String(e && e.message ? e.message : e)); }
    finally { setBusy(""); }
  };

  const doWorkspace = async (dir) => {
    if (!wsUrl || !wsKey || !wsEng) { setErr("workspace url, key, and engagement are required"); return; }
    setErr(""); setBusy("ws-" + dir); setWsRes(null);
    try {
      const r = dir === "push" ? await NL.actions.workspacePush(wsUrl, wsKey, wsEng)
                                : await NL.actions.workspacePull(wsUrl, wsKey, wsEng);
      if (r && r.ok === false) setErr(r.error || (dir + " failed"));
      setWsRes(r);
    } catch (e) { setErr(String(e && e.message ? e.message : e)); }
    finally { setBusy(""); }
  };

  const Btn = ({ label, onClick, k }) => (
    <button onClick={onClick} disabled={!!busy} style={{
      background: "transparent",
      color: busy ? "var(--dim)" : "var(--accent)",
      border: "1px solid var(--accent)", padding: "4px 10px", fontSize: "11px",
      fontFamily: "var(--ff-mono)", cursor: busy ? "wait" : "pointer",
      letterSpacing: "0.04em", textTransform: "uppercase",
    }}>{busy === k ? "…" : label}</button>
  );
  const input = {
    background: "var(--bg-deep)", color: "var(--text)", border: "1px solid var(--line)",
    borderRadius: 4, padding: "5px 8px", fontSize: "12px", fontFamily: "var(--ff-mono)",
  };
  const Section = ({ title, hint, children }) => (
    <div style={{ background: "var(--pane)", border: "1px solid var(--line)", borderRadius: 4, padding: 12, display: "flex", flexDirection: "column", gap: 8 }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 10, flexWrap: "wrap" }}>
        <span style={{ fontSize: "11px", color: "var(--accent)", textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600 }}>{title}</span>
        {hint && <span style={{ color: "var(--dim)", fontSize: "11px" }}>{hint}</span>}
      </div>
      {children}
    </div>
  );

  return (
    <div style={{ padding: 14, display: "flex", flexDirection: "column", gap: 12, height: "100%", minHeight: 0, overflow: "auto" }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 12, flexWrap: "wrap" }}>
        <span style={{ fontSize: "11px", color: "var(--accent)", textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600 }}>Reporting</span>
        <span style={{ color: "var(--dim)", fontSize: "11px" }}>engagement report export, OpenAPI import/export, SBOM, and workspace sync</span>
        {err && <span style={{ color: "var(--err)", fontSize: "11px" }}>{err}</span>}
      </div>

      <Section title="Engagement report" hint="findings + scope + notes, generated from the current session">
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <Btn k="md" label="Download Markdown" onClick={() => downloadBlob("md", NL.actions.reportBuild, "nullock-report.md")} />
          <Btn k="html" label="Download HTML" onClick={() => downloadBlob("html", NL.actions.reportHtml, "nullock-report.html")} />
          <Btn k="jsondl" label="Download JSON" onClick={() => downloadHref("/api/report/json", "nullock-report.json")} />
          <Btn k="xmldl" label="Download XML" onClick={() => downloadHref("/api/report/xml", "nullock-report.xml")} />
          <Btn k="json" label="View summary" onClick={loadSummary} />
        </div>
        {summary && (
          <div style={{ fontSize: "12px", color: "var(--text-2)", fontFamily: "var(--ff-mono)" }}>
            posture: <span style={{ color: "var(--accent)" }}>{summary.posture ? summary.posture.grade : "?"}</span>
            {" "}({summary.posture ? summary.posture.score : "?"}) ·{" "}
            findings: {summary.findingsTotal != null ? summary.findingsTotal : 0} ·{" "}
            hosts: {summary.inventory ? summary.inventory.hostCount : 0} ·{" "}
            generated {summary.generatedAt || ""}
          </div>
        )}
      </Section>

      <Section title="OpenAPI" hint="reverse-engineer a spec from captured history, or seed history from an existing spec">
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <Btn k="oa-export" label="Export captured surface" onClick={() => downloadHref("/api/openapi/export", "nullock-openapi.json")} />
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <textarea value={spec} onChange={e => setSpec(e.target.value)} placeholder="paste an OpenAPI 2.x/3.x spec (JSON)…"
                    rows={4} style={{ ...input, resize: "vertical", fontSize: "11px" }} spellCheck={false} />
          <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <input value={baseUrl} onChange={e => setBaseUrl(e.target.value)} placeholder="base URL override (optional)"
                   style={{ ...input, flex: "1 1 260px", minWidth: 200 }} spellCheck={false} />
            <Btn k="import" label="Import into history" onClick={doImport} />
          </div>
          {importRes && (
            <div style={{ fontSize: "11px", color: "var(--text-2)" }}>
              {importRes.ok
                ? "imported " + importRes.imported + " operations from " + importRes.host + (importRes.truncated ? " (truncated)" : "")
                : "import failed" + (importRes.error ? ": " + importRes.error : "")}
            </div>
          )}
        </div>
      </Section>

      <Section title="SBOM" hint="CycloneDX 1.5, from detected tech + CVE-correlated findings">
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <Btn k="sbom" label="Download SBOM" onClick={() => downloadHref("/api/export/sbom", "nullock-sbom.json")} />
        </div>
      </Section>

      <Section title="Workspace sync" hint="push/pull findings against a shared nullock-workspace server (your own infra, not scan-gated)">
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <input value={wsUrl} onChange={e => setWsUrl(e.target.value)} placeholder="https://workspace.example.com/"
                 style={{ ...input, flex: "1 1 220px", minWidth: 180 }} spellCheck={false} />
          <input value={wsKey} onChange={e => setWsKey(e.target.value)} placeholder="key" type="password"
                 style={{ ...input, width: 140 }} spellCheck={false} />
          <input value={wsEng} onChange={e => setWsEng(e.target.value)} placeholder="engagement"
                 style={{ ...input, width: 160 }} spellCheck={false} />
          <Btn k="ws-push" label="Push" onClick={() => doWorkspace("push")} />
          <Btn k="ws-pull" label="Pull" onClick={() => doWorkspace("pull")} />
        </div>
        {wsRes && (
          <div style={{ fontSize: "11px", color: "var(--text-2)" }}>
            {wsRes.ok
              ? ("pushed" in wsRes ? "pushed " + wsRes.pushed + " (" + wsRes.accepted + " accepted)" : "pulled/imported " + wsRes.imported)
              : "sync failed" + (wsRes.error ? ": " + wsRes.error : "")}
          </div>
        )}
      </Section>
    </div>
  );
}

// #269: dedicated WebSockets history tab. WS frames already flow through
// the ordinary HTTP-history rows -- proxy_server.cpp's runWebSocketRelay
// emits a synthetic WS↑/WS↓ entry per reassembled message, with
// req.path holding "(<opcode>[ deflate], <n> B[, continued])" (the only
// place the opcode/deflate/continued flags are carried) and req.body/
// resp.body holding the real payload bytes -- but only as pseudo-HTTP rows
// mixed into the Proxy tab's HTTP HISTORY table, where Status/Mime/Size are
// cosmetic (always 101 / text-or-octet-stream / payload size) and there is
// no per-connection grouping, no direction/type-only filter, and no
// per-message comment. This tab reuses those same NL.rows entries (no new
// backend call), groups them by host:port "connection" (the only grouping
// key a history row carries -- concurrent tunnels to the same host:port
// interleave in one bucket, a real remaining limitation since the row
// shape has no per-tunnel session id), decodes the opcode/deflate/
// continued flags out of path, and adds a client-side per-message comment
// (localStorage-persisted, matching the Comparer/Decoder client-only-state
// pattern -- there is no backend field for a WS message comment). The
// detail view reuses proxy.jsx's DetailPane, the exact component the Proxy
// tab already renders these rows through, so Raw/Headers/Body/Hex/
// Inspector and every Send-to- pivot behave identically here.
//
// Real remaining gap, unchanged by this tab and not claimed fixed here:
// runWebSocketRelay is only invoked from the TLS-MITM h1 keep-alive loop's
// 101 Upgrade branch, so a plaintext ws:// (non-TLS) tunnel is never
// captured -- a genuine backend capability gap vs Burp, not a frontend one.
const WS_PATH_RE = /^\((\w+)( deflate)?, (\d+) B(, continued)?\)$/;

function WebSocketsTab({ rows, dispatch, onSwitchTab }) {
  const [connKey, setConnKey] = React.useState(null);
  const [dir, setDir] = React.useState("all"); // all | up | down
  const [kindFilter, setKindFilter] = React.useState("all"); // all | text | binary | close | ping | pong | ...
  const [selectedId, setSelectedId] = React.useState(null);
  const [comments, setComments] = React.useState(() => {
    try { return JSON.parse(localStorage.getItem("nl-ws-comments") || "{}") || {}; }
    catch (e) { return {}; }
  });

  const wsRows = React.useMemo(() => {
    return (rows || [])
      .filter(r => r.method === "WS↑" || r.method === "WS↓")
      .map(r => {
        const m = WS_PATH_RE.exec(r.path || "");
        return {
          ...r,
          wsDir: r.method === "WS↑" ? "up" : "down",
          wsKind: m ? m[1] : "?",
          wsDeflate: !!(m && m[2]),
          wsContinued: !!(m && m[4]),
        };
      });
  }, [rows]);

  const connections = React.useMemo(() => {
    const map = new Map();
    for (const r of wsRows) {
      const key = r.host + ":" + r.port;
      let c = map.get(key);
      if (!c) { c = { key, host: r.host, port: r.port, tls: r.tls, count: 0, up: 0, down: 0, lastId: 0, lastTs: r.ts }; map.set(key, c); }
      c.count++;
      if (r.wsDir === "up") c.up++; else c.down++;
      if (r.id > c.lastId) { c.lastId = r.id; c.lastTs = r.ts; }
    }
    return Array.from(map.values()).sort((a, b) => b.lastId - a.lastId);
  }, [wsRows]);

  React.useEffect(() => {
    if (connKey != null && connections.some(c => c.key === connKey)) return;
    setConnKey(connections.length ? connections[0].key : null);
  }, [connections, connKey]);

  const messages = React.useMemo(() => {
    return wsRows
      .filter(r => connKey == null || (r.host + ":" + r.port) === connKey)
      .filter(r => dir === "all" || r.wsDir === dir)
      .filter(r => kindFilter === "all" || r.wsKind === kindFilter)
      .sort((a, b) => a.id - b.id);
  }, [wsRows, connKey, dir, kindFilter]);

  React.useEffect(() => {
    if (selectedId != null && messages.some(m => m.id === selectedId)) return;
    setSelectedId(messages.length ? messages[messages.length - 1].id : null);
  }, [messages, selectedId]);

  const selectedRow = messages.find(m => m.id === selectedId) || null;

  const setComment = (id, text) => {
    setComments(prev => {
      const next = { ...prev, [id]: text };
      try { localStorage.setItem("nl-ws-comments", JSON.stringify(next)); } catch (e) { /* storage unavailable/full -- comment stays in-memory only */ }
      return next;
    });
  };

  const Btn = ({ label, onClick, active }) => (
    <button onClick={onClick} style={{
      background: active ? "var(--accent)" : "transparent",
      color: active ? "var(--bg-deep)" : "var(--accent)",
      border: "1px solid var(--accent)", padding: "2px 8px",
      fontSize: "10px", fontFamily: "var(--ff-mono)", cursor: "pointer",
    }}>{label}</button>
  );

  return (
    <div style={{ display: "flex", height: "100%", minHeight: 0 }}>
      <div className="pane" style={{ width: 260, flex: "0 0 260px", display: "flex", flexDirection: "column", minHeight: 0, borderRight: "1px solid var(--line)" }}>
        <div className="pane-head">
          <span className="ph-corner">▸</span>
          <span>CONNECTIONS</span>
          <span className="ph-count">{connections.length}</span>
        </div>
        <div style={{ overflow: "auto", flex: 1 }}>
          {connections.length === 0 && (
            <div style={{ padding: 12, color: "var(--dim)", fontSize: "11px" }}>
              no WebSocket traffic captured yet — open a wss:// connection through
              the intercepting proxy (plaintext ws:// tunnels aren't relayed, only
              the TLS-MITM leg is).
            </div>
          )}
          {connections.map(c => (
            <div key={c.key} onClick={() => setConnKey(c.key)}
                 style={{
                   padding: "6px 10px", cursor: "pointer", fontSize: "11px",
                   background: connKey === c.key ? "var(--row-sel)" : "transparent",
                   borderBottom: "1px solid var(--line-soft)",
                 }}>
              <div style={{ color: "var(--text)" }}>
                <span className={"tls-dot " + (c.tls ? "" : "off")} />{c.host}:{c.port}
              </div>
              <div style={{ color: "var(--dim)" }}>{c.count} msgs · ↑{c.up} ↓{c.down}</div>
            </div>
          ))}
        </div>
      </div>
      <div className="pane" style={{ flex: 1, display: "grid", gridTemplateRows: "auto auto 1fr 1fr", minHeight: 0 }}>
        <div className="pane-head">
          <span className="ph-corner">▸</span>
          <span>WEBSOCKETS</span>
          <span className="ph-count">{messages.length} / {wsRows.length}</span>
        </div>
        <div style={{ display: "flex", gap: 6, alignItems: "center", padding: "6px 10px", borderBottom: "1px solid var(--line)", flexWrap: "wrap" }}>
          <span style={{ color: "var(--dim)", fontSize: "10px" }}>DIRECTION</span>
          <Btn label="ALL" active={dir === "all"} onClick={() => setDir("all")} />
          <Btn label="↑ UP" active={dir === "up"} onClick={() => setDir("up")} />
          <Btn label="↓ DOWN" active={dir === "down"} onClick={() => setDir("down")} />
          <span style={{ color: "var(--dim)", fontSize: "10px", marginLeft: 10 }}>TYPE</span>
          {["all", "text", "binary", "close", "ping", "pong"].map(k => (
            <Btn key={k} label={k.toUpperCase()} active={kindFilter === k} onClick={() => setKindFilter(k)} />
          ))}
        </div>
        <div style={{ minHeight: 0, overflow: "auto", borderBottom: "1px solid var(--line)" }}>
          <table className="tbl">
            <colgroup>
              <col style={{ width: 44 }} />
              <col style={{ width: 70 }} />
              <col style={{ width: 130 }} />
              <col style={{ width: 70 }} />
              <col style={{ width: 90 }} />
              <col />
            </colgroup>
            <thead>
              <tr>
                <th>#</th><th>Dir</th><th>Type</th><th>Len</th><th>Time</th><th>Comment</th>
              </tr>
            </thead>
            <tbody>
              {messages.map(m => (
                <tr key={m.id} className={selectedId === m.id ? "sel" : ""} onClick={() => setSelectedId(m.id)}>
                  <td className="num">{m.id.toString().padStart(3, "0")}</td>
                  <td>{m.wsDir === "up" ? "↑ up" : "↓ down"}</td>
                  <td>{m.wsKind}{m.wsDeflate ? " (deflate)" : ""}{m.wsContinued ? " …" : ""}</td>
                  <td className="num">{fmtSize(m.size)}</td>
                  <td className="num">{m.ts}</td>
                  <td onClick={e => e.stopPropagation()}>
                    <input value={comments[m.id] || ""} onChange={e => setComment(m.id, e.target.value)}
                           placeholder="…" style={{
                             background: "var(--bg-deep)", color: "var(--text)", border: "1px solid var(--line)",
                             padding: "2px 4px", fontSize: "11px", fontFamily: "var(--ff-mono)", width: "100%", boxSizing: "border-box",
                           }} />
                  </td>
                </tr>
              ))}
              {messages.length === 0 && (
                <tr><td colSpan={6} style={{ textAlign: "center", color: "var(--dim)", height: 80 }}>
                  ╌╌  no messages match filters  ╌╌
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
        <DetailPane
          row={selectedRow}
          onSendRepeater={() => selectedRow && dispatch({ type: "send-to-repeater", row: selectedRow })}
          onSendIntruder={() => selectedRow && dispatch({ type: "send-to-intruder", row: selectedRow })}
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
          }}
        />
      </div>
    </div>
  );
}

function CollaboratorTab() {
  // Self-hosted Collaborator client: mint out-of-band callback URLs, hand
  // them to the target by any route (paste into a param, a header, an XXE
  // body — anywhere), and watch interactions land. The backend already
  // mints tokens and retains an HTTP-hit ring (oast_server.cpp); this was
  // the last un-wired piece — previously just a status badge (app.jsx
  // "OAST: {oastDomain}"). No backend change: /api/oast/mint and
  // /api/oast/poll already return everything rendered below.
  const [payloads, setPayloads] = React.useState([]);
  const [hits, setHits]         = React.useState([]);
  const [selected, setSelected] = React.useState(null);
  const [running, setRunning]   = React.useState(null);
  const [baseHost, setBaseHost] = React.useState("");
  const [port, setPort]         = React.useState(0);
  const [autoPoll, setAutoPoll] = React.useState(true);
  const [busy, setBusy]         = React.useState(false);
  const [err, setErr]           = React.useState("");
  const [copied, setCopied]     = React.useState("");
  const sinceRef = React.useRef(0);

  // Blast: the multi-vector SSRF/XXE/blind-RCE/Log4Shell spray. Distinct from
  // mint-and-watch — this fires a battery of OOB probes at one target in one
  // call, each with its own registered token, so any callback auto-confirms
  // as a finding tagged with its attack class (control_server.cpp /api/oast/blast).
  const [blastUrl, setBlastUrl]           = React.useState("");
  const [blastSsrf, setBlastSsrf]         = React.useState(true);
  const [blastXxe, setBlastXxe]           = React.useState(true);
  const [blastRce, setBlastRce]           = React.useState(true);
  const [blastLog4shell, setBlastLog4shell] = React.useState(false);
  const [blastBusy, setBlastBusy]         = React.useState(false);
  const [blastErr, setBlastErr]           = React.useState("");
  const [blastResult, setBlastResult]     = React.useState(null);

  const poll = React.useCallback(async () => {
    try {
      const r = await NL.actions.oastPoll(sinceRef.current);
      if (!r) return;
      setRunning(!!r.running);
      setBaseHost(r.baseHost || "");
      setPort(r.port || 0);
      if (r.hits && r.hits.length) {
        sinceRef.current = r.hits.reduce((m, h) => Math.max(m, h.id), sinceRef.current);
        setHits(prev => [...r.hits.slice().reverse(), ...prev].slice(0, 500));
      }
    } catch (e) { /* transient network blip; next tick retries */ }
  }, []);

  React.useEffect(() => {
    poll();
    if (!autoPoll) return;
    const t = setInterval(poll, 3000);
    return () => clearInterval(t);
  }, [poll, autoPoll]);

  const mint = async () => {
    setErr(""); setBusy(true);
    try {
      const r = await NL.actions.oastMint({});
      if (r && r.ok === false) setErr(r.error || "mint failed");
      else setPayloads(prev => [{ ...r, mintedAt: Date.now() }, ...prev]);
    } catch (e) { setErr(String(e && e.message ? e.message : e)); }
    finally { setBusy(false); }
  };

  const blast = async () => {
    if (!blastUrl) { setBlastErr("enter a target URL"); return; }
    setBlastErr(""); setBlastBusy(true); setBlastResult(null);
    try {
      const r = await NL.actions.oastBlast({
        url: blastUrl, ssrf: blastSsrf, xxe: blastXxe, rce: blastRce, log4shell: blastLog4shell,
      });
      if (r && r.ok === false) setBlastErr(r.error || "blast failed");
      else setBlastResult(r);
    } catch (e) { setBlastErr(String(e && e.message ? e.message : e)); }
    finally { setBlastBusy(false); }
  };

  const copy = (text, key) => {
    try { navigator.clipboard?.writeText(text); setCopied(key); setTimeout(() => setCopied(""), 1000); } catch (e) {}
  };
  const fmtTime = (ms) => { try { return new Date(ms).toLocaleTimeString(); } catch (e) { return String(ms); } };

  const Btn = ({ label, onClick, disabled }) => (
    <button onClick={onClick} disabled={disabled || busy} style={{
      background: "transparent",
      color: (disabled || busy) ? "var(--dim)" : "var(--accent)",
      border: "1px solid var(--accent)", padding: "4px 10px", fontSize: "11px",
      fontFamily: "var(--ff-mono)", cursor: (disabled || busy) ? "wait" : "pointer",
      letterSpacing: "0.04em", textTransform: "uppercase",
    }}>{label}</button>
  );
  const th = { textAlign: "left", color: "var(--dim)", fontWeight: 500, padding: "3px 12px 3px 0", whiteSpace: "nowrap", verticalAlign: "top" };
  const td = { padding: "3px 12px 3px 0", wordBreak: "break-word", color: "var(--text)", verticalAlign: "top" };
  const inp = {
    background: "var(--bg-deep)", color: "var(--text)", border: "1px solid var(--line)",
    borderRadius: 4, padding: "5px 8px", fontSize: "12px", fontFamily: "var(--ff-mono)",
  };
  const Section = ({ title, hint, children }) => (
    <div style={{ background: "var(--pane)", border: "1px solid var(--line)", borderRadius: 4, padding: 12, display: "flex", flexDirection: "column", gap: 8 }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 10, flexWrap: "wrap" }}>
        <span style={{ fontSize: "11px", color: "var(--accent)", textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600 }}>{title}</span>
        {hint && <span style={{ color: "var(--dim)", fontSize: "11px" }}>{hint}</span>}
      </div>
      {children}
    </div>
  );

  return (
    <div style={{ padding: 14, display: "flex", flexDirection: "column", gap: 12, height: "100%", minHeight: 0, overflow: "auto" }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 12, flexWrap: "wrap" }}>
        <span style={{ fontSize: "11px", color: "var(--accent)", textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600 }}>Collaborator</span>
        <span style={{ color: "var(--dim)", fontSize: "11px" }}>
          self-hosted out-of-band interaction client —{" "}
          {running === null ? "checking…" : running
            ? <span style={{ color: "var(--accent)" }}>running on {baseHost}:{port}</span>
            : <span style={{ color: "var(--err)" }}>OAST server not running</span>}
        </span>
        {err && <span style={{ color: "var(--err)", fontSize: "11px" }}>{err}</span>}
      </div>

      <Section title="Payloads" hint="mint a unique callback URL, paste it anywhere on the target, watch for interactions below">
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <Btn label="Mint payload" onClick={mint} disabled={running === false} />
          <Btn label="Poll now" onClick={poll} />
          <label style={{ display: "flex", alignItems: "center", gap: 5, color: "var(--dim)", fontSize: "11px", cursor: "pointer" }}>
            <input type="checkbox" checked={autoPoll} onChange={e => setAutoPoll(e.target.checked)} />
            auto-poll (3s)
          </label>
        </div>
        {payloads.length === 0
          ? <div style={{ color: "var(--dim)", fontSize: "12px" }}>no payloads minted yet</div>
          : (
            <table style={{ borderCollapse: "collapse", fontSize: "12px", fontFamily: "var(--ff-mono)", width: "100%" }}>
              <thead><tr>{["minted", "token", "url", ""].map((c, i) => <th key={i} style={th}>{c}</th>)}</tr></thead>
              <tbody>
                {payloads.map((p, i) => {
                  const url = p.hostUrl || p.pathUrl;
                  const key = "p" + i;
                  return (
                    <tr key={i}>
                      <td style={td}>{fmtTime(p.mintedAt)}</td>
                      <td style={td}><span style={{ color: "var(--dim)" }}>{p.token}</span></td>
                      <td style={{ ...td, wordBreak: "break-all" }}><span style={{ color: "var(--accent)" }}>{url}</span></td>
                      <td style={td}><Btn label={copied === key ? "copied" : "copy"} onClick={() => copy(url, key)} /></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
      </Section>

      <Section title="Blast" hint="fire SSRF / blind-XXE / blind-RCE / Log4Shell out-of-band probes at one target in a single call — confirmed callbacks surface in Interactions below and as findings">
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <input value={blastUrl} onChange={e => setBlastUrl(e.target.value)}
            placeholder="https://target/endpoint" style={{ ...inp, flex: "1 1 260px", minWidth: 200 }} />
          {[
            ["SSRF", blastSsrf, setBlastSsrf],
            ["XXE", blastXxe, setBlastXxe],
            ["RCE", blastRce, setBlastRce],
            ["Log4Shell", blastLog4shell, setBlastLog4shell],
          ].map(([label, val, set]) => (
            <label key={label} style={{ display: "flex", alignItems: "center", gap: 5, color: "var(--dim)", fontSize: "11px", cursor: "pointer" }}>
              <input type="checkbox" checked={val} onChange={e => set(e.target.checked)} />
              {label}
            </label>
          ))}
          <Btn label="Fire" onClick={blast} disabled={running === false || !blastUrl || blastBusy} />
        </div>
        {blastErr && <div style={{ color: "var(--err)", fontSize: "11px" }}>{blastErr}</div>}
        {blastResult && (
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            <div style={{ color: "var(--dim)", fontSize: "11px" }}>
              {blastResult.fired} vector(s) fired at <span style={{ color: "var(--text)" }}>{blastResult.target}</span>
            </div>
            {blastResult.vectors && blastResult.vectors.length > 0 && (
              <table style={{ borderCollapse: "collapse", fontSize: "12px", fontFamily: "var(--ff-mono)", width: "100%" }}>
                <thead><tr>{["kind", "note", "token", "callback url"].map((c, i) => <th key={i} style={th}>{c}</th>)}</tr></thead>
                <tbody>
                  {blastResult.vectors.map((v, i) => (
                    <tr key={i}>
                      <td style={td}>{v.kind}</td>
                      <td style={td}>{v.note}</td>
                      <td style={td}><span style={{ color: "var(--dim)" }}>{v.token}</span></td>
                      <td style={{ ...td, wordBreak: "break-all" }}><span style={{ color: "var(--accent)" }}>{v.callbackUrl}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}
      </Section>

      <Section title={"Interactions (" + hits.length + ")"} hint="HTTP callbacks only — DNS-only interactions aren't retained by the DNS sink yet, so pure-DNS confirmations stay invisible here">
        <div style={{ display: "flex", gap: 12, minHeight: 0, flex: 1 }}>
          <div style={{ flex: "1 1 55%", overflow: "auto", maxHeight: 320 }}>
            {hits.length === 0
              ? <div style={{ color: "var(--dim)", fontSize: "12px" }}>no interactions yet</div>
              : (
                <table style={{ borderCollapse: "collapse", fontSize: "12px", fontFamily: "var(--ff-mono)", width: "100%" }}>
                  <thead><tr>{["time", "method", "path", "source", "bytes"].map((c, i) => <th key={i} style={th}>{c}</th>)}</tr></thead>
                  <tbody>
                    {hits.map((h) => (
                      <tr key={h.id} onClick={() => setSelected(h)}
                          style={{ cursor: "pointer", background: selected && selected.id === h.id ? "var(--bg-deep)" : "transparent" }}>
                        <td style={td}>{fmtTime(h.atMs)}</td>
                        <td style={td}>{h.method}</td>
                        <td style={{ ...td, wordBreak: "break-all" }}>{h.path}</td>
                        <td style={td}>{h.sourceIp}</td>
                        <td style={td}>{h.bodyBytes}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
          </div>
          <div style={{ flex: "1 1 45%", background: "var(--bg-deep)", border: "1px solid var(--line)", borderRadius: 4, padding: 10, fontSize: "12px", fontFamily: "var(--ff-mono)", overflow: "auto", maxHeight: 320 }}>
            {!selected
              ? <span style={{ color: "var(--dim)" }}>click an interaction to see detail</span>
              : (
                <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  <div><span style={{ color: "var(--dim)" }}>token</span> {selected.token}</div>
                  <div><span style={{ color: "var(--dim)" }}>time</span> {fmtTime(selected.atMs)}</div>
                  <div><span style={{ color: "var(--dim)" }}>source ip</span> {selected.sourceIp}</div>
                  <div><span style={{ color: "var(--dim)" }}>method</span> {selected.method}</div>
                  <div><span style={{ color: "var(--dim)" }}>host header</span> {selected.hostHeader}</div>
                  <div style={{ wordBreak: "break-all" }}><span style={{ color: "var(--dim)" }}>path</span> {selected.path}</div>
                  <div><span style={{ color: "var(--dim)" }}>user agent</span> {selected.userAgent}</div>
                  <div><span style={{ color: "var(--dim)" }}>body bytes</span> {selected.bodyBytes}</div>
                  {selected.bodyPreview && (
                    <div>
                      <div style={{ color: "var(--dim)", marginTop: 4 }}>body preview</div>
                      <pre style={{ whiteSpace: "pre-wrap", wordBreak: "break-all", margin: 0, color: "var(--text-2)" }}>{selected.bodyPreview}</pre>
                    </div>
                  )}
                </div>
              )}
          </div>
        </div>
      </Section>
    </div>
  );
}

const TEST_TYPES = [
  "sqli", "xss", "ssrf", "ssti", "idor", "cmdi", "openredirect", "xxe",
  "nosqli", "crlf", "ldapi", "xpathi", "massassign", "protopollution",
  "race", "deser", "hostheader", "cors", "cswsh", "verbtamper", "methods",
  "smuggle", "takeover", "cachedeception", "pathtraversal",
  // NOTE: jwt is deliberately excluded. /api/jwt/test needs a `token` (the
  // currently-valid captured JWT to calibrate against) which this tab's
  // uniform {url, param?, method?} contract has no field for -- it would
  // always fail with "token required". Real JWT active-testing lives in
  // the Inspector tab's JWT TOOLKIT (paste token -> Active test), alongside
  // offline analyze/forge.
];

function TestsTab() {
  // Unified launcher for the active-vulnerability arsenal: 24 /api/<type>/test
  // backends that existed with no UI (of the 26 in the family, jwt needs a
  // token field this uniform form can't provide -- see Inspector's JWT
  // toolkit -- and cache/poison has a distinct request shape entirely).
  // Uniform {url, param?, method?} request; results (hits/findings) render
  // generically and also flow to Issues.
  const [url, setUrl]     = React.useState("");
  const [param, setParam] = React.useState("");
  const [method, setMethod] = React.useState("");
  const [type, setType]   = React.useState("sqli");
  const [res, setRes]     = React.useState(null);
  const [busy, setBusy]   = React.useState(false);
  const [err, setErr]     = React.useState("");
  const [ranType, setRanType] = React.useState("");

  const run = async () => {
    if (!url) { setErr("enter a target URL"); return; }
    setErr(""); setBusy(true); setRes(null); setRanType(type);
    try {
      const r = await NL.actions.runTest(type, url, param, method);
      if (r && r.ok === false && r.error) { setErr(r.error); setRes(null); }
      else setRes(r);
    } catch (e) { setErr(String(e && e.message ? e.message : e)); }
    finally { setBusy(false); }
  };

  const sevColor = (s) => ({
    critical: "var(--err)", high: "#ea580c", medium: "#d97706",
    low: "#3f8f29", info: "var(--dim)",
  }[String(s || "").toLowerCase()] || "var(--text-2)");

  // The result array is hits | findings | detections | results depending on the
  // test; render each item's scalar fields generically so one view fits all 26.
  const items = res ? (res.hits || res.findings || res.detections || res.results || []) : [];
  const isVuln = res && (res.vulnerable === true || items.length > 0);

  const inp = {
    background: "var(--bg-deep)", color: "var(--text)", border: "1px solid var(--line)",
    borderRadius: 4, padding: "5px 8px", fontSize: "12px", fontFamily: "var(--ff-mono)",
  };

  return (
    <div style={{ padding: 14, display: "flex", flexDirection: "column", gap: 10, height: "100%", minHeight: 0 }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}>
        <span style={{ fontSize: "11px", color: "var(--accent)", textTransform: "uppercase", letterSpacing: "0.06em", fontWeight: 600 }}>Active tests</span>
        <span style={{ color: "var(--dim)", fontSize: "11px" }}>run a single active check against an authorized target — findings also go to Issues</span>
      </div>
      <div style={{ background: "var(--pane)", border: "1px solid var(--line)", padding: 10, borderRadius: 4, display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
        <input value={url} onChange={e => setUrl(e.target.value)} placeholder="https://target/path?id=1"
               onKeyDown={e => { if (e.key === "Enter") run(); }}
               style={{ ...inp, flex: "1 1 300px", minWidth: 200 }} spellCheck={false} />
        <input value={param} onChange={e => setParam(e.target.value)} placeholder="param (optional)"
               style={{ ...inp, flex: "0 1 150px" }} spellCheck={false} />
        <select value={method} onChange={e => setMethod(e.target.value)} style={{ ...inp, flex: "0 0 90px" }}>
          <option value="">auto</option><option value="GET">GET</option><option value="POST">POST</option>
        </select>
        <select value={type} onChange={e => setType(e.target.value)} style={{ ...inp, flex: "0 0 150px" }}>
          {TEST_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <button onClick={run} disabled={busy} style={{
          background: "var(--accent)", color: busy ? "var(--dim)" : "var(--bg)",
          border: "1px solid var(--accent)", padding: "5px 14px", fontSize: "11px",
          fontFamily: "var(--ff-mono)", cursor: busy ? "wait" : "pointer",
          letterSpacing: "0.04em", textTransform: "uppercase", fontWeight: 600,
        }}>{busy ? "running…" : "▶ run"}</button>
        <span style={{ color: "var(--err)", fontSize: "11px" }}>{err}</span>
      </div>
      <div style={{ flex: 1, overflow: "auto", background: "var(--pane)", border: "1px solid var(--line)", borderRadius: 4, padding: 12, minHeight: 0 }}>
        {!res ? <span style={{ color: "var(--dim)", fontSize: "12px" }}>pick a test type and run — results appear here and in Issues</span> : (
          <div>
            <div style={{ marginBottom: 10, fontSize: "12px", fontFamily: "var(--ff-mono)" }}>
              <span style={{ color: "var(--accent)", textTransform: "uppercase" }}>{ranType}</span>
              {"  "}
              <span style={{ color: isVuln ? "var(--err)" : "var(--ok, #6c8)", fontWeight: 600 }}>
                {isVuln ? "VULNERABLE" : "no findings"}
              </span>
              <span style={{ color: "var(--dim)" }}>{"  · " + items.length + " result" + (items.length === 1 ? "" : "s")}</span>
            </div>
            {items.map((it, i) => (
              <div key={i} style={{ border: "1px solid var(--line)", borderRadius: 4, padding: 8, marginBottom: 8 }}>
                {Object.keys(it).filter(k => it[k] !== "" && it[k] != null && typeof it[k] !== "object").map(k => (
                  <div key={k} style={{ display: "flex", gap: 10, fontSize: "12px", fontFamily: "var(--ff-mono)", padding: "1px 0" }}>
                    <span style={{ color: "var(--dim)", minWidth: 90 }}>{k}</span>
                    <span style={{ color: k === "severity" ? sevColor(it[k]) : "var(--text)", wordBreak: "break-all" }}>{String(it[k])}</span>
                  </div>
                ))}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// #357: Decoder gzip encode/decode. Pure client-side via the browser's
// Compression Streams API -- no backend call, since transcode.cpp has no
// gzip operation (only content_decode.hpp's proxy-only auto-unpack does,
// see #345). Binary in/out is represented as base64 text, matching the
// existing b64-decode convention of falling back to a hex dump when the
// decoded bytes aren't valid UTF-8.
function bytesToBase64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}
function base64ToBytes(b64) {
  const bin = atob(b64.replace(/\s/g, ""));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
async function gzipEncodeText(text) {
  if (typeof CompressionStream === "undefined") {
    throw new Error("gzip compression needs a browser with the Compression Streams API (Chrome 80+, Firefox 113+, Safari 16.4+)");
  }
  const cs = new CompressionStream("gzip");
  const writer = cs.writable.getWriter();
  // Swallow write/close rejections here -- the same underlying error
  // surfaces (and is handled) via the arrayBuffer() read below; leaving
  // these unhandled would otherwise log/throw an unhandled-rejection.
  writer.write(new TextEncoder().encode(text)).catch(() => {});
  writer.close().catch(() => {});
  const buf = await new Response(cs.readable).arrayBuffer();
  return bytesToBase64(new Uint8Array(buf));
}
async function gzipDecodeText(b64) {
  if (typeof DecompressionStream === "undefined") {
    throw new Error("gzip decompression needs a browser with the Compression Streams API (Chrome 80+, Firefox 113+, Safari 16.4+)");
  }
  let bytes;
  try { bytes = base64ToBytes(b64.trim()); }
  catch (e) { throw new Error("input isn't valid base64 gzip data"); }
  const ds = new DecompressionStream("gzip");
  const writer = ds.writable.getWriter();
  writer.write(bytes).catch(() => {});
  writer.close().catch(() => {});
  const buf = await new Response(ds.readable).arrayBuffer();
  const outBytes = new Uint8Array(buf);
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(outBytes);
  } catch (e) {
    let bin = "";
    for (let i = 0; i < outBytes.length; i++) bin += String.fromCharCode(outBytes[i]);
    return toHexDump(bin);
  }
}

function DecoderTab({ decoder }) {
  const [input, setInput]   = React.useState("");
  const [output, setOutput] = React.useState("");
  const [activeOp, setOp]   = React.useState("");
  const [err, setErr]       = React.useState("");
  const [chain, setChain]   = React.useState([]);
  const [copied, setCopied] = React.useState(false);

  // #323 "Send to Decoder": Proxy/Repeater/Intercept dispatch send-to-decoder,
  // which bumps decoder.seedNonce in the app reducer. Every bump (even a
  // repeat of the same text) overwrites this tab's local input and clears
  // any stale output from a previous run.
  const seedNonce = decoder && decoder.seedNonce;
  React.useEffect(() => {
    if (!seedNonce) return;
    setInput(decoder.seedText || "");
    setOutput(""); setOp(""); setErr(""); setChain([]);
  }, [seedNonce]);
  // Per-block Text/Hex view (#358): flip either pane to a hex dump without
  // mutating the underlying value, so a non-printing or non-ASCII byte in
  // a decode result is visible instead of silently disappearing in a
  // plain textarea. Hex view is read-only in both blocks; the input box
  // itself is still edited as text (see DECODER-HEX-LOSSY note below).
  const [inputView, setInputView]   = React.useState("text");
  const [outputView, setOutputView] = React.useState("text");

  const OPS = [
    "base64-encode", "base64-decode", "base64url-encode", "base64url-decode",
    "url-encode", "url-decode", "html-encode", "html-decode",
    "hex-encode", "hex-decode", "unicode-escape", "unicode-unescape",
    "rot13", "jwt-decode", "octal-encode", "octal-decode",
    "binary-encode", "binary-decode",
    "md4", "md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3-256",
    "graphql-parse", "grpc-frame", "cbor-decode", "saml-decode",
    "gzip-encode", "gzip-decode",
  ];

  // #326: the four protocol decoders (graphql-parse/grpc-frame/cbor-decode/
  // saml-decode) already exist as pure client-side codecs in proxy.jsx's
  // CodecBar (runCodec()) and never hit /api/transcode -- route those
  // op names to runCodec directly instead of the backend round-trip every
  // other op uses.
  const CLIENT_ONLY_OPS = { "graphql-parse": 1, "grpc-frame": 1, "cbor-decode": 1, "saml-decode": 1 };
  // #357: gzip encode/decode, likewise never hits /api/transcode (no
  // backend op exists for it), but the Compression Streams API is async
  // unlike runCodec, so it gets its own dispatch table.
  const ASYNC_CLIENT_OPS = { "gzip-encode": gzipEncodeText, "gzip-decode": gzipDecodeText };

  const run = async (operation) => {
    setOp(operation); setErr(""); setChain([]);
    if (CLIENT_ONLY_OPS[operation]) {
      try { setOutput(runCodec(operation, input)); }
      catch (e) { setErr(String(e && e.message ? e.message : e)); }
      return;
    }
    if (ASYNC_CLIENT_OPS[operation]) {
      try { setOutput(await ASYNC_CLIENT_OPS[operation](input)); }
      catch (e) { setErr(String(e && e.message ? e.message : e)); }
      return;
    }
    try {
      const r = await NL.actions.transcode(operation, input);
      setOutput(r.output || "");
      if (r.chain && r.chain.length) setChain(r.chain);
      if (!r.ok) setErr(r.error || "failed");
    } catch (e) { setErr(String(e && e.message ? e.message : e)); }
  };

  const copy = () => {
    try { navigator.clipboard?.writeText(output); setCopied(true); setTimeout(() => setCopied(false), 1000); } catch (e) {}
  };
  const useOutputAsInput = () => { setInput(output); setOutput(""); setChain([]); setErr(""); };

  const Btn = ({ label, onClick, primary, disabled, title }) => (
    <button onClick={onClick} disabled={disabled} title={title}
      style={{
        background: primary ? "var(--accent)" : "transparent",
        color: disabled ? "var(--dim)" : primary ? "var(--bg)" : "var(--accent)",
        border: "1px solid " + (disabled ? "var(--line)" : "var(--accent)"),
        padding: "4px 9px", fontSize: "10.5px", fontFamily: "var(--ff-mono)",
        cursor: disabled ? "not-allowed" : "pointer", letterSpacing: "0.04em",
        textTransform: "uppercase", whiteSpace: "nowrap",
      }}>{label}</button>
  );

  const area = {
    width: "100%", boxSizing: "border-box", background: "var(--bg-deep)",
    color: "var(--text)", border: "1px solid var(--line)", borderRadius: 4,
    padding: 8, fontSize: "12px", fontFamily: "var(--ff-mono)", resize: "none",
    flex: 1, minHeight: 0, whiteSpace: "pre-wrap", wordBreak: "break-all",
  };
  const hexArea = { ...area, whiteSpace: "pre", overflowX: "auto", fontSize: "11px" };

  const ViewToggle = ({ view, onChange }) => (
    <div style={{ display: "flex", border: "1px solid var(--line)", borderRadius: 3, overflow: "hidden" }}>
      {["text", "hex"].map(v => (
        <button key={v} onClick={() => onChange(v)} title={v === "hex" ? "Hex dump (read-only)" : "Plain text"}
          style={{
            background: view === v ? "var(--accent)" : "transparent",
            color: view === v ? "var(--bg)" : "var(--dim)",
            border: "none", padding: "2px 7px", fontSize: "9.5px",
            fontFamily: "var(--ff-mono)", textTransform: "uppercase",
            letterSpacing: "0.04em", cursor: "pointer",
          }}>{v}</button>
      ))}
    </div>
  );

  return (
    <div style={{ padding: 14, display: "flex", flexDirection: "column",
                  gap: 10, height: "100%", minHeight: 0 }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}>
        <span style={{ fontSize: "11px", color: "var(--accent)", textTransform: "uppercase",
                       letterSpacing: "0.06em", fontWeight: 600 }}>Decoder</span>
        <span style={{ color: "var(--dim)", fontSize: "11px" }}>
          encode · decode · hash · smart auto-decode · JWT · hash-ID
        </span>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10,
                    flex: 1, minHeight: 0 }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 6, minHeight: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ fontSize: "10px", color: "var(--dim)", textTransform: "uppercase",
                          letterSpacing: "0.06em", flex: 1 }}>Input</div>
            <ViewToggle view={inputView} onChange={setInputView} />
          </div>
          {inputView === "hex" ? (
            <textarea style={{ ...hexArea, color: "var(--dim)" }} value={toHexDump(input)} readOnly spellCheck={false} />
          ) : (
            <textarea style={area} value={input} placeholder="paste text to transform…"
                      onChange={e => setInput(e.target.value)} spellCheck={false} />
          )}
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 6, minHeight: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ fontSize: "10px", color: "var(--dim)", textTransform: "uppercase",
                          letterSpacing: "0.06em", flex: 1 }}>
              Output {activeOp ? "· " + activeOp : ""}
              {chain.length ? " · chain: " + chain.join(" → ") : ""}
            </div>
            <ViewToggle view={outputView} onChange={setOutputView} />
            <Btn label={copied ? "copied" : "copy"} onClick={copy} disabled={!output} />
            <Btn label="↑ input" title="Use output as the new input (chain transforms)"
                 onClick={useOutputAsInput} disabled={!output} />
          </div>
          {outputView === "hex" ? (
            <textarea style={{ ...hexArea, color: "var(--dim)" }} value={toHexDump(output)} readOnly spellCheck={false} />
          ) : (
            <textarea style={{ ...area, color: err ? "var(--err)" : "var(--text)" }}
                      value={err ? (output ? output + "\n\n[" + err + "]" : "[" + err + "]") : output}
                      readOnly spellCheck={false} />
          )}
        </div>
      </div>

      <div style={{ background: "var(--pane)", border: "1px solid var(--line)",
                    padding: 10, borderRadius: 4, display: "flex", gap: 6, flexWrap: "wrap",
                    alignItems: "center" }}>
        <Btn label="✦ smart decode" primary onClick={() => run("smart")}
             title="Auto-detect the encoding and recursively decode" />
        <Btn label="identify hash" onClick={() => run("identify")}
             title="Guess the hash algorithm by length + charset" />
        <span style={{ width: 1, height: 18, background: "var(--line)", margin: "0 2px" }} />
        {OPS.map(o => (
          <Btn key={o} label={o} primary={o === activeOp} onClick={() => run(o)} />
        ))}
      </div>
    </div>
  );
}

function PayloadsTab() {
  const [technique, setTechnique] = React.useState("all");
  const [data, setData]       = React.useState(null);   // server response
  const [loading, setLoading] = React.useState(false);
  const [err, setErr]         = React.useState("");
  const [copied, setCopied]   = React.useState(-1);

  const copy = (text, i) => {
    try {
      navigator.clipboard?.writeText(text);
      setCopied(i);
      setTimeout(() => setCopied(-1), 1000);
    } catch (e) {}
  };

  const forge = async (t) => {
    const tech = t || technique;
    setTechnique(tech);
    setLoading(true);
    setErr("");
    try {
      const r = await NL.actions.forgePayloads(tech);
      setData(r);
    } catch (e) {
      setErr(String(e && e.message ? e.message : e));
    }
    setLoading(false);
  };

  const TECHS = ["all", "ssti", "cmdi", "xxe", "sqli", "xss", "jwt",
                 "lfi", "ssrf", "redirect", "nosqli", "ldap", "crlf"];
  const payloads = (data && data.payloads) || [];

  const Btn = ({ label, onClick, primary, disabled, title }) => (
    <button onClick={onClick} disabled={disabled} title={title}
      style={{
        background: primary ? "var(--accent)" : "transparent",
        color: disabled ? "var(--dim)" : primary ? "var(--bg)" : "var(--accent)",
        border: "1px solid " + (disabled ? "var(--line)" : "var(--accent)"),
        padding: "4px 10px", fontSize: "11px",
        fontFamily: "var(--ff-mono)", cursor: disabled ? "not-allowed" : "pointer",
        letterSpacing: "0.05em", textTransform: "uppercase",
      }}>{label}</button>
  );

  return (
    <div style={{ padding: 14, display: "flex", flexDirection: "column",
                  gap: 10, height: "100%", minHeight: 0 }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}>
        <span style={{
          fontSize: "11px", color: "var(--accent)", textTransform: "uppercase",
          letterSpacing: "0.06em", fontWeight: 600,
        }}>Payload Forge</span>
        <span style={{ color: "var(--dim)", fontSize: "11px" }}>
          ready-to-run PoC payloads · SSTI · cmd-injection · XXE · SQLi · XSS · JWT alg=none
        </span>
      </div>

      <div style={{
        background: "var(--pane)", border: "1px solid var(--line)",
        padding: 12, borderRadius: 4, display: "flex", gap: 8,
        alignItems: "center", flexWrap: "wrap",
      }}>
        {TECHS.map(t => (
          <Btn key={t} label={t} primary={t === technique}
               onClick={() => forge(t)} />
        ))}
        <span style={{ color: "var(--dim)", fontSize: "11px", marginLeft: 8 }}>
          {loading ? "forging…" : (data ? (data.count + " payloads") : "pick a technique")}
          {err ? " · " + err : ""}
        </span>
      </div>

      {data ? (
        <div style={{ color: "var(--dim)", fontSize: "11px", display: "flex",
                      gap: 16, flexWrap: "wrap" }}>
          <span>marker: <span style={{ color: "var(--text)" }}>{data.marker}</span></span>
          <span>OAST: {data.oastDomain
            ? <span style={{ color: "var(--text)" }}>{data.oastDomain}</span>
            : <span style={{ color: "var(--err)" }}>offline — OOB payloads omitted</span>}</span>
        </div>
      ) : null}

      <div style={{ flex: 1, minHeight: 0, overflow: "auto", display: "flex",
                    flexDirection: "column", gap: 8 }}>
        {payloads.map((p, i) => (
          <div key={i} style={{
            background: "var(--pane)", border: "1px solid var(--line)",
            borderRadius: 4, padding: 10, display: "flex", flexDirection: "column",
            gap: 6,
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ color: "var(--text)", fontSize: "12px", fontWeight: 600 }}>
                {p.variant}</span>
              <span style={{
                fontSize: "9px", color: "var(--dim)", border: "1px solid var(--line)",
                borderRadius: 3, padding: "1px 5px", textTransform: "uppercase",
              }}>{p.technique}</span>
              {p.oob ? (
                <span style={{
                  fontSize: "9px", color: "var(--bg)", background: "var(--accent)",
                  borderRadius: 3, padding: "1px 5px", textTransform: "uppercase",
                }}>oob</span>
              ) : null}
              <div style={{ flex: 1 }} />
              <Btn label={copied === i ? "copied" : "copy"}
                   onClick={() => copy(p.payload, i)} />
            </div>
            <pre style={{
              margin: 0, padding: 8, background: "var(--bg-deep)",
              border: "1px solid var(--line)", borderRadius: 3,
              fontSize: "11.5px", fontFamily: "var(--ff-mono)", color: "var(--text)",
              whiteSpace: "pre-wrap", wordBreak: "break-all", overflow: "auto",
            }}>{p.payload}</pre>
            {p.note ? (
              <div style={{ color: "var(--dim)", fontSize: "10.5px" }}>{p.note}</div>
            ) : null}
          </div>
        ))}
        {!loading && data && payloads.length === 0 ? (
          <div style={{ color: "var(--dim)", fontSize: "11px", padding: 8 }}>
            No payloads for this technique.
          </div>
        ) : null}
      </div>
    </div>
  );
}

function ReconTab() {
  const [, force] = React.useReducer(x => x + 1, 0);
  React.useEffect(() => {
    const onUpdate = () => force();
    window.addEventListener("nl-update", onUpdate);
    return () => window.removeEventListener("nl-update", onUpdate);
  }, []);

  const rec = (window.NL && NL.recon) ? NL.recon
            : { target: "", running: false, dns: [], subdomains: [], error: "" };
  const [domain, setDomain] = React.useState("");
  React.useEffect(() => { if (rec.target && !domain) setDomain(rec.target); }, [rec.target]);

  const runAll = async () => {
    const d = domain.trim();
    if (!d) return;
    await NL.actions.reconDns(d);
    await NL.actions.reconCrt(d);
    await NL.actions.reconWordlist(d, SUBDOMAIN_WORDLIST);
  };

  // Group DNS records by type for display.
  const dnsByType = {};
  for (const r of rec.dns) {
    (dnsByType[r.type] = dnsByType[r.type] || []).push(r);
  }
  const dnsOrder = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR"];

  // Sort subdomains: resolved first, alphabetical within
  const sortedSubs = [...rec.subdomains].sort((a, b) => {
    const ar = (a.ips && a.ips.length) ? 1 : 0;
    const br = (b.ips && b.ips.length) ? 1 : 0;
    if (ar !== br) return br - ar;
    return a.name.localeCompare(b.name);
  });

  const Btn = ({ label, onClick, primary, danger, disabled, title }) => (
    <button onClick={onClick} disabled={disabled} title={title}
      style={{
        background: primary ? "var(--accent)" : "transparent",
        color: disabled ? "var(--dim)" : primary ? "var(--bg)"
             : danger ? "var(--err)" : "var(--accent)",
        border: "1px solid " + (disabled ? "var(--line)"
                              : danger ? "var(--err)" : "var(--accent)"),
        padding: "4px 10px", fontSize: "11px",
        fontFamily: "var(--ff-mono)", cursor: disabled ? "not-allowed" : "pointer",
        letterSpacing: "0.05em", textTransform: "uppercase",
      }}>{label}</button>
  );

  const inp = {
    background: "var(--bg-deep)", color: "var(--text)",
    border: "1px solid var(--line)", padding: "4px 6px",
    fontSize: "12px", fontFamily: "var(--ff-mono)",
  };

  return (
    <div style={{ padding: 14, display: "flex", flexDirection: "column",
                  gap: 10, height: "100%", minHeight: 0 }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}>
        <span style={{
          fontSize: "11px", color: "var(--accent)", textTransform: "uppercase",
          letterSpacing: "0.06em", fontWeight: 600,
        }}>Recon</span>
        <span style={{ color: "var(--dim)", fontSize: "11px" }}>
          DNS · reverse DNS (PTR) · certificate transparency · wordlist subdomain enum
        </span>
      </div>

      <div style={{
        background: "var(--pane)", border: "1px solid var(--line)",
        padding: 12, borderRadius: 4, display: "flex", gap: 8,
        alignItems: "center", flexWrap: "wrap",
      }}>
        <input style={{ ...inp, flex: 1, minWidth: 200 }}
               value={domain}
               placeholder="example.com  (or an IP, e.g. 1.2.3.4, for Reverse DNS)"
               onChange={e => setDomain(e.target.value)}
               onKeyDown={e => { if (e.key === "Enter") runAll(); }} />
        <Btn label="Run all" primary onClick={runAll} disabled={!domain.trim()} />
        <Btn label="DNS only"   onClick={() => domain && NL.actions.reconDns(domain.trim())} />
        <Btn label="crt.sh"     onClick={() => domain && NL.actions.reconCrt(domain.trim())} />
        <Btn label="Wordlist"   onClick={() => domain && NL.actions.reconWordlist(domain.trim(), SUBDOMAIN_WORDLIST)} />
        <Btn label="Reverse DNS" onClick={() => domain && NL.actions.reconReverse(domain.trim())}
             title="PTR lookup — put an IP (1.2.3.4 or ::1) in the field" />
        <Btn label="WHOIS" onClick={() => domain && NL.actions.reconWhois(domain.trim())}
             title="WHOIS lookup — follows the IANA → registry/registrar referral" />
        <Btn label="Stop"  danger onClick={() => NL.actions.reconStop()}  disabled={!rec.running} />
        <Btn label="Clear"        onClick={() => NL.actions.reconClear()} disabled={rec.running} />
        <span style={{ color: "var(--dim)", fontSize: "11px", marginLeft: 8 }}>
          {rec.running ? "running…" : "ready"}
          {rec.error ? " · " + rec.error : ""}
        </span>
      </div>

      {rec.whois ? (
        <div style={{
          background: "var(--pane)", border: "1px solid var(--line)",
          borderRadius: 4, display: "flex", flexDirection: "column",
          maxHeight: 260, minHeight: 0,
        }}>
          <div style={{
            padding: "6px 10px", borderBottom: "1px solid var(--line)",
            fontSize: "10px", color: "var(--dim)", textTransform: "uppercase",
            letterSpacing: "0.06em",
          }}>WHOIS</div>
          <pre style={{
            overflow: "auto", flex: 1, margin: 0, padding: 10,
            fontSize: "11.5px", fontFamily: "var(--ff-mono)", color: "var(--text)",
            whiteSpace: "pre-wrap", wordBreak: "break-word",
          }}>{rec.whois}</pre>
        </div>
      ) : null}

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10,
                    flex: 1, minHeight: 0 }}>
        {/* DNS RECORDS */}
        <div style={{
          background: "var(--pane)", border: "1px solid var(--line)",
          borderRadius: 4, display: "flex", flexDirection: "column", minHeight: 0,
        }}>
          <div style={{
            padding: "6px 10px", borderBottom: "1px solid var(--line)",
            fontSize: "10px", color: "var(--dim)", textTransform: "uppercase",
            letterSpacing: "0.06em", display: "flex",
          }}>
            <span style={{ flex: 1 }}>DNS records</span>
            <span>{rec.dns.length}</span>
          </div>
          <div style={{ overflow: "auto", flex: 1, padding: 8 }}>
            {rec.dns.length === 0 && (
              <div style={{ color: "var(--dim)", fontSize: "12px", textAlign: "center", padding: 16 }}>
                no records yet
              </div>
            )}
            {dnsOrder.map(type => {
              const rows = dnsByType[type] || [];
              if (rows.length === 0) return null;
              return (
                <div key={type} style={{ marginBottom: 10 }}>
                  <div style={{
                    color: "var(--accent)", fontSize: "10.5px",
                    textTransform: "uppercase", letterSpacing: "0.06em",
                    fontFamily: "var(--ff-mono)", paddingBottom: 4,
                    borderBottom: "1px solid var(--line-soft)",
                  }}>{type} ({rows.length})</div>
                  {rows.map((r, i) => (
                    <div key={i} style={{
                      fontSize: "11.5px", fontFamily: "var(--ff-mono)",
                      color: "var(--text)", padding: "3px 4px",
                      display: "flex", gap: 8,
                    }}>
                      {type === "MX" && (
                        <span style={{ color: "var(--dim)", minWidth: 32 }}>{r.priority}</span>
                      )}
                      <span style={{
                        flex: 1, overflow: "hidden",
                        textOverflow: "ellipsis", whiteSpace: "nowrap",
                      }} title={r.value}>{r.value}</span>
                    </div>
                  ))}
                </div>
              );
            })}
          </div>
        </div>

        {/* SUBDOMAINS */}
        <div style={{
          background: "var(--pane)", border: "1px solid var(--line)",
          borderRadius: 4, display: "flex", flexDirection: "column", minHeight: 0,
        }}>
          <div style={{
            padding: "6px 10px", borderBottom: "1px solid var(--line)",
            fontSize: "10px", color: "var(--dim)", textTransform: "uppercase",
            letterSpacing: "0.06em", display: "flex",
          }}>
            <span style={{ flex: 1 }}>Subdomains</span>
            <span>{rec.subdomains.length}</span>
          </div>
          <div style={{ overflow: "auto", flex: 1 }}>
            {rec.subdomains.length === 0 && (
              <div style={{ color: "var(--dim)", fontSize: "12px", textAlign: "center", padding: 16 }}>
                no subdomains discovered yet
              </div>
            )}
            {sortedSubs.map((s, i) => {
              const resolved = s.ips && s.ips.length;
              return (
                <div key={i} style={{
                  display: "grid",
                  gridTemplateColumns: "1fr 60px 1fr",
                  gap: 6, padding: "5px 10px", alignItems: "baseline",
                  fontSize: "12px", fontFamily: "var(--ff-mono)",
                  borderBottom: "1px solid var(--line-soft)",
                  opacity: resolved ? 1 : 0.55,
                }}>
                  <span style={{ color: "var(--text)", overflow: "hidden",
                                 textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                        title={s.name}>{s.name}</span>
                  <span style={{ color: s.source === "crt.sh" ? "#8ee5a0" : "var(--accent)",
                                 fontSize: "10px" }}>{s.source}</span>
                  <span style={{ color: "var(--text-2)", overflow: "hidden",
                                 textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                        title={(s.ips || []).join(", ")}>
                    {resolved ? s.ips.join(", ") : "(historical)"}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}

// Cookie / session manager. Captures every Set-Cookie response into a
// per-host bag. Toggle "auto-inject" on a host and all outgoing
// requests for that host get the captured cookies merged into their
// Cookie header. Burp-flavored "log in once, scan with that session".
// Session handling rules (Burp's "Sessions > Session handling rules"
// macro engine, session_rules.hpp): extract a value from a matched
// response (header/cookie/JSON-path/regex), store it under a variable,
// and inject it into every subsequent matched request (header/cookie/
// body/URL). The backend's /api/session-rules/set replaces the WHOLE
// rule list in one call -- no per-rule add/update/remove/toggle
// endpoints exist -- so these pure helpers build the next full array
// from the current one; the editor POSTs the result back wholesale.
const EXTRACT_FROM_LABEL = ["Header", "Cookie", "JSON path", "Regex (body, 1st group)"];
const INJECT_INTO_LABEL  = ["Header", "Cookie", "Body ({{var}})", "URL query"];

// Tool-scope bitmask, mirroring SessionRulesLogic::SessionTool
// (session_rules_logic.hpp) exactly -- a rule's `tools` field is 0 (unset)
// for "applies everywhere" (back-compatible with rules authored before
// scoping existed), else a bitwise-OR of the tools it's restricted to.
// Only Proxy/Repeater/Intruder are enforced server-side today (Scanner's
// bit is accepted and round-trips, but nothing yet calls applyToRequest
// with ToolScanner) -- the checkbox is still offered since the backend
// contract already reserves the bit and will honor it once wired.
const SESSION_TOOL_BITS = [
  { bit: 1, label: "Proxy" },
  { bit: 2, label: "Repeater" },
  { bit: 4, label: "Intruder" },
  { bit: 8, label: "Scanner" },
];
function sessionRuleToggleToolBit(mask, bit) {
  return (mask & bit) ? (mask & ~bit) : (mask | bit);
}
function sessionRuleToolsLabel(mask) {
  if (!mask) return "all tools";
  return SESSION_TOOL_BITS.filter(t => mask & t.bit).map(t => t.label).join(", ") || "all tools";
}

function sessionRuleUpsert(rules, index, rule) {
  if (index < 0) return [...rules, rule];
  return rules.map((r, i) => (i === index ? rule : r));
}
function sessionRuleRemoveAt(rules, index) {
  return rules.filter((_, i) => i !== index);
}
function sessionRuleToggle(rules, index) {
  return rules.map((r, i) => (i === index ? { ...r, enabled: !r.enabled } : r));
}

function SessionsTab() {
  const [, force] = React.useReducer(x => x + 1, 0);
  React.useEffect(() => {
    const onUpdate = () => force();
    window.addEventListener("nl-update", onUpdate);
    return () => window.removeEventListener("nl-update", onUpdate);
  }, []);

  const sessions = (window.NL && NL.sessions) ? NL.sessions : [];
  const [expanded, setExpanded] = React.useState(null); // host being shown in detail

  // Cookie jar (full inventory: path/expiry + httpOnly/secure/sameSite
  // percentage rollups) -- distinct from the inject-focused list above,
  // which only ever shows name/value/flags per captured Set-Cookie.
  const [cookieJar, setCookieJar]     = React.useState(null);
  const [cookieJarBusy, setCookieJarBusy] = React.useState(false);
  const loadCookieJar = React.useCallback(async () => {
    setCookieJarBusy(true);
    try { setCookieJar(await NL.actions.cookieJar()); }
    finally { setCookieJarBusy(false); }
  }, []);
  React.useEffect(() => { loadCookieJar(); }, [loadCookieJar]);

  const sessionRules = (window.NL && NL.sessionRules && NL.sessionRules.rules) || [];
  const sessionVars  = (window.NL && NL.sessionRules && NL.sessionRules.variables) || {};
  const SR_DEFAULT = {
    name: "", enabled: true, hostGlob: "*", pathGlob: "*",
    extractFrom: 0, extractKey: "", variable: "",
    injectInto: 0, injectKey: "", injectTemplate: "",
    tools: 0,
  };
  const [srDraft, setSrDraft] = React.useState(SR_DEFAULT);
  const [srEditingIndex, setSrEditingIndex] = React.useState(-1);
  const setSrK = (k, v) => setSrDraft(d => ({ ...d, [k]: v }));
  const srReset = () => { setSrDraft(SR_DEFAULT); setSrEditingIndex(-1); };
  const srSubmit = () => {
    if (!srDraft.variable) return;
    NL.actions.sessionRulesSet(sessionRuleUpsert(sessionRules, srEditingIndex, srDraft));
    srReset();
  };
  const srStartEdit = (i) => { setSrDraft({ ...SR_DEFAULT, ...sessionRules[i] }); setSrEditingIndex(i); };

  const Btn = ({ label, onClick, danger, primary, disabled, title, size }) => (
    <button onClick={onClick} disabled={disabled} title={title}
      style={{
        background: primary ? "var(--accent)" : "transparent",
        color: disabled ? "var(--dim)"
             : primary ? "var(--bg)"
             : danger ? "var(--err)"
             : "var(--accent)",
        border: "1px solid " + (disabled ? "var(--line)"
                              : danger ? "var(--err)"
                              : "var(--accent)"),
        padding: size === "sm" ? "1px 6px" : "4px 10px",
        fontSize: size === "sm" ? "10px" : "11px",
        fontFamily: "var(--ff-mono)", cursor: disabled ? "not-allowed" : "pointer",
        letterSpacing: "0.05em", textTransform: "uppercase",
      }}>{label}</button>
  );

  const fmtAge = (ms) => {
    if (!ms) return "?";
    const dt = (Date.now() - ms) / 1000;
    if (dt < 60)    return Math.floor(dt) + "s ago";
    if (dt < 3600)  return Math.floor(dt / 60) + "m ago";
    if (dt < 86400) return Math.floor(dt / 3600) + "h ago";
    return Math.floor(dt / 86400) + "d ago";
  };

  const sorted = [...sessions].sort((a, b) => {
    if (a.autoInject !== b.autoInject) return a.autoInject ? -1 : 1;
    return (b.lastSeen || 0) - (a.lastSeen || 0);
  });

  return (
    <div style={{ padding: 14, display: "flex", flexDirection: "column",
                  gap: 10, height: "100%", minHeight: 0 }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}>
        <span style={{
          fontSize: "11px", color: "var(--accent)", textTransform: "uppercase",
          letterSpacing: "0.06em", fontWeight: 600,
        }}>Sessions</span>
        <span style={{ color: "var(--dim)", fontSize: "11px" }}>
          captured Set-Cookies, per-host · toggle a row to inject those
          cookies on every outgoing request for that host
        </span>
        <span style={{ flex: 1 }} />
        <Btn label="Clear all" danger
             disabled={sessions.length === 0}
             onClick={() => { if (confirm("Clear ALL captured sessions?")) NL.actions.sessionClearAll(); }} />
      </div>

      {sessions.length === 0 && (
        <div style={{
          background: "var(--pane)", border: "1px solid var(--line)",
          borderRadius: 4, padding: 24, textAlign: "center",
          color: "var(--dim)", fontSize: "12px",
        }}>
          No Set-Cookie responses captured yet. Proxy traffic that
          triggers a login or any cookie-setting endpoint and they'll
          show up here.
        </div>
      )}

      {sorted.map(s => (
        <div key={s.host} style={{
          background: "var(--pane)", border: "1px solid " +
            (s.autoInject ? "var(--accent)" : "var(--line)"),
          borderRadius: 4, padding: 0,
        }}>
          <div style={{
            display: "flex", alignItems: "center", gap: 8,
            padding: "8px 12px",
          }}>
            <span style={{
              width: 8, height: 8, borderRadius: 4,
              background: s.autoInject ? "var(--accent)" : "transparent",
              border: "1px solid var(--accent)",
            }} />
            <span style={{ color: "var(--text)", fontFamily: "var(--ff-mono)",
                           fontSize: "12px", flex: 1, overflow: "hidden",
                           textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                  title={s.host}>{s.host}</span>
            <span style={{ color: "var(--text-2)", fontSize: "11px" }}>
              {s.cookies.length} cookie{s.cookies.length === 1 ? "" : "s"}
            </span>
            <span style={{ color: "var(--dim)", fontSize: "10.5px", minWidth: 60, textAlign: "right" }}>
              {fmtAge(s.lastSeen)}
            </span>
            <label style={{
              display: "flex", gap: 4, alignItems: "center",
              fontSize: "10.5px", color: "var(--text-2)",
              textTransform: "uppercase", letterSpacing: "0.05em",
            }}>
              <input type="checkbox" checked={!!s.autoInject}
                     onChange={e => NL.actions.sessionAutoInject(s.host, e.target.checked)} />
              auto-inject
            </label>
            <Btn label={expanded === s.host ? "Hide" : "View"} size="sm"
                 onClick={() => setExpanded(expanded === s.host ? null : s.host)} />
            <Btn label="Copy to…" size="sm" onClick={() => {
              const to = prompt("Copy this session to which host?", s.host);
              if (to && to !== s.host) NL.actions.sessionCopyTo(s.host, to);
            }} />
            <Btn label="Clear" size="sm" danger onClick={() => {
              if (confirm("Drop captured cookies for " + s.host + "?"))
                NL.actions.sessionClearHost(s.host);
            }} />
          </div>
          {expanded === s.host && (
            <div style={{ borderTop: "1px solid var(--line)",
                          padding: 8, background: "var(--bg-deep)" }}>
              {s.cookies.length === 0 && (
                <div style={{ color: "var(--dim)", fontSize: "11px", padding: 8 }}>
                  (no cookies; backend captured the host but lost the list)
                </div>
              )}
              {s.cookies.map((c, i) => (
                <div key={i} style={{
                  display: "grid",
                  gridTemplateColumns: "160px 1fr 90px",
                  gap: 6, padding: "4px 6px",
                  fontFamily: "var(--ff-mono)", fontSize: "11.5px",
                  borderBottom: "1px solid var(--line-soft)",
                }}>
                  <span style={{ color: "var(--accent)", overflow: "hidden",
                                 textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                        title={c.name}>{c.name}</span>
                  <span style={{ color: "var(--text)", overflow: "hidden",
                                 textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                        title={c.value}>{c.value}</span>
                  <span style={{ color: "var(--dim)", fontSize: "10px", textAlign: "right" }}>
                    {c.httpOnly && "HO "}{c.secure && "S "}{c.sameSite && c.sameSite}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      ))}

      {/* COOKIE JAR -- full per-host cookie inventory (path/expiry, plus
          httpOnly/secure/sameSite percentage rollups), reading /api/cookies
          directly rather than the /api/snapshot sessions block above. */}
      <div style={{ display: "flex", alignItems: "baseline", gap: 12, marginTop: 6 }}>
        <span style={{
          fontSize: "11px", color: "var(--accent)", textTransform: "uppercase",
          letterSpacing: "0.06em", fontWeight: 600,
        }}>Cookie jar</span>
        <span style={{ color: "var(--dim)", fontSize: "11px" }}>
          path/expiry + httpOnly/secure/sameSite coverage per host
        </span>
        <span style={{ flex: 1 }} />
        <Btn label={cookieJarBusy ? "…" : "Refresh"} disabled={cookieJarBusy} onClick={loadCookieJar} />
      </div>

      {cookieJar && (cookieJar.hosts || []).length === 0 && (
        <div style={{
          background: "var(--pane)", border: "1px solid var(--line)",
          borderRadius: 4, padding: 16, textAlign: "center",
          color: "var(--dim)", fontSize: "12px",
        }}>
          No cookies captured yet.
        </div>
      )}

      {cookieJar && (cookieJar.hosts || []).map(h => (
        <div key={h.host} style={{
          background: "var(--pane)", border: "1px solid var(--line)",
          borderRadius: 4, padding: 8,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, fontSize: "11.5px", fontFamily: "var(--ff-mono)", flexWrap: "wrap" }}>
            <span style={{ color: "var(--text)", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={h.host}>{h.host}</span>
            <span style={{ color: "var(--dim)" }}>{h.count} cookie{h.count === 1 ? "" : "s"}</span>
            <span style={{ color: "var(--dim)" }}>HttpOnly {h.httpOnlyPct}%</span>
            <span style={{ color: "var(--dim)" }}>Secure {h.securePct}%</span>
            <span style={{ color: "var(--dim)" }}>SameSite {h.sameSitePct}%</span>
            <Btn label="Add cookie" size="sm" onClick={() => {
              const name = prompt("Cookie name (for " + h.host + "):");
              if (!name) return;
              const value = prompt("Value for " + name + ":", "");
              if (value === null) return;
              NL.actions.sessionSetCookie(h.host, name, value).then(loadCookieJar);
            }} />
          </div>
          {(h.cookies || []).length > 0 && (
            <div style={{ marginTop: 4, display: "flex", flexDirection: "column", gap: 2 }}>
              {h.cookies.map((c, i) => (
                <div key={i} style={{
                  display: "grid", gridTemplateColumns: "160px 90px 1fr 110px 100px",
                  gap: 6, padding: "3px 4px", fontFamily: "var(--ff-mono)", fontSize: "11px",
                  borderBottom: "1px solid var(--line-soft)",
                }}>
                  <span style={{ color: "var(--accent)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={c.name}>{c.name}</span>
                  <span style={{ color: "var(--text-2)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={c.path}>{c.path || "/"}</span>
                  <span style={{ color: "var(--dim)" }}>
                    {c.persistent
                      ? (c.expiresEpoch ? new Date(c.expiresEpoch * 1000).toISOString().slice(0, 19).replace("T", " ") + " UTC" : (c.expires || "persistent"))
                      : "session"}
                  </span>
                  <span style={{ color: "var(--dim)", fontSize: "10px", textAlign: "right" }}>
                    {c.httpOnly && "HO "}{c.secure && "S "}{c.sameSite}
                  </span>
                  <span style={{ display: "flex", gap: 4, justifyContent: "flex-end" }}>
                    <Btn label="Edit" size="sm" onClick={() => {
                      const value = prompt("New value for " + c.name + ":", "");
                      if (value === null) return;
                      NL.actions.sessionSetCookie(h.host, c.name, value, c.path, c.httpOnly, c.secure, c.sameSite)
                        .then(loadCookieJar);
                    }} />
                    <Btn label="Del" size="sm" danger onClick={() => {
                      if (confirm("Delete cookie " + c.name + " for " + h.host + "?"))
                        NL.actions.sessionRemoveCookie(h.host, c.name).then(loadCookieJar);
                    }} />
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      ))}

      {/* SESSION HANDLING RULES -- extract a value from a matched response
          (header/cookie/JSON path/regex), inject it into every subsequent
          matched request. Burp's macro-driven session handling rules. */}
      <div style={{ display: "flex", alignItems: "baseline", gap: 12, marginTop: 6 }}>
        <span style={{
          fontSize: "11px", color: "var(--accent)", textTransform: "uppercase",
          letterSpacing: "0.06em", fontWeight: 600,
        }}>Session handling rules</span>
        <span style={{ color: "var(--dim)", fontSize: "11px" }}>
          {sessionRules.length} rule{sessionRules.length === 1 ? "" : "s"} ·
          {" "}{Object.keys(sessionVars).length} captured variable{Object.keys(sessionVars).length === 1 ? "" : "s"}
        </span>
        <span style={{ flex: 1 }} />
        <Btn label="Clear captured vars" danger
             disabled={Object.keys(sessionVars).length === 0}
             onClick={() => { if (confirm("Clear all captured session-rule variables?")) NL.actions.sessionRulesClearVars(); }} />
      </div>

      {(() => {
        const inputStyle = {
          background: "var(--bg-deep)", color: "var(--text)",
          border: "1px solid var(--line)", padding: "4px 6px",
          fontSize: "12px", fontFamily: "var(--ff-mono)",
        };
        return (
          <div style={{
            background: "var(--pane)", border: "1px solid var(--line)",
            padding: 12, borderRadius: 4, display: "grid",
            gridTemplateColumns: "120px 1fr 120px 1fr", gap: 8,
            alignItems: "center",
          }}>
            <label style={{ fontSize: "11px", color: "var(--dim)" }}>Name</label>
            <input style={inputStyle} value={srDraft.name}
                   placeholder="refresh csrf token"
                   onChange={e => setSrK("name", e.target.value)} />
            <label style={{ fontSize: "11px", color: "var(--dim)" }}>Enabled</label>
            <input type="checkbox" checked={srDraft.enabled}
                   onChange={e => setSrK("enabled", e.target.checked)} />

            <label style={{ fontSize: "11px", color: "var(--dim)" }}>Host glob</label>
            <input style={inputStyle} value={srDraft.hostGlob}
                   placeholder="*.example.com"
                   onChange={e => setSrK("hostGlob", e.target.value)} />
            <label style={{ fontSize: "11px", color: "var(--dim)" }}>Path glob</label>
            <input style={inputStyle} value={srDraft.pathGlob}
                   placeholder="/form* (blank = all)"
                   onChange={e => setSrK("pathGlob", e.target.value)} />

            <label style={{ fontSize: "11px", color: "var(--dim)" }}>Extract from</label>
            <select style={inputStyle} value={srDraft.extractFrom}
                    onChange={e => setSrK("extractFrom", parseInt(e.target.value, 10))}>
              {EXTRACT_FROM_LABEL.map((l, i) => <option key={i} value={i}>{l}</option>)}
            </select>
            <label style={{ fontSize: "11px", color: "var(--dim)" }}>Extract key</label>
            <input style={inputStyle} value={srDraft.extractKey}
                   placeholder="header/cookie name, JSON path, or regex"
                   onChange={e => setSrK("extractKey", e.target.value)} />

            <label style={{ fontSize: "11px", color: "var(--dim)" }}>Store as var</label>
            <input style={inputStyle} value={srDraft.variable}
                   placeholder="csrf_token"
                   onChange={e => setSrK("variable", e.target.value)} />
            <label style={{ fontSize: "11px", color: "var(--dim)" }}>Inject into</label>
            <select style={inputStyle} value={srDraft.injectInto}
                    onChange={e => setSrK("injectInto", parseInt(e.target.value, 10))}>
              {INJECT_INTO_LABEL.map((l, i) => <option key={i} value={i}>{l}</option>)}
            </select>

            <label style={{ fontSize: "11px", color: "var(--dim)" }}>Inject key</label>
            <input style={inputStyle} value={srDraft.injectKey}
                   placeholder="header/cookie/param name"
                   onChange={e => setSrK("injectKey", e.target.value)} />
            <label style={{ fontSize: "11px", color: "var(--dim)" }}>Inject template</label>
            <input style={inputStyle} value={srDraft.injectTemplate}
                   placeholder="{{csrf_token}} (blank = bare variable)"
                   onChange={e => setSrK("injectTemplate", e.target.value)} />

            <label style={{ fontSize: "11px", color: "var(--dim)" }}>Tools scope</label>
            <div style={{ gridColumn: "2 / span 3", display: "flex", gap: 12, flexWrap: "wrap" }}>
              {SESSION_TOOL_BITS.map(t => (
                <label key={t.bit} style={{
                  display: "flex", gap: 4, alignItems: "center",
                  fontSize: "11px", color: "var(--text-2)",
                }}>
                  <input type="checkbox" checked={!!(srDraft.tools & t.bit)}
                         onChange={() => setSrK("tools", sessionRuleToggleToolBit(srDraft.tools || 0, t.bit))} />
                  {t.label}
                </label>
              ))}
              <span style={{ color: "var(--dim)", fontSize: "10.5px" }}>
                (none checked = all tools)
              </span>
            </div>

            <div style={{ gridColumn: "1 / span 4", display: "flex", gap: 6, marginTop: 4 }}>
              <Btn label={srEditingIndex >= 0 ? "Update rule" : "Add rule"}
                   primary onClick={srSubmit} disabled={!srDraft.variable} />
              {srEditingIndex >= 0 && <Btn label="Cancel" onClick={srReset} />}
              <span style={{ flex: 1 }} />
              <span style={{ color: "var(--dim)", fontSize: "11px" }}>
                A value captured from a matching response is stored under its variable name,
                then substituted (as {"{{var}}"}) into every subsequent matching request.
              </span>
            </div>
          </div>
        );
      })()}

      <div style={{
        background: "var(--pane)", border: "1px solid var(--line)",
        borderRadius: 4,
      }}>
        {sessionRules.length === 0 && (
          <div style={{ padding: 16, textAlign: "center", color: "var(--dim)", fontSize: "12px" }}>
            No session handling rules yet. Add one above to auto-refresh a
            CSRF token, JWT, or nonce across requests.
          </div>
        )}
        {sessionRules.map((r, i) => (
          <div key={i} style={{
            display: "grid",
            gridTemplateColumns: "40px 40px 140px 1fr 1fr 1fr 120px 140px",
            gap: 6, padding: "6px 10px", alignItems: "center",
            fontSize: "11.5px", fontFamily: "var(--ff-mono)",
            borderBottom: "1px solid var(--line-soft)",
            opacity: r.enabled ? 1 : 0.45,
          }}>
            <span style={{ color: "var(--dim)" }}>{i + 1}</span>
            <input type="checkbox" checked={!!r.enabled}
                   onChange={() => NL.actions.sessionRulesSet(sessionRuleToggle(sessionRules, i))} />
            <span style={{ color: "var(--text)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {r.name || <span style={{ color: "var(--dim)" }}>(unnamed)</span>}
            </span>
            <span style={{ color: "var(--text-2)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              extract {EXTRACT_FROM_LABEL[r.extractFrom] || "?"} &quot;{r.extractKey}&quot; on {r.hostGlob || "*"}
            </span>
            <span style={{ color: "var(--text-2)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              &rarr; {"{{" + r.variable + "}}"}
            </span>
            <span style={{ color: "var(--text-2)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              inject {INJECT_INTO_LABEL[r.injectInto] || "?"} &quot;{r.injectKey}&quot;
            </span>
            <span style={{ color: "var(--dim)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                  title="Tools this rule is scoped to">
              {sessionRuleToolsLabel(r.tools || 0)}
            </span>
            <span style={{ display: "flex", gap: 4, justifyContent: "flex-end" }}>
              <Btn label="Edit" size="sm" onClick={() => srStartEdit(i)} />
              <Btn label="Del" size="sm" danger onClick={() => {
                if (confirm("Delete rule \"" + (r.name || "(unnamed)") + "\"?"))
                  NL.actions.sessionRulesSet(sessionRuleRemoveAt(sessionRules, i));
              }} />
            </span>
          </div>
        ))}
      </div>

      {Object.keys(sessionVars).length > 0 && (
        <div style={{
          background: "var(--pane)", border: "1px solid var(--line)",
          borderRadius: 4, padding: 8,
        }}>
          <div style={{ fontSize: "10px", color: "var(--dim)", textTransform: "uppercase",
                        letterSpacing: "0.06em", marginBottom: 4 }}>
            Captured variables (this engagement)
          </div>
          {Object.entries(sessionVars).map(([k, v]) => (
            <div key={k} style={{
              display: "grid", gridTemplateColumns: "160px 1fr", gap: 6,
              padding: "3px 4px", fontFamily: "var(--ff-mono)", fontSize: "11.5px",
              borderBottom: "1px solid var(--line-soft)",
            }}>
              <span style={{ color: "var(--accent)" }}>{k}</span>
              <span style={{ color: "var(--text)", overflow: "hidden",
                             textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={v}>{v}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// Wireshark "Statistics > Endpoints"-style aggregator. Walks the live
// history rows and aggregates by host: request count, bytes in/out,
// status-class breakdown, distinct paths, last-seen. No backend call --
// pure derivation from NL.rows so it follows the snapshot poll naturally.
function fmtBytes(n) {
  if (!n) return "0";
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  if (n < 1024 * 1024 * 1024) return (n / 1024 / 1024).toFixed(2) + " MB";
  return (n / 1024 / 1024 / 1024).toFixed(2) + " GB";
}

function StatsTab({ dispatch }) {
  const [, force] = React.useReducer(x => x + 1, 0);
  React.useEffect(() => {
    const onUpdate = () => force();
    window.addEventListener("nl-update", onUpdate);
    return () => window.removeEventListener("nl-update", onUpdate);
  }, []);

  const rows = (window.NL && NL.rows) ? NL.rows : [];
  const [sortBy, setSortBy]   = React.useState("count"); // count|bytes|host|errors
  const [order, setOrder]     = React.useState("desc");
  const [methodMix, setMethodMix] = React.useState(false); // overall method pie-ish bar

  // Aggregate.
  const agg = React.useMemo(() => {
    const byHost = new Map();
    const overall = {
      total: 0, bytesIn: 0, bytesOut: 0,
      sc: { "1xx": 0, "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "ws": 0, "other": 0 },
      methods: {},
      mimes: {},
      tls: 0, plain: 0,
    };
    for (const r of rows) {
      let h = byHost.get(r.host);
      if (!h) {
        h = {
          host: r.host, count: 0, bytesIn: 0, bytesOut: 0,
          sc: { "1xx": 0, "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "ws": 0, "other": 0 },
          paths: new Set(), tls: false, lastTs: "",
          firstId: r.id, lastId: r.id,
        };
        byHost.set(r.host, h);
      }
      h.count++;
      h.bytesIn  += (r.size || 0);
      h.bytesOut += (r.reqSize || 0);
      h.paths.add(r.path || r.url || "");
      h.tls = h.tls || !!r.tls;
      h.lastTs = r.ts || h.lastTs;
      if (r.id > h.lastId) h.lastId = r.id;

      const m = r.method || "";
      const isWs = m === "WS↑" || m === "WS↓";
      let key = "other";
      if (isWs) key = "ws";
      else {
        const status = r.status || 0;
        if (status >= 100 && status < 200) key = "1xx";
        else if (status < 300) key = "2xx";
        else if (status < 400) key = "3xx";
        else if (status < 500) key = "4xx";
        else if (status < 600) key = "5xx";
      }
      h.sc[key]++;
      overall.sc[key]++;
      overall.total++;
      overall.bytesIn  += (r.size || 0);
      overall.bytesOut += (r.reqSize || 0);
      if (r.tls) overall.tls++; else overall.plain++;
      if (m) overall.methods[m] = (overall.methods[m] || 0) + 1;
      if (r.mime) overall.mimes[r.mime] = (overall.mimes[r.mime] || 0) + 1;
    }
    return { byHost: Array.from(byHost.values()), overall };
  }, [rows]);

  const sorted = React.useMemo(() => {
    const arr = [...agg.byHost];
    const dir = order === "asc" ? 1 : -1;
    arr.sort((a, b) => {
      if (sortBy === "host") return dir * a.host.localeCompare(b.host);
      if (sortBy === "bytes") return dir * ((a.bytesIn + a.bytesOut) - (b.bytesIn + b.bytesOut));
      if (sortBy === "errors") {
        const ae = a.sc["4xx"] + a.sc["5xx"];
        const be = b.sc["4xx"] + b.sc["5xx"];
        return dir * (ae - be);
      }
      return dir * (a.count - b.count);
    });
    return arr;
  }, [agg, sortBy, order]);

  const jumpToHost = (host) => {
    // Clears any stale site-map origin scoping (exact host+port+tls) left
    // over from a prior Proxy-tab click -- this is a plain host-substring jump.
    dispatch({ type: "set", payload: { tab: "proxy", hostFilter: host, selectedHost: host, selectedOrigin: null } });
  };

  const setSort = (key) => {
    if (sortBy === key) setOrder(order === "asc" ? "desc" : "asc");
    else { setSortBy(key); setOrder("desc"); }
  };

  const Pill = ({ label, value, color }) => (
    <span style={{
      display: "inline-block", padding: "1px 6px",
      background: "var(--bg-deep)", border: "1px solid var(--line)",
      borderRadius: 3, fontSize: "10px", fontFamily: "var(--ff-mono)",
      color: color || "var(--text-2)", marginRight: 4,
    }}>{label}: {value}</span>
  );

  const SCcell = (sc) => (
    <span style={{ display: "inline-flex", gap: 3 }}>
      {sc["2xx"] > 0 && <span style={{ color: "#8ee5a0" }}>{sc["2xx"]}</span>}
      {sc["3xx"] > 0 && <span style={{ color: "var(--accent)" }}>{sc["3xx"]}</span>}
      {sc["4xx"] > 0 && <span style={{ color: "#f0c060" }}>{sc["4xx"]}</span>}
      {sc["5xx"] > 0 && <span style={{ color: "var(--err, #f88)" }}>{sc["5xx"]}</span>}
      {sc["ws"]  > 0 && <span style={{ color: "var(--dim)" }}>WS:{sc["ws"]}</span>}
    </span>
  );

  return (
    <div style={{
      padding: 14, display: "flex", flexDirection: "column", gap: 10,
      height: "100%", minHeight: 0,
    }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}>
        <span style={{
          fontSize: "11px", color: "var(--accent)", textTransform: "uppercase",
          letterSpacing: "0.06em", fontWeight: 600,
        }}>Network endpoints</span>
        <span style={{ color: "var(--dim)", fontSize: "11px" }}>
          aggregated from {rows.length} captured rows
        </span>
        <span style={{ flex: 1 }} />
        <span style={{ fontSize: "11px", color: "var(--dim)" }}>
          method mix <input type="checkbox" checked={methodMix} onChange={e => setMethodMix(e.target.checked)} />
        </span>
      </div>

      {/* OVERALL */}
      <div style={{
        background: "var(--pane)", border: "1px solid var(--line)",
        padding: 10, borderRadius: 4, display: "flex", flexWrap: "wrap",
        gap: 6, alignItems: "center",
      }}>
        <Pill label="hosts" value={agg.byHost.length} color="var(--accent)" />
        <Pill label="reqs" value={agg.overall.total} />
        <Pill label="↓ resp bytes" value={fmtBytes(agg.overall.bytesIn)} />
        <Pill label="↑ req bytes" value={fmtBytes(agg.overall.bytesOut)} />
        <Pill label="2xx" value={agg.overall.sc["2xx"]} color="#8ee5a0" />
        <Pill label="3xx" value={agg.overall.sc["3xx"]} color="var(--accent)" />
        <Pill label="4xx" value={agg.overall.sc["4xx"]} color="#f0c060" />
        <Pill label="5xx" value={agg.overall.sc["5xx"]} color="var(--err,#f88)" />
        <Pill label="WS" value={agg.overall.sc["ws"]} color="var(--dim)" />
        <Pill label="TLS" value={agg.overall.tls + " (" + (agg.overall.total ? Math.round(agg.overall.tls / agg.overall.total * 100) : 0) + "%)"} />
        <Pill label="plain" value={agg.overall.plain} />
      </div>

      {methodMix && Object.keys(agg.overall.methods).length > 0 && (
        <div style={{
          background: "var(--pane)", border: "1px solid var(--line)",
          padding: 10, borderRadius: 4, fontSize: "11px",
        }}>
          <div style={{ color: "var(--dim)", marginBottom: 4 }}>Method mix</div>
          <div style={{ display: "flex", height: 8, overflow: "hidden", borderRadius: 2 }}>
            {Object.entries(agg.overall.methods).sort((a,b) => b[1]-a[1]).map(([m, c]) => {
              const pct = (c / agg.overall.total) * 100;
              const colors = { GET: "#8ee5a0", POST: "var(--accent)", PUT: "#f0c060",
                              DELETE: "var(--err,#f88)", PATCH: "#c294f0", "WS↑": "#888", "WS↓": "#666" };
              return (
                <div key={m} title={m + ": " + c + " (" + pct.toFixed(1) + "%)"}
                     style={{ width: pct + "%", background: colors[m] || "var(--dim)" }} />
              );
            })}
          </div>
          <div style={{ marginTop: 6, fontFamily: "var(--ff-mono)", fontSize: "10.5px" }}>
            {Object.entries(agg.overall.methods).sort((a,b) => b[1]-a[1]).map(([m, c]) =>
              <span key={m} style={{ marginRight: 10, color: "var(--text-2)" }}>{m}: {c}</span>
            )}
          </div>
        </div>
      )}

      {/* PER-HOST TABLE */}
      <div style={{
        background: "var(--pane)", border: "1px solid var(--line)",
        borderRadius: 4, flex: 1, minHeight: 0, display: "flex", flexDirection: "column",
      }}>
        <div style={{
          display: "grid",
          gridTemplateColumns: "1fr 70px 90px 90px 60px 110px 100px",
          gap: 6, padding: "6px 10px", borderBottom: "1px solid var(--line)",
          fontSize: "10px", color: "var(--dim)", textTransform: "uppercase",
          letterSpacing: "0.06em",
        }}>
          <span style={{ cursor: "pointer" }} onClick={() => setSort("host")}>host {sortBy==="host" ? (order==="asc"?"▲":"▼") : ""}</span>
          <span style={{ cursor: "pointer" }} onClick={() => setSort("count")}>reqs {sortBy==="count" ? (order==="asc"?"▲":"▼") : ""}</span>
          <span style={{ cursor: "pointer" }} onClick={() => setSort("bytes")}>↑ out {sortBy==="bytes" ? (order==="asc"?"▲":"▼") : ""}</span>
          <span>↓ in</span>
          <span>tls</span>
          <span style={{ cursor: "pointer" }} onClick={() => setSort("errors")}>statuses {sortBy==="errors" ? (order==="asc"?"▲":"▼") : ""}</span>
          <span>paths</span>
        </div>
        <div style={{ overflow: "auto", flex: 1 }}>
          {sorted.length === 0 && (
            <div style={{ padding: 24, textAlign: "center", color: "var(--dim)", fontSize: "12px" }}>
              no traffic captured yet
            </div>
          )}
          {sorted.map(h => (
            <div key={h.host}
                 onClick={() => jumpToHost(h.host)}
                 title={"Click to filter Proxy tab by " + h.host}
                 style={{
                   display: "grid",
                   gridTemplateColumns: "1fr 70px 90px 90px 60px 110px 100px",
                   gap: 6, padding: "5px 10px", alignItems: "center",
                   fontSize: "12px", fontFamily: "var(--ff-mono)",
                   borderBottom: "1px solid var(--line-soft)",
                   cursor: "pointer",
                 }}>
              <span style={{ color: "var(--text)", overflow: "hidden",
                             textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                    title={h.host}>{h.host || "(no host)"}</span>
              <span style={{ color: "var(--accent)" }}>{h.count}</span>
              <span style={{ color: "var(--text-2)" }}>{fmtBytes(h.bytesOut)}</span>
              <span style={{ color: "var(--text-2)" }}>{fmtBytes(h.bytesIn)}</span>
              <span style={{ color: h.tls ? "#8ee5a0" : "var(--dim)" }}>{h.tls ? "✓" : "—"}</span>
              <span>{SCcell(h.sc)}</span>
              <span style={{ color: "var(--dim)" }}>{h.paths.size}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// Color edit + Save As panel. Reads the current theme's color map from
// the backend snapshot, applies local edits as inline CSS variables for
// live preview, and posts a full set to /api/theme/save-as on save.
function ColorsEditor() {
  const [, force] = React.useReducer(x => x + 1, 0);
  React.useEffect(() => {
    const onUpdate = () => force();
    window.addEventListener("nl-update", onUpdate);
    return () => window.removeEventListener("nl-update", onUpdate);
  }, []);

  const base = (window.NL && NL.themeColors) ? NL.themeColors : {};
  const [edits, setEdits] = React.useState({});
  const [saveName, setSaveName] = React.useState("");
  const [savedMsg, setSavedMsg] = React.useState("");

  // Apply any edits as inline CSS vars so the user sees the change instantly.
  React.useEffect(() => {
    const root = document.documentElement;
    Object.entries(edits).forEach(([k, v]) => {
      if (v) root.style.setProperty("--" + k, v);
    });
  }, [edits]);

  const merged = { ...base, ...edits };
  const keys = Object.keys(merged).sort();
  const isBuiltin = window.NL && NL.themeIsBuiltin;

  const onChange = (k, v) => setEdits(e => ({ ...e, [k]: v }));
  const onReset = () => {
    // Clear local edits and put the backend's authoritative values back.
    setEdits({});
    const root = document.documentElement;
    Object.entries(base).forEach(([k, v]) => root.style.setProperty("--" + k, v));
  };
  const onSave = async () => {
    const name = saveName.trim() || (window.NL ? (NL.currentTheme || "custom") : "custom");
    const colors = { ...merged };
    const res = await NL.actions.saveTheme(name, colors);
    if (res && res.saved) {
      setEdits({});
      setSaveName("");
      setSavedMsg("Saved as “" + (res.current || name) + "”");
      setTimeout(() => setSavedMsg(""), 2500);
    } else {
      setSavedMsg("Save failed");
      setTimeout(() => setSavedMsg(""), 2500);
    }
  };

  return (
    <TweakSection title={"Colors" + (isBuiltin ? " (forks on save)" : "")}>
      <div style={{ display: "grid", gridTemplateColumns: "1fr auto auto", gap: "4px 10px", alignItems: "center" }}>
        {keys.map(k => (
          <React.Fragment key={k}>
            <div style={{ fontSize: "11px", color: "var(--dim)" }}>--{k}</div>
            <input
              type="color"
              value={merged[k] || "#000000"}
              onChange={e => onChange(k, e.target.value)}
              style={{ width: 36, height: 22, border: "1px solid var(--line)", background: "transparent", padding: 0 }}
            />
            <input
              type="text"
              value={merged[k] || ""}
              onChange={e => onChange(k, e.target.value)}
              style={{
                width: 84, fontFamily: "var(--ff-mono)", fontSize: "11px",
                background: "transparent", color: "var(--text)",
                border: "1px solid var(--line)", padding: "2px 6px",
              }}
              spellCheck={false}
            />
          </React.Fragment>
        ))}
      </div>
      <div style={{ marginTop: 10, display: "flex", gap: 6, alignItems: "center" }}>
        <input
          type="text"
          placeholder={isBuiltin ? "save as… (built-in forks)" : "save as… (leave blank to overwrite)"}
          value={saveName}
          onChange={e => setSaveName(e.target.value)}
          style={{
            flex: 1, fontFamily: "var(--ff-mono)", fontSize: "11px",
            background: "transparent", color: "var(--text)",
            border: "1px solid var(--line)", padding: "4px 6px",
          }}
        />
        <TweakButton label="SAVE"  onClick={onSave} />
        <TweakButton label="RESET" onClick={onReset} />
      </div>
      {savedMsg && (
        <div style={{ marginTop: 4, fontSize: "11px", color: "var(--ok)" }}>{savedMsg}</div>
      )}
    </TweakSection>
  );
}

// Dismissible corner banner for the backend's async update check
// (UpdateChecker, packed into every /api/snapshot as `update`). Pure
// presentational -- App owns the dismissed-version state.
function UpdateBanner({ update, onDismiss }) {
  if (!update || !update.available || !update.latestVersion) return null;
  const openRelease = () => {
    const u = update.releaseUrl;
    if (!u) return;
    if (typeof Qt !== "undefined" && Qt.openUrlExternally) Qt.openUrlExternally(u);
    else window.open(u, "_blank");
  };
  return (
    <div style={{
      position: "fixed", top: 8, right: 8, zIndex: 60, width: 300,
      background: "var(--pane)", border: "1px solid var(--accent)",
      padding: "10px 12px", display: "flex", flexDirection: "column", gap: 6,
      boxShadow: "0 4px 16px rgba(0,0,0,0.35)", fontFamily: "var(--ff-mono)",
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}>
        <span style={{ fontSize: "var(--fz-xs)", letterSpacing: "0.06em", textTransform: "uppercase", color: "var(--accent)", fontWeight: 600 }}>
          Update available
        </span>
        <span onClick={onDismiss} title="Dismiss" style={{ cursor: "pointer", color: "var(--dim)" }}>✕</span>
      </div>
      <div style={{ fontSize: "var(--fz-sm)", color: "var(--text)" }}>
        {update.currentVersion ? `v${update.currentVersion} → ` : ""}v{update.latestVersion}
      </div>
      {update.releaseNotes && (
        <div title={update.releaseNotes} style={{
          fontSize: "var(--fz-xs)", color: "var(--dim)", maxHeight: 60,
          overflow: "auto", whiteSpace: "pre-wrap",
        }}>
          {update.releaseNotes.slice(0, 240)}
        </div>
      )}
      {update.releaseUrl && (
        <button className="btn" onClick={openRelease} style={{ alignSelf: "flex-start" }}>
          VIEW RELEASE
        </button>
      )}
    </div>
  );
}

// Rebindable hotkeys (#247): the global shortcut layer (palette-open,
// tab-jump 1-9) now has a real user-configurable binding map, persisted to
// localStorage the same way nl-update-dismissed/nl-intercept-respmods
// already are. Pure helpers first (testable outside React), then the
// overlay UI that records a new combo per action.
const HOTKEYS_STORAGE_KEY = "nl-hotkeys";

function defaultHotkeys() {
  const map = { "open-palette": "mod+k" };
  for (let i = 1; i <= 9; i++) map["jump-slot-" + i] = "mod+" + i;
  return map;
}

// Only mod-chord combos (Ctrl/Cmd + optional Shift/Alt + a key) are
// recordable/dispatchable -- bare letters would collide with every text
// input on the page. Returns null for a bare modifier press or a
// non-mod-chord key.
function comboFromEvent(e) {
  if (!e || !e.key) return null;
  if (["Control", "Meta", "Shift", "Alt"].includes(e.key)) return null;
  if (!(e.ctrlKey || e.metaKey)) return null;
  const parts = ["mod"];
  if (e.shiftKey) parts.push("shift");
  if (e.altKey) parts.push("alt");
  parts.push(e.key.toLowerCase());
  return parts.join("+");
}

function comboLabel(combo) {
  if (!combo) return "unbound";
  const isMac = typeof navigator !== "undefined" && /Mac/.test(navigator.platform || "");
  return combo.split("+").map((p) => {
    if (p === "mod") return isMac ? "⌘" : "Ctrl";
    if (p === "shift") return "Shift";
    if (p === "alt") return "Alt";
    return p.length === 1 ? p.toUpperCase() : p[0].toUpperCase() + p.slice(1);
  }).join("+");
}

function loadHotkeys() {
  const defaults = defaultHotkeys();
  try {
    const raw = localStorage.getItem(HOTKEYS_STORAGE_KEY);
    if (!raw) return defaults;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return defaults;
    const merged = { ...defaults };
    for (const k of Object.keys(defaults)) {
      if (typeof parsed[k] === "string" && parsed[k]) merged[k] = parsed[k];
    }
    return merged;
  } catch { return defaults; }
}

function saveHotkeys(map) {
  try { localStorage.setItem(HOTKEYS_STORAGE_KEY, JSON.stringify(map)); } catch {}
}

function matchHotkeyAction(hotkeys, combo) {
  if (!combo) return null;
  for (const [action, bound] of Object.entries(hotkeys)) {
    if (bound === combo) return action;
  }
  return null;
}

// Lists every bindable action + lets the user record a new combo for one,
// with a live conflict check against every other current binding (rather
// than silently letting two actions share a combo, matching how a "record
// a shortcut" UI conventionally behaves).
function HotkeysOverlay({ hotkeys, actions, onChange, onReset, onClose }) {
  const [recordingId, setRecordingId] = React.useState(null);
  const [conflict, setConflict] = React.useState(null);

  React.useEffect(() => {
    if (!recordingId) return;
    const onKey = (e) => {
      if (e.key === "Escape") { e.preventDefault(); setRecordingId(null); return; }
      const combo = comboFromEvent(e);
      if (!combo) return;
      e.preventDefault();
      const existing = matchHotkeyAction(hotkeys, combo);
      if (existing && existing !== recordingId) {
        setConflict({ combo, action: existing });
        return;
      }
      setConflict(null);
      onChange(recordingId, combo);
      setRecordingId(null);
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [recordingId, hotkeys, onChange]);

  const defaults = defaultHotkeys();
  const actionLabel = (id) => (actions.find((a) => a.id === id) || {}).label || id;

  return (
    <div onClick={onClose}
         style={{
           position: "fixed", inset: 0, background: "rgba(0,0,0,0.55)",
           display: "flex", justifyContent: "center", alignItems: "flex-start",
           paddingTop: "10vh", zIndex: 80,
         }}>
      <div onClick={(e) => e.stopPropagation()}
           style={{
             background: "var(--pane)", border: "1px solid var(--accent)",
             width: "min(90vw, 480px)", maxHeight: "70vh", overflow: "hidden",
             display: "flex", flexDirection: "column",
             boxShadow: "0 0 0 1px var(--line), 0 12px 40px rgba(0,0,0,0.5)",
           }}>
        <div style={{
          padding: "10px 12px", borderBottom: "1px solid var(--line)",
          fontFamily: "var(--ff-mono)", fontSize: "13px", display: "flex",
          justifyContent: "space-between", alignItems: "center",
        }}>
          <span>Customize shortcuts</span>
          <button className="btn" onClick={onClose}>CLOSE</button>
        </div>
        <div style={{ overflow: "auto", padding: "4px 0" }}>
          {actions.map((a) => (
            <div key={a.id} style={{
              padding: "6px 12px", fontSize: "12px", fontFamily: "var(--ff-mono)",
              display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8,
            }}>
              <span>{a.label}</span>
              <span style={{ display: "flex", gap: 6, alignItems: "center" }}>
                <button className="btn" onClick={() => { setConflict(null); setRecordingId(a.id); }}
                        style={recordingId === a.id ? { borderColor: "var(--accent)" } : undefined}>
                  {recordingId === a.id ? "Press keys… (Esc)" : comboLabel(hotkeys[a.id])}
                </button>
                {hotkeys[a.id] !== defaults[a.id] && (
                  <button className="btn" title="Reset to default" onClick={() => onReset(a.id)}>↺</button>
                )}
              </span>
            </div>
          ))}
        </div>
        {conflict && (
          <div style={{
            padding: "8px 12px", borderTop: "1px solid var(--line)",
            fontSize: "11px", color: "var(--warn, #d9822b)",
          }}>
            "{comboLabel(conflict.combo)}" is already bound to "{actionLabel(conflict.action)}" — rebind that one first, or press a different combo.
          </div>
        )}
      </div>
    </div>
  );
}

// Command palette (#247): fuzzy-searchable list of global commands --
// jump to any tab, or fire one of a handful of cross-cutting toggles --
// opened via Ctrl/Cmd+K or the ⌘K title-bar button. Substring match on
// label + keywords, arrow-key nav, Enter to run, Escape to close (matching
// the existing overlay convention in proxy.jsx).
function CommandPalette({ commands, onClose }) {
  const [query, setQuery] = React.useState("");
  const [active, setActive] = React.useState(0);
  const inputRef = React.useRef(null);

  const results = React.useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return commands;
    return commands.filter(c =>
      c.label.toLowerCase().includes(q) || (c.keywords || "").toLowerCase().includes(q));
  }, [query, commands]);

  React.useEffect(() => { setActive(0); }, [query]);
  React.useEffect(() => { if (inputRef.current) inputRef.current.focus(); }, []);

  const run = (cmd) => { if (cmd) { onClose(); cmd.run(); } };

  const onKeyDown = (e) => {
    if (e.key === "Escape") { e.preventDefault(); onClose(); return; }
    if (e.key === "ArrowDown") { e.preventDefault(); setActive(a => Math.min(a + 1, results.length - 1)); return; }
    if (e.key === "ArrowUp") { e.preventDefault(); setActive(a => Math.max(a - 1, 0)); return; }
    if (e.key === "Enter") { e.preventDefault(); run(results[active]); return; }
  };

  return (
    <div onClick={onClose}
         style={{
           position: "fixed", inset: 0, background: "rgba(0,0,0,0.55)",
           display: "flex", justifyContent: "center", alignItems: "flex-start",
           paddingTop: "12vh", zIndex: 80,
         }}>
      <div onClick={(e) => e.stopPropagation()}
           style={{
             background: "var(--pane)", border: "1px solid var(--accent)",
             width: "min(90vw, 560px)", maxHeight: "60vh", overflow: "hidden",
             display: "flex", flexDirection: "column",
             boxShadow: "0 0 0 1px var(--line), 0 12px 40px rgba(0,0,0,0.5)",
           }}>
        <input
          ref={inputRef}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={onKeyDown}
          placeholder="Type a command or tab name…"
          style={{
            background: "var(--bg-deep)", color: "var(--text)", border: "none",
            borderBottom: "1px solid var(--line)", padding: "10px 12px",
            fontFamily: "var(--ff-mono)", fontSize: "13px", outline: "none",
          }}
        />
        <div style={{ overflow: "auto" }}>
          {results.length === 0 && (
            <div style={{ padding: "10px 12px", color: "var(--dim)", fontSize: "11px" }}>No matching commands</div>
          )}
          {results.map((c, i) => (
            <div key={c.id}
                 onMouseEnter={() => setActive(i)}
                 onClick={() => run(c)}
                 style={{
                   padding: "7px 12px", fontSize: "12px", fontFamily: "var(--ff-mono)", cursor: "pointer",
                   display: "flex", justifyContent: "space-between", gap: 8,
                   background: i === active ? "var(--accent)" : "transparent",
                   color: i === active ? "var(--bg-deep)" : "var(--text)",
                 }}>
              <span>{c.label}</span>
              {c.hint && <span style={{ opacity: 0.7 }}>{c.hint}</span>}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function App() {
  const [tab, setTab] = React.useState("proxy");
  const [tweaks, setTweak] = useTweaks(TWEAK_DEFAULTS);
  const [tweaksOpen, setTweaksOpen] = React.useState(false);
  const [paletteOpen, setPaletteOpen] = React.useState(false);
  const [hotkeys, setHotkeys] = React.useState(loadHotkeys);
  const [hotkeysOpen, setHotkeysOpen] = React.useState(false);
  const [bootShown, setBootShown] = React.useState(() => tweaks.bootSplash !== false);
  const [updateDismissed, setUpdateDismissed] = React.useState(() => {
    try { return localStorage.getItem("nl-update-dismissed") || ""; } catch { return ""; }
  });

  const initialState = React.useMemo(() => ({
    rows: NL.rows,
    selectedRowId: NL.rows[2]?.id ?? null,
    hostFilter: "",
    statusClass: "all",
    methodFilter: "ALL",
    search: "",
    selectedHost: null,
    selectedOrigin: null,
    proxyOn: true,
    logOutOfScope: NL.bootInfo && NL.bootInfo.logOutOfScope === true,
    intercept: false,
    interceptResponses: false,
    interceptAutoContentLength: NL.interceptAutoContentLength,
    intercepted: NL.intercepted,
    scope: NL.scope,
    repeater: NL.repeater,
    comparer: { items: [], selA: null, selB: null },
    // Sequencer: append-only inbox for tokens sent from Proxy history /
    // Repeater (#167 "Send to Sequencer"). SequencerTab keeps its own local
    // textarea state for smooth typing/pasting and just watches this array
    // grow, appending anything new on mount/update -- see SequencerTab.
    sequencer: { tokens: [] },
    // Decoder: client-only seed slot (#323). The Decoder tab keeps its own
    // local input/output useState (nothing to persist across polls), so
    // this is just a hand-off: "Send to Decoder" bumps seedNonce, and
    // DecoderTab's effect watches seedNonce to overwrite its input --
    // bumping (not just setting seedText) is what lets sending the exact
    // same text twice in a row still trigger the overwrite.
    decoder: { seedText: "", seedLabel: "", seedNonce: 0 },
    intruder: {
      // UI-only grep fields: the snapshot never echoes these back, so the
      // nl-snapshot merge ({...state.intruder, ...NL.intruder}) preserves
      // whatever the user typed. grepMatch/grepExtract are what we POST to
      // the backend; grepMatchText/grepExtractRegex are the raw inputs.
      grepMatch: [],
      grepExtract: {},
      grepMatchText: "",
      grepExtractRegex: "",
      // Backend echoes concurrency/throttleMs in every snapshot; these are
      // just first-paint defaults matching IntruderPool::kDefaultConcurrency.
      concurrency: 10,
      throttleMs: 0,
      // Payload-processing rule chain ({op,arg}[]). Like grepMatch above,
      // the snapshot never echoes this back, so nl-snapshot's
      // {...state.intruder, ...NL.intruder} merge preserves whatever the
      // user built here across polls (it's still POSTed on every edit).
      rules: [],
      ...NL.intruder,
      running: false,
    },
  }), []);

  const [state, dispatch] = React.useReducer(reducer, initialState);

  // Live-sync: real-data.js fires 'nl-update' whenever the snapshot poll
  // brings in a fresh payload from the control server. Push it into the
  // reducer so the table, sitemap, repeater state, etc. stay current
  // without the user having to refresh.
  React.useEffect(() => {
    const onUpdate = () => dispatch({ type: "nl-snapshot" });
    window.addEventListener("nl-update", onUpdate);
    return () => window.removeEventListener("nl-update", onUpdate);
  }, []);

  // Global hotkeys (#247): Ctrl/Cmd+K opens the command palette from
  // anywhere (including while an input is focused, matching the palette's
  // own convention of always being reachable); Ctrl/Cmd+1..9 jumps straight
  // to one of the first nine tabs, mirroring the "0N" index badge the tab
  // strip already renders (chrome.jsx TitleBar). Bindings are now
  // user-remappable (HotkeysOverlay below, persisted to localStorage) --
  // dispatch is a lookup against the current `hotkeys` map, not a hardcoded
  // key check. Suspended while the rebind overlay itself is open so
  // recording a new combo there can't also fire the old one here.
  React.useEffect(() => {
    if (hotkeysOpen) return;
    const onKey = (e) => {
      const combo = comboFromEvent(e);
      if (!combo) return;
      const action = matchHotkeyAction(hotkeys, combo);
      if (!action) return;
      if (action === "open-palette") { e.preventDefault(); setPaletteOpen(o => !o); return; }
      const m = /^jump-slot-(\d)$/.exec(action);
      if (m) {
        const t = TABS[Number(m[1]) - 1];
        if (t) { e.preventDefault(); setTab(t.id); }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [hotkeys, hotkeysOpen]);

  const hotkeyActions = React.useMemo(() => ([
    { id: "open-palette", label: "Open command palette" },
    ...TABS.slice(0, 9).map((t, i) => ({ id: "jump-slot-" + (i + 1), label: "Go to " + t.label })),
  ]), []);

  const updateHotkey = React.useCallback((id, combo) => {
    setHotkeys((prev) => { const next = { ...prev, [id]: combo }; saveHotkeys(next); return next; });
  }, []);
  const resetHotkey = React.useCallback((id) => {
    setHotkeys((prev) => { const next = { ...prev, [id]: defaultHotkeys()[id] }; saveHotkeys(next); return next; });
  }, []);

  // intruder ticking (kept as no-op for real-data mode; the snapshot
  // brings in completed rows directly)
  React.useEffect(() => {
    if (!state.intruder.running) return;
    const id = setInterval(() => dispatch({ type: "intruder-tick" }), 240);
    return () => clearInterval(id);
  }, [state.intruder.running]);

  // apply theme + density to document
  React.useEffect(() => {
    document.documentElement.setAttribute("data-theme", tweaks.theme);
    if (tweaks.density === "default") {
      document.documentElement.removeAttribute("data-density");
    } else {
      document.documentElement.setAttribute("data-density", tweaks.density);
    }
    document.documentElement.style.setProperty("--ff-mono", FONT_STACKS[tweaks.fontFamily] || FONT_STACKS["JetBrains Mono"]);
    document.documentElement.style.setProperty("--ff-display", FONT_STACKS[tweaks.fontFamily] || FONT_STACKS["JetBrains Mono"]);
    if (tweaks.accent && tweaks.accent !== "default" && ACCENT_PRESETS[tweaks.accent]) {
      document.documentElement.style.setProperty("--accent", ACCENT_PRESETS[tweaks.accent]);
    } else {
      document.documentElement.style.removeProperty("--accent");
    }
  }, [tweaks]);

  // chrome props -- same filter logic as the table so the "N filtered"
  // counter in the status bar matches what the table actually shows.
  const filtered = state.rows.filter(r => {
    if (state.selectedOrigin) {
      const o = state.selectedOrigin;
      const port = r.port || (r.tls ? 443 : 80);
      if (r.host !== o.host || port !== o.port || !!r.tls !== o.tls) return false;
    } else {
      const tableHostFilter = state.selectedHost || state.hostFilter;
      if (tableHostFilter && !r.host.includes(tableHostFilter)) return false;
    }
    if (state.statusClass !== "all" && (Math.floor(r.status / 100) + "xx") !== state.statusClass) return false;
    if (state.methodFilter !== "ALL" && r.method !== state.methodFilter) return false;
    if (state.search) {
      const s = state.search.toLowerCase();
      const blob = [r.url, r.path, r.host, r.method, r.mime,
                    String(r.status || ""), String(r.params || ""), r.ip || ""]
                    .join(" ").toLowerCase();
      if (!blob.includes(s)) return false;
    }
    return true;
  }).length;
  const hidden = state.rows.length - filtered;
  const h2Count = (window.NL && NL.bootInfo && NL.bootInfo.h2UpstreamCount) || 0;

  const tabsWithDots = TABS.map(t => ({
    ...t,
    dot: (t.id === "intercept" && (state.intercept || state.interceptResponses)) || (t.id === "intruder" && state.intruder.running),
  }));

  const copyCa = () => navigator.clipboard?.writeText(NL.bootInfo.caPath);

  const paletteCommands = React.useMemo(() => ([
    ...TABS.map((t, i) => ({
      id: "tab-" + t.id,
      label: "Go to " + t.label,
      keywords: "tab navigate switch",
      hint: i < 9 ? comboLabel(hotkeys["jump-slot-" + (i + 1)]) : "tab",
      run: () => setTab(t.id),
    })),
    {
      id: "toggle-intercept",
      label: state.intercept ? "Turn intercept OFF" : "Turn intercept ON",
      keywords: "proxy intercept",
      hint: "proxy",
      run: () => dispatch({ type: "intercept-toggle" }),
    },
    {
      id: "toggle-intercept-responses",
      label: state.interceptResponses ? "Stop intercepting responses" : "Intercept responses too",
      keywords: "proxy intercept response",
      hint: "proxy",
      run: () => dispatch({ type: "intercept-responses-toggle" }),
    },
    {
      id: "toggle-tweaks",
      label: "Open appearance / tweaks panel",
      keywords: "theme density font accent settings appearance",
      hint: "ui",
      run: () => setTweaksOpen((o) => !o),
    },
    {
      id: "copy-ca",
      label: "Copy CA certificate path",
      keywords: "cert tls mitm ca",
      hint: "cert",
      run: copyCa,
    },
    {
      id: "customize-shortcuts",
      label: "Customize keyboard shortcuts…",
      keywords: "hotkey hotkeys keybind rebind shortcut settings",
      hint: "ui",
      run: () => setHotkeysOpen(true),
    },
  ]), [state.intercept, state.interceptResponses, hotkeys]);

  const update = (window.NL && NL.update) || { available: false };
  const showUpdateBanner = update.available && update.latestVersion && update.latestVersion !== updateDismissed;
  const dismissUpdate = () => {
    setUpdateDismissed(update.latestVersion);
    try { localStorage.setItem("nl-update-dismissed", update.latestVersion); } catch {}
  };

  return (
    <div className="nl-window" data-screen-label="Nullock">
      {showUpdateBanner && <UpdateBanner update={update} onDismiss={dismissUpdate} />}
      {paletteOpen && <CommandPalette commands={paletteCommands} onClose={() => setPaletteOpen(false)} />}
      {hotkeysOpen && (
        <HotkeysOverlay
          hotkeys={hotkeys}
          actions={hotkeyActions}
          onChange={updateHotkey}
          onReset={resetHotkey}
          onClose={() => setHotkeysOpen(false)}
        />
      )}
      <TitleBar
        tabs={tabsWithDots}
        current={tab}
        onTab={setTab}
        theme={tweaks.theme}
        onTheme={(t) => setTweak("theme", t)}
        onToggleTweaks={() => setTweaksOpen(o => !o)}
        onOpenPalette={() => setPaletteOpen(true)}
      />
      <Rail
        proxyOn={state.proxyOn}
        port={NL.bootInfo.port}
        h2Count={h2Count}
        filtered={hidden}
        total={state.rows.length}
        intercept={state.intercept || state.interceptResponses}
        queue={state.intercepted.length}
        project={NL.bootInfo.project}
        intruderRunning={state.intruder.running}
        intruderProgress={`${state.intruder.results.filter(r => r.status !== null).length}/${state.intruder.payloads.length}`}
      />
      <div style={{ minHeight: 0, overflow: "hidden", position: "relative" }}>
        {tab === "proxy" && (
          <ProxyTab
            state={state}
            dispatch={dispatch}
            showSitemap={tweaks.showSitemap}
            onSwitchTab={setTab}
          />
        )}
        {tab === "scope" && (
          <ScopeTab
            scope={state.scope}
            dispatch={dispatch}
            bootInfo={NL.bootInfo}
            logOutOfScope={state.logOutOfScope}
            onCopyCa={copyCa}
          />
        )}
        {tab === "repeater" && (
          <RepeaterTab rep={state.repeater} dispatch={dispatch} onSwitchTab={setTab} />
        )}
        {tab === "intercept" && (
          <InterceptTab
            intercept={state.intercept}
            interceptResponses={state.interceptResponses}
            interceptAutoContentLength={state.interceptAutoContentLength}
            intercepted={state.intercepted}
            dispatch={dispatch}
            onSwitchTab={setTab}
          />
        )}
        {tab === "intruder" && (
          <IntruderTab intruder={state.intruder} dispatch={dispatch} />
        )}
        {tab === "rules" && (
          <RulesTab />
        )}
        {tab === "issues" && (
          <IssuesTab dispatch={dispatch} />
        )}
        {tab === "scans" && (
          <ScansTab />
        )}
        {tab === "recon" && (
          <ReconTab />
        )}
        {tab === "payloads" && (
          <PayloadsTab />
        )}
        {tab === "decoder" && (
          <DecoderTab decoder={state.decoder} />
        )}
        {tab === "comparer" && (
          <ComparerTab comparer={state.comparer} dispatch={dispatch} />
        )}
        {tab === "inspector" && (
          <InspectorTab />
        )}
        {tab === "probe" && (
          <ProbeTab />
        )}
        {tab === "sequencer" && (
          <SequencerTab sequencer={state.sequencer} dispatch={dispatch} />
        )}
        {tab === "tests" && (
          <TestsTab />
        )}
        {tab === "discover" && (
          <DiscoverTab />
        )}
        {tab === "labs" && (
          <LabsTab dispatch={dispatch} />
        )}
        {tab === "collaborator" && (
          <CollaboratorTab />
        )}
        {tab === "reporting" && (
          <ReportingTab />
        )}
        {tab === "processor" && (
          <ProcessorTab />
        )}
        {tab === "stats" && (
          <StatsTab dispatch={dispatch} />
        )}
        {tab === "sessions" && (
          <SessionsTab />
        )}
        {tab === "websockets" && (
          <WebSocketsTab rows={state.rows} dispatch={dispatch} onSwitchTab={setTab} />
        )}
        {tab === "settings" && (
          <SettingsTab />
        )}
      </div>
      <StatusBar
        proxyOn={state.proxyOn}
        port={NL.bootInfo.port}
        total={state.rows.length}
        filtered={hidden}
        scope={state.scope}
        intercept={state.intercept || state.interceptResponses}
        queue={state.intercepted.length}
        har={NL.bootInfo.harPath}
        onExport={() => {
          act("exportHar");
          // Real path is set by the backend; surface the project's
          // exports/ dir so the user can find it.
          const dir = (window.NL && NL.bootInfo && NL.bootInfo.projectDir)
                        ? NL.bootInfo.projectDir + "\\exports\\"
                        : "<project>/exports/";
          alert("HAR export written to:\n" + dir);
        }}
        onClear={() => dispatch({ type: "clear-history" })}
        onTogglePower={() => dispatch({ type: "toggle-power" })}
      />

      {tweaks.scanlines && <div className="nl-scan" />}
      <div className="nl-vignette" />

      {bootShown && <BootSplash onDone={() => setBootShown(false)} />}

      {tweaksOpen && (
        <TweaksPanel onClose={() => setTweaksOpen(false)} title="TWEAKS">
          <TweakSection title="Theme">
            <TweakSelect
              label="Palette"
              value={NL.currentTheme || tweaks.theme}
              options={(NL.themes && NL.themes.length ? NL.themes : ["cyber"])
                .map(t => ({ value: t, label: t.toUpperCase() }))}
              onChange={v => {
                setTweak("theme", v);
                act("setTheme", v);  // <- tell backend, ThemesManager picks up
              }}
            />
            <TweakColor
              label="Accent override"
              value={tweaks.accent}
              options={Object.keys(ACCENT_PRESETS).map(k => k === "default" ? "transparent" : ACCENT_PRESETS[k])}
              onChange={(hex, idx) => setTweak("accent", Object.keys(ACCENT_PRESETS)[idx])}
            />
          </TweakSection>

          <ColorsEditor />

          <TweakSection title="Layout">
            <TweakRadio
              label="Density"
              value={tweaks.density}
              options={[
                { value: "compact",      label: "Compact" },
                { value: "default",      label: "Default" },
                { value: "comfortable",  label: "Comfort" },
              ]}
              onChange={v => setTweak("density", v)}
            />
            <TweakToggle
              label="Show site map"
              value={tweaks.showSitemap}
              onChange={v => setTweak("showSitemap", v)}
            />
            <TweakToggle
              label="CRT scanlines"
              value={tweaks.scanlines}
              onChange={v => setTweak("scanlines", v)}
            />
            <TweakButton
              label="REPLAY BOOT"
              onClick={() => { setTweaksOpen(false); setBootShown(true); }}
            />
          </TweakSection>
          <TweakSection title="Type">
            <TweakSelect
              label="Mono family"
              value={tweaks.fontFamily}
              options={Object.keys(FONT_STACKS).map(k => ({ value: k, label: k }))}
              onChange={v => setTweak("fontFamily", v)}
            />
          </TweakSection>
        </TweaksPanel>
      )}
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("app")).render(<App />);
