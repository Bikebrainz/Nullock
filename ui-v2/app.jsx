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
  { id: "stats",     label: "STATS" },
  { id: "sessions",  label: "SESSIONS" },
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
        repeater: NL.repeater ? { ...state.repeater, ...NL.repeater } : state.repeater,
        intruder: NL.intruder ? { ...state.intruder, ...NL.intruder } : state.intruder,
        proxyOn: NL.bootInfo && NL.bootInfo.proxyOn !== undefined ? NL.bootInfo.proxyOn : state.proxyOn,
      };
    }

    case "send-to-repeater": {
      if (!action.row) return state;
      const row = action.row;
      const req = NL.requestRawAt(row.id - 1);
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
    case "send-to-intruder": {
      if (!action.row) return state;
      const row = action.row;
      const req = NL.requestRawAt(row.id - 1);
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
    case "intercept-forward": {
      const current = state.intercepted[0];
      act("interceptForward", current ? current.text : "");
      return { ...state, intercepted: state.intercepted.slice(1) };
    }
    case "intercept-drop":
      act("interceptDrop");
      return { ...state, intercepted: state.intercepted.slice(1) };
    case "intercept-forward-all":
      act("interceptForwardAll");
      return { ...state, intercepted: [] };

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

  const b = (window.NL && NL.bootInfo) || {};
  const scope = (window.NL && NL.scope) || { in: [], out: [], notes: "" };
  const rowCount = (window.NL && NL.rows) ? NL.rows.length : 0;
  const blocked = b.mitmBlocked || [];
  const extLog = b.extensionsLog || [];
  const scripts = b.extensionScripts || [];

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

  const Btn = ({ label, onClick, danger }) => (
    <button
      onClick={onClick}
      style={{
        background: "transparent",
        color: danger ? "var(--err)" : "var(--accent)",
        border: "1px solid " + (danger ? "var(--err)" : "var(--accent)"),
        padding: "4px 10px", fontSize: "11px",
        fontFamily: "var(--ff-mono)", cursor: "pointer",
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
        <Row label="MITM bypass" value={blocked.length ? blocked.join(", ") : ""} hint="empty" />
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
      </Card>

      <Card title="Project">
        <Row label="Name" value={b.project} hint="default" />
        <Row label="Path" value={b.projectDir} copyable />
        <Row label="Scope (in)"  value={String((scope.in || []).length) + " globs"} />
        <Row label="Scope (out)" value={String((scope.out || []).length) + " globs"} />
        <Row label="Themes dir" value={b.themesDir || (window.NL ? NL.themesDir : "")} copyable />
        <Row label="Notes" value={scope.notes ? scope.notes.split('\n')[0].slice(0, 60) : ""} hint="(none)" />
        <div style={{ display: "flex", gap: 6, marginTop: 4, flexWrap: "wrap" }}>
          <Btn label="Export HAR" onClick={() => NL.actions.exportHar()} />
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

      <Card
        title={"Extensions (" + scripts.length + ")"}
        action={<Btn label="Reload" onClick={() => NL.actions.reloadExtensions()} />}
      >
        <Row label="Folder" value={b.extensionsDir} copyable />
        <Row label="Loaded" value={scripts.length ? scripts.join(", ") : ""} hint="none yet" />
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

  const Btn = ({ label, onClick, danger, primary, disabled }) => (
    <button
      onClick={onClick}
      disabled={disabled}
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
          gridTemplateColumns: "40px 40px 120px 110px 130px 1fr 1fr 140px",
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
              gridTemplateColumns: "40px 40px 120px 110px 130px 1fr 1fr 140px",
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
const SEVERITY_ORDER = { high: 0, medium: 1, low: 2, info: 3 };
const SEVERITY_COLOR = {
  high:   "var(--err, #f88)",
  medium: "#f0c060",
  low:    "var(--accent)",
  info:   "var(--dim)",
};

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

  // Aggregate counts per severity and per kind for the filter chips.
  const sevCounts  = { high: 0, medium: 0, low: 0, info: 0 };
  const kindCounts = {};
  for (const f of findings) {
    sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1;
    kindCounts[f.kind]    = (kindCounts[f.kind]    || 0) + 1;
  }

  const visible = findings.filter(f =>
    (sevFilter  === "all" || f.severity === sevFilter)
    && (kindFilter === "all" || f.kind     === kindFilter)
  ).sort((a, b) => {
    const sa = SEVERITY_ORDER[a.severity] ?? 4;
    const sb = SEVERITY_ORDER[b.severity] ?? 4;
    if (sa !== sb) return sa - sb;
    return b.id - a.id;  // newest first within same severity
  });

  const jumpToRow = (rowId) => {
    dispatch({ type: "set", payload: { tab: "proxy", selectedRowId: rowId }});
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
          {total} total · showing {visible.length}
        </span>
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
          onClick={() => { if (confirm("Clear all findings?")) NL.actions.clearFindings(); }}
          style={{
            background: "transparent", color: "var(--err, #f88)",
            border: "1px solid var(--err, #f88)", padding: "3px 10px",
            fontSize: "10.5px", fontFamily: "var(--ff-mono)", cursor: "pointer",
            letterSpacing: "0.05em", textTransform: "uppercase",
          }}>Clear all</button>
      </div>

      <div>
        <Chip label="all" active={sevFilter === "all"} onClick={() => setSevFilter("all")} />
        {["high", "medium", "low", "info"].map(s => (
          <Chip key={s} label={s} count={sevCounts[s]}
                color={SEVERITY_COLOR[s]}
                active={sevFilter === s}
                onClick={() => setSevFilter(s)} />
        ))}
      </div>
      <div>
        <Chip label="any kind" active={kindFilter === "all"} onClick={() => setKindFilter("all")} />
        {Object.entries(kindCounts).sort((a, b) => b[1] - a[1]).map(([k, c]) => (
          <Chip key={k} label={k} count={c}
                active={kindFilter === k}
                onClick={() => setKindFilter(k)} />
        ))}
      </div>

      <div style={{
        background: "var(--pane)", border: "1px solid var(--line)",
        borderRadius: 4, flex: 1, minHeight: 0, overflow: "auto",
      }}>
        {visible.length === 0 && (
          <div style={{ padding: 24, textAlign: "center", color: "var(--dim)", fontSize: "12px" }}>
            no findings yet — proxy some traffic and check back
          </div>
        )}
        {visible.map(f => (
          <div key={f.id}
               onClick={() => jumpToRow(f.rowId)}
               style={{
                 display: "grid",
                 gridTemplateColumns: "70px 60px 180px 1fr",
                 gap: 8, padding: "6px 12px",
                 borderBottom: "1px solid var(--line-soft)",
                 alignItems: "baseline",
                 cursor: "pointer", fontSize: "12px",
                 fontFamily: "var(--ff-mono)",
               }}
               title={"Click to jump to row #" + String(f.rowId).padStart(3, "0")}>
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
              <span style={{ color: "var(--text)" }}>{f.summary}</span>
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
            </div>
          </div>
        ))}
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

  return (
    <div style={{ padding: 14, display: "flex", flexDirection: "column", gap: 10, height: "100%", minHeight: 0 }}>
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
        borderRadius: 4, flex: 1, minHeight: 0, display: "flex", flexDirection: "column",
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
function ComparerTab() {
  const [a, setA]         = React.useState("");
  const [b, setB]         = React.useState("");
  const [mode, setMode]   = React.useState("words");
  const [result, setRes]  = React.useState(null);
  const [err, setErr]     = React.useState("");

  const run = async (m) => {
    const mm = m || mode;
    setMode(mm); setErr("");
    try {
      const r = await NL.actions.compareBlobs(mm, a, b);
      setRes(r);
    } catch (e) { setErr(String(e && e.message ? e.message : e)); }
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
    width: "100%", boxSizing: "border-box", background: "var(--bg-deep)",
    color: "var(--text)", border: "1px solid var(--line)", borderRadius: 4,
    padding: 8, fontSize: "12px", fontFamily: "var(--ff-mono)", resize: "none",
    flex: 1, minHeight: 0, whiteSpace: "pre-wrap", wordBreak: "break-all",
  };
  const segStyle = (op) => ({
    background: op === "ins" ? "rgba(70,200,120,0.22)"
              : op === "del" ? "rgba(220,80,80,0.22)" : "transparent",
    color: op === "ins" ? "var(--ok, #6c8)" : op === "del" ? "var(--err)" : "var(--text)",
    textDecoration: op === "del" ? "line-through" : "none",
    whiteSpace: "pre-wrap", wordBreak: "break-all",
  });

  return (
    <div style={{ padding: 14, display: "flex", flexDirection: "column",
                  gap: 10, height: "100%", minHeight: 0 }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}>
        <span style={{ fontSize: "11px", color: "var(--accent)", textTransform: "uppercase",
                       letterSpacing: "0.06em", fontWeight: 600 }}>Comparer</span>
        <span style={{ color: "var(--dim)", fontSize: "11px" }}>
          diff two blobs — word / line / char level
        </span>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10,
                    minHeight: 0, height: "38%" }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 6, minHeight: 0 }}>
          <div style={{ fontSize: "10px", color: "var(--dim)", textTransform: "uppercase",
                        letterSpacing: "0.06em" }}>A</div>
          <textarea style={area} value={a} placeholder="first blob…"
                    onChange={e => setA(e.target.value)} spellCheck={false} />
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 6, minHeight: 0 }}>
          <div style={{ fontSize: "10px", color: "var(--dim)", textTransform: "uppercase",
                        letterSpacing: "0.06em" }}>B</div>
          <textarea style={area} value={b} placeholder="second blob…"
                    onChange={e => setB(e.target.value)} spellCheck={false} />
        </div>
      </div>

      <div style={{ background: "var(--pane)", border: "1px solid var(--line)",
                    padding: 10, borderRadius: 4, display: "flex", gap: 6, flexWrap: "wrap",
                    alignItems: "center" }}>
        <Btn label="compare words" primary={mode === "words"} onClick={() => run("words")} />
        <Btn label="lines" primary={mode === "lines"} onClick={() => run("lines")} />
        <Btn label="chars" primary={mode === "chars"} onClick={() => run("chars")} />
        <span style={{ color: "var(--dim)", fontSize: "11px", marginLeft: 8 }}>
          {err ? err
            : result
              ? (result.identical ? "identical"
                 : ("+" + result.added + " / -" + result.removed + " · " + result.common + " common")
                   + (result.truncated ? " · (truncated)" : ""))
              : "enter two blobs and compare"}
        </span>
      </div>

      <div style={{ ...area, flex: 1, overflow: "auto", background: "var(--pane)" }}>
        {result && result.segments
          ? result.segments.map((s, i) => (
              <span key={i} style={segStyle(s.op)}>{s.text}</span>
            ))
          : <span style={{ color: "var(--dim)" }}>diff appears here — green = added in B, red = removed from A</span>}
      </div>
    </div>
  );
}

function DecoderTab() {
  const [input, setInput]   = React.useState("");
  const [output, setOutput] = React.useState("");
  const [activeOp, setOp]   = React.useState("");
  const [err, setErr]       = React.useState("");
  const [chain, setChain]   = React.useState([]);
  const [copied, setCopied] = React.useState(false);

  const OPS = [
    "base64-encode", "base64-decode", "base64url-encode", "base64url-decode",
    "url-encode", "url-decode", "html-encode", "html-decode",
    "hex-encode", "hex-decode", "unicode-escape", "unicode-unescape",
    "rot13", "jwt-decode", "md5", "sha1", "sha256", "sha512",
  ];

  const run = async (operation) => {
    setOp(operation); setErr(""); setChain([]);
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
          <div style={{ fontSize: "10px", color: "var(--dim)", textTransform: "uppercase",
                        letterSpacing: "0.06em" }}>Input</div>
          <textarea style={area} value={input} placeholder="paste text to transform…"
                    onChange={e => setInput(e.target.value)} spellCheck={false} />
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 6, minHeight: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ fontSize: "10px", color: "var(--dim)", textTransform: "uppercase",
                          letterSpacing: "0.06em", flex: 1 }}>
              Output {activeOp ? "· " + activeOp : ""}
              {chain.length ? " · chain: " + chain.join(" → ") : ""}
            </div>
            <Btn label={copied ? "copied" : "copy"} onClick={copy} disabled={!output} />
            <Btn label="↑ input" title="Use output as the new input (chain transforms)"
                 onClick={useOutputAsInput} disabled={!output} />
          </div>
          <textarea style={{ ...area, color: err ? "var(--err)" : "var(--text)" }}
                    value={err ? (output ? output + "\n\n[" + err + "]" : "[" + err + "]") : output}
                    readOnly spellCheck={false} />
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
function SessionsTab() {
  const [, force] = React.useReducer(x => x + 1, 0);
  React.useEffect(() => {
    const onUpdate = () => force();
    window.addEventListener("nl-update", onUpdate);
    return () => window.removeEventListener("nl-update", onUpdate);
  }, []);

  const sessions = (window.NL && NL.sessions) ? NL.sessions : [];
  const [expanded, setExpanded] = React.useState(null); // host being shown in detail

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
    dispatch({ type: "set", payload: { tab: "proxy", hostFilter: host, selectedHost: host } });
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

function App() {
  const [tab, setTab] = React.useState("proxy");
  const [tweaks, setTweak] = useTweaks(TWEAK_DEFAULTS);
  const [tweaksOpen, setTweaksOpen] = React.useState(false);
  const [bootShown, setBootShown] = React.useState(() => tweaks.bootSplash !== false);

  const initialState = React.useMemo(() => ({
    rows: NL.rows,
    selectedRowId: NL.rows[2]?.id ?? null,
    hostFilter: "",
    statusClass: "all",
    methodFilter: "ALL",
    search: "",
    selectedHost: null,
    proxyOn: true,
    intercept: false,
    intercepted: NL.intercepted,
    scope: NL.scope,
    repeater: NL.repeater,
    intruder: {
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
    const tableHostFilter = state.selectedHost || state.hostFilter;
    if (tableHostFilter && !r.host.includes(tableHostFilter)) return false;
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
    dot: (t.id === "intercept" && state.intercept) || (t.id === "intruder" && state.intruder.running),
  }));

  const copyCa = () => navigator.clipboard?.writeText(NL.bootInfo.caPath);

  return (
    <div className="nl-window" data-screen-label="Nullock">
      <TitleBar
        tabs={tabsWithDots}
        current={tab}
        onTab={setTab}
        theme={tweaks.theme}
        onTheme={(t) => setTweak("theme", t)}
        onToggleTweaks={() => setTweaksOpen(o => !o)}
      />
      <Rail
        proxyOn={state.proxyOn}
        port={NL.bootInfo.port}
        h2Count={h2Count}
        filtered={hidden}
        total={state.rows.length}
        intercept={state.intercept}
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
          />
        )}
        {tab === "scope" && (
          <ScopeTab
            scope={state.scope}
            dispatch={dispatch}
            bootInfo={NL.bootInfo}
            onCopyCa={copyCa}
          />
        )}
        {tab === "repeater" && (
          <RepeaterTab rep={state.repeater} dispatch={dispatch} />
        )}
        {tab === "intercept" && (
          <InterceptTab
            intercept={state.intercept}
            intercepted={state.intercepted}
            dispatch={dispatch}
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
          <DecoderTab />
        )}
        {tab === "comparer" && (
          <ComparerTab />
        )}
        {tab === "stats" && (
          <StatsTab dispatch={dispatch} />
        )}
        {tab === "sessions" && (
          <SessionsTab />
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
        intercept={state.intercept}
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
