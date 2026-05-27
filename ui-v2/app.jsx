// Main app: state, dispatch, tab routing, Tweaks panel.

const TABS = [
  { id: "proxy",     label: "PROXY" },
  { id: "scope",     label: "SCOPE" },
  { id: "repeater",  label: "REPEATER" },
  { id: "intercept", label: "INTERCEPT" },
  { id: "intruder",  label: "INTRUDER" },
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
      act("repeaterSet", { host: row.host, port: row.tls ? 443 : 80, tls: row.tls, request: req });
      return {
        ...state,
        tab: "repeater",
        repeater: {
          ...state.repeater,
          host: row.host,
          port: row.tls ? 443 : 80,
          tls: row.tls,
          request: req,
          response: state.repeater.response,
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

  // chrome props
  const filtered = state.rows.filter(r => {
    const tableHostFilter = state.selectedHost || state.hostFilter;
    if (tableHostFilter && !r.host.includes(tableHostFilter)) return false;
    if (state.statusClass !== "all" && (Math.floor(r.status / 100) + "xx") !== state.statusClass) return false;
    if (state.methodFilter !== "ALL" && r.method !== state.methodFilter) return false;
    if (state.search && !r.url.toLowerCase().includes(state.search.toLowerCase())) return false;
    return true;
  }).length;
  const hidden = state.rows.length - filtered;
  const h2Count = Math.floor(state.rows.length * 0.32);

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
