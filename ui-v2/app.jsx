// Main app: state, dispatch, tab routing, Tweaks panel.

const TABS = [
  { id: "proxy",     label: "PROXY" },
  { id: "scope",     label: "SCOPE" },
  { id: "repeater",  label: "REPEATER" },
  { id: "intercept", label: "INTERCEPT" },
  { id: "intruder",  label: "INTRUDER" },
];

function reducer(state, action) {
  switch (action.type) {
    case "set":
      return { ...state, ...action.payload };
    case "switch-tab":
      return { ...state, tab: action.tab };
    case "send-to-repeater": {
      if (!action.row) return state;
      const row = action.row;
      const req = NL.requestRawAt(row.id - 1);
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
      // mark a value to fuzz: replace path after last "=" with §marker§
      let tmpl = req;
      if (req.includes("=")) {
        tmpl = req.replace(/(=)([^&\s\n]*)$/m, "$1§payload§");
      }
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
      return { ...state, repeater: { ...state.repeater, ...action.payload } };
    case "repeater-clear":
      return { ...state, repeater: { ...state.repeater, request: "", response: "", statusLine: "—" } };
    case "intruder-set":
      return { ...state, intruder: { ...state.intruder, ...action.payload } };
    case "intruder-clear":
      return { ...state, intruder: { ...state.intruder, running: false, results: state.intruder.payloads.map(() => ({ status: null, size: 0, ms: 0, err: "" })) } };
    case "intruder-start":
      return { ...state, intruder: { ...state.intruder, running: true } };
    case "intruder-stop":
      return { ...state, intruder: { ...state.intruder, running: false } };
    case "intruder-tick": {
      // advance one pending row
      const results = [...state.intruder.results];
      const next = results.findIndex(r => r.status === null);
      if (next === -1) return { ...state, intruder: { ...state.intruder, running: false } };
      const payload = state.intruder.payloads[next];
      // fake outcome:
      const hit = /admin|operator|correct|root|password/i.test(payload) && Math.random() < 0.18;
      const errored = Math.random() < 0.05;
      results[next] = errored
        ? { status: 0, size: 0, ms: 1200 + Math.floor(Math.random() * 1500), err: "timeout" }
        : { status: hit ? 200 : 401, size: hit ? 312 : 124, ms: 60 + Math.floor(Math.random() * 110), err: "" };
      return { ...state, intruder: { ...state.intruder, results } };
    }
    case "intercept-toggle":
      return { ...state, intercept: !state.intercept };
    case "intercept-forward":
      return { ...state, intercepted: state.intercepted.slice(1) };
    case "intercept-drop":
      return { ...state, intercepted: state.intercepted.slice(1) };
    case "intercept-forward-all":
      return { ...state, intercepted: [] };
    case "scope-add-in":
      if (state.scope.in.includes(action.value)) return state;
      return { ...state, scope: { ...state.scope, in: [...state.scope.in, action.value] } };
    case "scope-remove-in":
      return { ...state, scope: { ...state.scope, in: state.scope.in.filter((_, i) => i !== action.index) } };
    case "scope-add-out":
      if (state.scope.out.includes(action.value)) return state;
      return { ...state, scope: { ...state.scope, out: [...state.scope.out, action.value] } };
    case "scope-remove-out":
      return { ...state, scope: { ...state.scope, out: state.scope.out.filter((_, i) => i !== action.index) } };
    case "clear-history":
      return { ...state, rows: [], selectedRowId: null };
    case "toggle-power":
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

  // intruder ticking
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
        onExport={() => alert("Mock: HAR exported to\n" + NL.bootInfo.harPath)}
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
              value={tweaks.theme}
              options={NL.themes.map(t => ({ value: t, label: t.toUpperCase() }))}
              onChange={v => setTweak("theme", v)}
            />
            <TweakColor
              label="Accent override"
              value={tweaks.accent}
              options={Object.keys(ACCENT_PRESETS).map(k => k === "default" ? "transparent" : ACCENT_PRESETS[k])}
              onChange={(hex, idx) => setTweak("accent", Object.keys(ACCENT_PRESETS)[idx])}
            />
          </TweakSection>
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
