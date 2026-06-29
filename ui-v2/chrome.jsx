// Chrome: title bar (custom frameless), tab strip, command rail, status bar.

function NullockMark({ size = 26 }) {
  // Hydra brand mark: real logo image with animated halo + slow rotating hex frame.
  return (
    <div className="nl-mark" style={{ width: size, height: size }}>
      <svg
        className="nl-mark-ring"
        width={size} height={size}
        viewBox="0 0 24 24"
        fill="none"
        stroke="var(--accent)"
        strokeWidth="0.7"
        aria-hidden="true"
      >
        <polygon points="12,1.5 22.4,7 22.4,17 12,22.5 1.6,17 1.6,7" />
      </svg>
      <img className="nl-mark-img" src="assets/nullock_logo.png" alt="Nullock" draggable="false" />
      <div className="nl-mark-scan" aria-hidden="true" />
    </div>
  );
}

function TitleBar({ tabs, current, onTab, theme, onTheme, onToggleTweaks }) {
  return (
    <div className="tb" data-no-drag>
      <div className="tb-brand">
        <NullockMark size={26} />
        <div>
          <div className="tb-name">NULL<span className="nm-x">0</span>CK</div>
        </div>
        <div className="tb-meta">v0.4 · acme-corp-2026</div>
      </div>
      <div className="tb-tabs">
        {tabs.map((t, i) => (
          <div
            key={t.id}
            className="tb-tab"
            aria-current={current === t.id ? "true" : "false"}
            onClick={() => onTab(t.id)}
          >
            <span className="idx">0{i + 1}</span>
            <span>{t.label}</span>
            {t.dot ? <span className="dot" /> : null}
          </div>
        ))}
      </div>
      <div className="tb-right">
        <div className="tb-theme" onClick={() => {
          if (!NL.themes || !NL.themes.length) return;   // empty list -> NaN index
          const i = NL.themes.indexOf(theme);
          onTheme(NL.themes[(i + 1) % NL.themes.length]);
        }} title="Cycle theme">
          <span className="theme-swatch" />
          <span>{theme}</span>
        </div>
        <div className="tb-iconbtn" onClick={onToggleTweaks} title="Tweaks panel">
          ⌥ TWEAKS
        </div>
      </div>
      <div className="tb-wctrls">
        <button title="Minimize">
          <svg width="10" height="10" viewBox="0 0 10 10"><rect x="1" y="5" width="8" height="1" fill="currentColor"/></svg>
        </button>
        <button title="Maximize">
          <svg width="10" height="10" viewBox="0 0 10 10" fill="none" stroke="currentColor"><rect x="1.5" y="1.5" width="7" height="7"/></svg>
        </button>
        <button className="close" title="Close">
          <svg width="10" height="10" viewBox="0 0 10 10" stroke="currentColor"><line x1="1" y1="1" x2="9" y2="9"/><line x1="9" y1="1" x2="1" y2="9"/></svg>
        </button>
      </div>
    </div>
  );
}

function Rail({ proxyOn, port, h2Count, filtered, total, intercept, queue, project, intruderRunning, intruderProgress }) {
  return (
    <div className="rail">
      <div className="seg">
        <span className={"led" + (proxyOn ? "" : " off")} />
        <span>PROXY</span>
        <span className="v">{proxyOn ? `:${port}` : "STOPPED"}</span>
      </div>
      <div className="sep" />
      <div className="seg">
        <span>SESSION</span>
        <span className="a">{project}</span>
      </div>
      <div className="sep" />
      <div className="seg">
        <span>CAPTURED</span>
        <span className="v">{total}</span>
        <span>·</span>
        <span>SHOWN</span>
        <span className="v">{total - filtered}</span>
      </div>
      <div className="sep" />
      <AsciiSparkline width={18} intensity={proxyOn ? 1 : 0.05} label="RX" />
      <div className="sep" />
      <div className="seg">
        <span>H2 UPSTREAM</span>
        <span className="v">{h2Count}</span>
      </div>
      <div className="sep" />
      {intercept ? (
        <div className="seg">
          <span className="led err blink" />
          <span style={{ color: "var(--err)" }}>INTERCEPT</span>
          <span className="v">{queue}</span>
        </div>
      ) : (
        <div className="seg">
          <span className="led off" />
          <span>INTERCEPT IDLE</span>
        </div>
      )}
      {intruderRunning && (
        <>
          <div className="sep" />
          <div className="seg">
            <BrailleSpinner />
            <span style={{ color: "var(--accent)" }}>INTRUDER</span>
            <span className="v">{intruderProgress}</span>
          </div>
        </>
      )}
    </div>
  );
}

function StatusBar({ proxyOn, port, total, filtered, scope, intercept, queue, har, onExport, onClear, onTogglePower }) {
  return (
    <div className="sb">
      <div className="seg">
        <span>● </span>
        <span>PROXY</span>
        <span className={proxyOn ? "v" : "red"}>
          {proxyOn ? `LISTENING ${port}` : "STOPPED"}
        </span>
      </div>
      <div className="sep" />
      <div className="seg">
        <span>{total}</span><span>REQ</span>
        {filtered > 0 ? <><span>·</span><span className="v">{filtered} FILTERED</span></> : null}
      </div>
      <div className="sep" />
      <div className="seg">
        <span>SCOPE</span>
        <span className="a">{scope.in.length} IN / {scope.out.length} OUT</span>
      </div>
      <div className="sep" />
      {intercept ? (
        <div className="seg">
          <span className="red blink">▮ INTERCEPT ({queue})</span>
        </div>
      ) : (
        <div className="seg"><span>INTERCEPT OFF</span></div>
      )}
      <div className="spacer" />
      <div className="seg">
        <span>HAR</span>
        <span className="v" style={{ maxWidth: 280, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{har}</span>
        <button onClick={onExport}>EXPORT</button>
      </div>
      <div className="sep" />
      <button onClick={onClear}>CLEAR</button>
      <button onClick={onTogglePower}>{proxyOn ? "STOP" : "START"}</button>
    </div>
  );
}

Object.assign(window, { TitleBar, Rail, StatusBar, NullockMark });
