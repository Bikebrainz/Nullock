// Scope, Repeater, Intercept, Intruder tabs.

// ===================== SCOPE =====================
function ScopeTab({ scope, dispatch, bootInfo, onCopyCa }) {
  const [newIn, setNewIn] = React.useState("");
  const [newOut, setNewOut] = React.useState("");
  const [copied, setCopied] = React.useState(false);

  return (
    <div className="tab-body" style={{ gridTemplateRows: "auto auto 1fr" }}>
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
          <button className="btn">OPEN FOLDER</button>
        </div>
      </div>

      <div className="pane-head" style={{ borderTop: "1px solid var(--line)" }}>
        <span className="ph-corner">▸</span>
        <span>SCOPE · {scope.in.length} IN / {scope.out.length} OUT</span>
        <span className="ph-count">project: {bootInfo.project}</span>
      </div>

      <div className="scope-grid">
        <div className="scope-col">
          <div className="pane-head" style={{ background:"var(--pane)" }}>
            <span style={{ color: "var(--ok)" }}>▸</span>
            <span>IN-SCOPE GLOBS</span>
            <span className="ph-count">{scope.in.length}</span>
          </div>
          <div className="scope-list">
            {scope.in.map((g, i) => (
              <div key={g} className="scope-item in">
                <span className="glob">{g}</span>
                <span className="rm" onClick={() => dispatch({ type: "scope-remove-in", index: i })}>×</span>
              </div>
            ))}
            {scope.in.length === 0 && <div style={{ padding: 16, color: "var(--dim)", fontSize: "var(--fz-sm)" }}>nothing in scope — all hosts captured</div>}
          </div>
          <div className="scope-add">
            <div className="fld" style={{ flex: 1 }}>
              <span className="pre">+IN</span>
              <input
                placeholder="e.g. *.acme.corp"
                value={newIn}
                onChange={e => setNewIn(e.target.value)}
                onKeyDown={e => { if (e.key === "Enter" && newIn.trim()) { dispatch({ type: "scope-add-in", value: newIn.trim() }); setNewIn(""); } }}
              />
            </div>
            <button className="btn" onClick={() => { if (newIn.trim()) { dispatch({ type: "scope-add-in", value: newIn.trim() }); setNewIn(""); } }}>ADD</button>
          </div>
        </div>
        <div className="scope-col">
          <div className="pane-head" style={{ background:"var(--pane)" }}>
            <span style={{ color: "var(--err)" }}>▸</span>
            <span>OUT-OF-SCOPE GLOBS</span>
            <span className="ph-count">{scope.out.length}</span>
          </div>
          <div className="scope-list">
            {scope.out.map((g, i) => (
              <div key={g} className="scope-item out">
                <span className="glob">{g}</span>
                <span className="rm" onClick={() => dispatch({ type: "scope-remove-out", index: i })}>×</span>
              </div>
            ))}
            {scope.out.length === 0 && <div style={{ padding: 16, color: "var(--dim)", fontSize: "var(--fz-sm)" }}>no exclusions</div>}
          </div>
          <div className="scope-add">
            <div className="fld" style={{ flex: 1 }}>
              <span className="pre">+OUT</span>
              <input
                placeholder="e.g. *.analytics.com"
                value={newOut}
                onChange={e => setNewOut(e.target.value)}
                onKeyDown={e => { if (e.key === "Enter" && newOut.trim()) { dispatch({ type: "scope-add-out", value: newOut.trim() }); setNewOut(""); } }}
              />
            </div>
            <button className="btn" onClick={() => { if (newOut.trim()) { dispatch({ type: "scope-add-out", value: newOut.trim() }); setNewOut(""); } }}>ADD</button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ===================== REPEATER =====================
function RepeaterTab({ rep, dispatch }) {
  const [busy, setBusy] = React.useState(false);

  const send = () => {
    setBusy(true);
    setTimeout(() => {
      setBusy(false);
      // small visual change: bump response timestamp
      const ms = 60 + Math.floor(Math.random() * 180);
      dispatch({ type: "repeater-set", payload: {
        statusLine: `HTTP/2 200 OK · 248 B · ${ms} ms`,
      }});
    }, 450);
  };

  return (
    <div className="tab-body" style={{ gridTemplateRows: "auto auto 1fr" }}>
      <div className="pane-head">
        <span className="ph-corner">▸</span>
        <span>REPEATER · one-shot request editor</span>
        <span className="ph-count">target locked</span>
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
          </div>
          <textarea
            className="txt"
            value={rep.request}
            onChange={e => dispatch({ type: "repeater-set", payload: { request: e.target.value }})}
            spellCheck={false}
          />
        </div>
        <div className="divider-v" />
        <div className="pane" style={{ minWidth: 0 }}>
          <div className="pane-head">
            <span style={{ color:"var(--accent)" }}>▸</span>
            <span>RESPONSE · read-only</span>
            <span className="ph-count">{rep.response.split("\n").length} LINES</span>
          </div>
          <textarea className="txt readonly" value={rep.response} readOnly />
        </div>
      </div>
    </div>
  );
}

// ===================== INTERCEPT =====================
function InterceptTab({ intercept, intercepted, dispatch }) {
  const current = intercepted[0] || null;
  const more = Math.max(0, intercepted.length - 1);

  const [editedText, setEditedText] = React.useState(current ? current.text : "");
  React.useEffect(() => { setEditedText(current ? current.text : ""); }, [current?.id]);

  return (
    <div className="tab-body" style={{ gridTemplateRows: "auto 1fr" }}>
      <div className="icp-toggle">
        <div className={"pwr" + (intercept ? " on" : "")} onClick={() => dispatch({ type: "intercept-toggle" })} />
        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          <span style={{ fontSize: "var(--fz-xs)", letterSpacing: "0.18em", textTransform: "uppercase", color: "var(--dim)" }}>
            INTERCEPT MODE
          </span>
          <span style={{ fontSize: "var(--fz-md)", color: intercept ? "var(--err)" : "var(--text-2)" }}>
            {intercept ? "ON — outbound requests paused" : "off — requests pass through"}
          </span>
        </div>
        <span style={{ flex: 1 }} />
        <div className="chip">
          QUEUE <span style={{ color: "var(--accent)", marginLeft: 8, fontSize: "var(--fz-md)" }}>{intercepted.length}</span>
        </div>
        <button className="btn" onClick={() => dispatch({ type: "intercept-forward-all" })} disabled={!intercept || intercepted.length === 0}>
          FORWARD ALL
        </button>
      </div>

      {current ? (
        <div className="icp-current">
          <div className="icp-meta">
            <span className="id">#{current.id}</span>
            <span className="chip accent">PENDING</span>
            <span className="url">
              <span className="proto">{current.tls ? "https://" : "http://"}</span>
              {current.host}<span className="proto">:{current.port}</span>
            </span>
            <span style={{ flex: 1 }} />
            {more > 0 && (
              <span style={{ color: "var(--warn)", fontSize: "var(--fz-xs)", letterSpacing: "0.14em", textTransform: "uppercase" }} className="blink">
                ▮ {more} more waiting
              </span>
            )}
          </div>
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
          {intercept
            ? <AsciiRadar label="awaiting next request" />
            : "── intercept off · no queue ──"}
        </div>
      )}
    </div>
  );
}

// ===================== INTRUDER =====================
function IntruderTab({ intruder, dispatch }) {
  const total = intruder.payloads.length;
  const completed = intruder.results.filter(r => r.status !== null).length;
  const pct = total ? Math.round((completed / total) * 100) : 0;

  return (
    <div className="tab-body" style={{ gridTemplateRows: "auto auto 1fr auto" }}>
      <div className="pane-head">
        <span className="ph-corner">▸</span>
        <span>INTRUDER · sniper mode</span>
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
        <span style={{ flex: 1 }} />
        <span style={{ color: "var(--dim)", fontSize: "var(--fz-xs)", letterSpacing: "0.14em", textTransform: "uppercase" }}>
          PROGRESS <span style={{ color: "var(--accent)" }}>{completed}/{total}</span>
        </span>
        <button className="btn" onClick={() => dispatch({ type: "intruder-clear" })}>CLEAR</button>
        {intruder.running ? (
          <button className="btn danger" onClick={() => dispatch({ type: "intruder-stop" })}>■ STOP</button>
        ) : (
          <button className="btn primary" onClick={() => dispatch({ type: "intruder-start" })}>▶ START</button>
        )}
      </div>

      <div style={{ display: "grid", gridTemplateRows: "1fr 1fr", height: "100%", minHeight: 0, borderTop: "1px solid var(--line)" }}>
        <div style={{ display: "grid", gridTemplateColumns: "1.5fr 1px 1fr", minHeight: 0, borderBottom: "1px solid var(--line)" }}>
          <div className="pane" style={{ minWidth: 0 }}>
            <div className="pane-head">
              <span style={{ color:"var(--accent-2)" }}>▸</span>
              <span>TEMPLATE</span>
              <span className="ph-count">
                {(intruder.template.match(/§/g)?.length || 0) / 2} INSERTION POINT
              </span>
            </div>
            <textarea
              className="txt"
              value={intruder.template}
              onChange={e => dispatch({ type: "intruder-set", payload: { template: e.target.value }})}
              spellCheck={false}
            />
          </div>
          <div className="divider-v" />
          <div className="pane" style={{ minWidth: 0 }}>
            <div className="pane-head">
              <span style={{ color:"var(--accent)" }}>▸</span>
              <span>PAYLOADS</span>
              <span className="ph-count">{intruder.payloads.length}</span>
            </div>
            <textarea
              className="txt"
              value={intruder.payloads.join("\n")}
              onChange={e => dispatch({ type: "intruder-set", payload: { payloads: e.target.value.split("\n").filter(Boolean) }})}
              spellCheck={false}
            />
          </div>
        </div>

        <div className="pane" style={{ minHeight: 0 }}>
          <div className="pane-head">
            <span className="ph-corner">▸</span>
            <span>RESULTS</span>
            <span className="ph-count">{completed} / {total} · {pct}%</span>
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
                <col />
              </colgroup>
              <thead>
                <tr><th>#</th><th>Payload</th><th>Status</th><th>Size</th><th>Time</th><th>Error</th></tr>
              </thead>
              <tbody>
                {intruder.payloads.map((p, i) => {
                  const r = intruder.results[i] || { status: null, size: 0, ms: 0, err: "" };
                  const pending = r.status === null;
                  const cls = (r.status >= 400) ? "s4" : (r.status >= 300) ? "s3" : (r.status >= 200) ? "s2" : "";
                  return (
                    <tr key={i} className={pending ? "pending" : ""}>
                      <td>{(i + 1).toString().padStart(3, "0")}</td>
                      <td><span style={{ color: pending ? "var(--dim)" : "var(--text)" }}>{p}</span></td>
                      <td><span className={"status " + cls}>{pending ? "—" : r.status}</span></td>
                      <td>{pending ? "—" : (r.size + " B")}</td>
                      <td>{pending ? "—" : (r.ms + " ms")}</td>
                      <td style={{ color: r.err ? "var(--err)" : "var(--dim)" }}>{r.err || (pending ? "queued" : "")}</td>
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

Object.assign(window, { ScopeTab, RepeaterTab, InterceptTab, IntruderTab });
