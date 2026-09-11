// ASCII animations: boot splash, traffic sparkline, intercept radar, braille spinner.

// ---------- Sparkline ----------
const SPARK_CHARS = " ▁▂▃▄▅▆▇█";

function AsciiSparkline({ width = 16, label = "HISTORY / S" }) {
  const [bars, setBars] = React.useState(() => Array(width).fill(0));
  React.useEffect(() => {
    let previous = null;
    let generation = NL.bootInfo?.historyGeneration;
    const id = setInterval(() => {
      const current = Math.max(0, ...(NL.rows || []).map(r => r.id || 0));
      const same = generation === NL.bootInfo?.historyGeneration;
      const delta = NL.connected && same && previous !== null ? Math.max(0, current - previous) : 0;
      generation = NL.bootInfo?.historyGeneration;
      previous = current;
      setBars(prev => [...prev.slice(1), Math.min(8, delta)]);
    }, 1000);
    return () => clearInterval(id);
  }, [width]);
  return (
    <span className="ascii-spark" title="New history rows per second; each bar is capped at eight">
      <span className="ascii-spark-label">{label}</span>
      <span className="ascii-spark-bars">
        {bars.map((b, i) => (
          <span key={i} style={{ color: b >= 6 ? "var(--accent)" : b >= 3 ? "var(--text-2)" : "var(--dim)" }}>
            {SPARK_CHARS[b] || " "}
          </span>
        ))}
      </span>
    </span>
  );
}

// ---------- Braille spinner ----------
const BRAILLE = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"];

function BrailleSpinner({ color = "var(--accent)" }) {
  const [i, setI] = React.useState(0);
  React.useEffect(() => {
    const id = setInterval(() => setI(x => (x + 1) % BRAILLE.length), 90);
    return () => clearInterval(id);
  }, []);
  return <span style={{ color, fontFamily: "var(--ff-mono)" }}>{BRAILLE[i]}</span>;
}

// ---------- ASCII radar ----------
const RADAR_FRAMES = [
`        . · . · .
     ·             ·
   .       ◉       .
     ·             ·
        ' · . · '`,
`        . · . · .
     ·             ·
   .       ◉━━━━   .
     ·             ·
        ' · . · '`,
`        . · . · .
     ·       |     ·
   .         ◉     .
     ·             ·
        ' · . · '`,
`        . · . · .
     ·             ·
   .   ━━━━◉       .
     ·             ·
        ' · . · '`,
`        . · . · .
     ·             ·
   .         ◉     .
     ·       |     ·
        ' · . · '`,
];

function AsciiRadar({ label = "AWAITING NEXT REQUEST" }) {
  const [f, setF] = React.useState(0);
  React.useEffect(() => {
    const id = setInterval(() => setF(x => (x + 1) % RADAR_FRAMES.length), 280);
    return () => clearInterval(id);
  }, []);
  return (
    <div className="ascii-radar">
      <pre className="ascii-radar-art">{RADAR_FRAMES[f]}</pre>
      <div className="ascii-radar-label">▸ {label}</div>
      <div className="ascii-radar-sub">{NL.connected ? (NL.bootInfo?.proxyOn ? `listening :${NL.bootInfo.port}` : "proxy stopped") : "backend disconnected"}</div>
    </div>
  );
}

// ---------- Boot splash ----------
const NL_LOGO = [
  "███╗   ██╗██╗   ██╗██╗     ██╗      ██████╗  ██████╗██╗  ██╗",
  "████╗  ██║██║   ██║██║     ██║     ██╔═══██╗██╔════╝██║ ██╔╝",
  "██╔██╗ ██║██║   ██║██║     ██║     ██║   ██║██║     █████╔╝ ",
  "██║╚██╗██║██║   ██║██║     ██║     ██║   ██║██║     ██╔═██╗ ",
  "██║ ╚████║╚██████╔╝███████╗███████╗╚██████╔╝╚██████╗██║  ██╗",
  "╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝",
];

function BootSplash({ onDone }) {
  const b = window.NL?.bootInfo || {};
  const BOOT_LINES = [
    { l: "control connection", v: NL.connected ? "connected" : "unavailable", d: 180 },
    { l: "proxy listener", v: NL.connected ? (b.proxyOn ? `:${b.port}` : "stopped") : "unknown", d: 180 },
    { l: "project", v: b.project || "none", d: 180 },
    { l: "extensions", v: String(b.loadedExtensions || 0), d: 180 },
  ];
  const [logoRevealed, setLogoRevealed] = React.useState(0);
  const [linesShown, setLinesShown] = React.useState(0);
  const [phase, setPhase] = React.useState("logo"); // logo → boot → ready
  const [cursorOn, setCursorOn] = React.useState(true);

  // reveal logo rows
  React.useEffect(() => {
    if (phase !== "logo") return;
    if (logoRevealed >= NL_LOGO.length) {
      const t = setTimeout(() => setPhase("boot"), 280);
      return () => clearTimeout(t);
    }
    const t = setTimeout(() => setLogoRevealed(r => r + 1), 70);
    return () => clearTimeout(t);
  }, [logoRevealed, phase]);

  // type out boot lines
  React.useEffect(() => {
    if (phase !== "boot") return;
    if (linesShown >= BOOT_LINES.length) {
      const t = setTimeout(() => setPhase("ready"), 420);
      return () => clearTimeout(t);
    }
    const t = setTimeout(() => setLinesShown(n => n + 1), BOOT_LINES[linesShown]?.d || 240);
    return () => clearTimeout(t);
  }, [linesShown, phase]);

  // blinking cursor
  React.useEffect(() => {
    const id = setInterval(() => setCursorOn(c => !c), 420);
    return () => clearInterval(id);
  }, []);

  // auto-dismiss after ready
  React.useEffect(() => {
    if (phase !== "ready") return;
    const t = setTimeout(onDone, 1100);
    return () => clearTimeout(t);
  }, [phase, onDone]);

  const skip = (
    <button className="boot-skip" onClick={onDone}>
      <span className="kbd">ESC</span> SKIP
    </button>
  );

  return (
    <div className="boot-overlay" onKeyDown={e => e.key === "Escape" && onDone()} tabIndex={0} ref={el => el?.focus()}>
      <div className="boot-scan" />
      {skip}
      <div className="boot-stage">
        <pre className="boot-logo">
{NL_LOGO.slice(0, logoRevealed).join("\n")}
        </pre>
        <div className="boot-sub">
          <span className="dim">[</span> MITM PROXY <span className="dim">·</span> {b.version ? `v${b.version}` : "version unavailable"} <span className="dim">·</span> local control <span className="dim">]</span>
        </div>

        <div className="boot-lines">
          {BOOT_LINES.slice(0, linesShown).map((line, i) => {
            const dots = ".".repeat(Math.max(2, 44 - line.l.length));
            return (
              <div key={i} className="boot-line">
                <span className="prompt">▸</span>
                <span className="lbl">{line.l}</span>
                <span className="dots">{dots}</span>
                <span className="val">{line.v}</span>
              </div>
            );
          })}
          {phase === "boot" && (
            <div className="boot-line typing">
              <span className="prompt">▸</span>
              <span className="lbl">{BOOT_LINES[linesShown]?.l || ""}</span>
              <span className="cursor">{cursorOn ? "█" : " "}</span>
            </div>
          )}
          {phase === "ready" && (
            <div className="boot-line ready">
              <span className="prompt">▸</span>
              <span className="lbl" style={{ color: "var(--accent)" }}>{NL.connected ? "CONNECTED" : "BACKEND UNAVAILABLE"}</span>
              <span className="dots">{".".repeat(28)}</span>
              <span className="val" style={{ color: "var(--accent)" }}>★</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { AsciiSparkline, BrailleSpinner, AsciiRadar, BootSplash });
